"""Tests for the unary gRPC surface of the Specter Python binding.

Covers message framing (identity and gzip), incremental deframing across a
chunk boundary, the gRPC request header presets, and the Response.trailers
contract. These are deterministic and network-free except for a single
loopback HTTP/1.1 round trip that exercises the trailers None path on a
non-trailers (buffered) response.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

import specter


def _frame_header(framed: bytes) -> tuple[int, int]:
    flag = framed[0]
    (length,) = struct.unpack("!I", framed[1:5])
    return flag, length


def test_encode_message_identity_layout() -> None:
    payload = b"hello grpc"
    framed = specter.encode_message(payload, False, specter.GrpcEncoding.Identity)
    flag, length = _frame_header(framed)
    assert flag == 0
    assert length == len(payload)
    assert framed[5:] == payload


def test_framer_identity_round_trip() -> None:
    payload = b"\x0a\x05world"
    framed = specter.encode_message(payload, False, specter.GrpcEncoding.Identity)

    framer = specter.GrpcFramer(specter.GrpcEncoding.Identity)
    framer.push(framed)
    assert framer.next_message() == payload
    assert framer.next_message() is None


def test_framer_gzip_round_trip() -> None:
    payload = b"the quick brown fox jumps over the lazy dog" * 8
    framed = specter.encode_message(payload, True, specter.GrpcEncoding.Gzip)

    # Compressed flag is set and the framed body is not the raw payload.
    flag, _ = _frame_header(framed)
    assert flag == 1

    framer = specter.GrpcFramer(specter.GrpcEncoding.Gzip)
    framer.push(framed)
    assert framer.next_message() == payload
    assert framer.next_message() is None


def test_framer_partial_frame_across_header_boundary() -> None:
    payload = b"partial-delivery-message"
    framed = specter.encode_message(payload, False, specter.GrpcEncoding.Identity)

    framer = specter.GrpcFramer(specter.GrpcEncoding.Identity)
    # Split inside the 5-byte prefix so neither slice carries a full header.
    framer.push(framed[:3])
    assert framer.next_message() is None
    framer.push(framed[3:])
    assert framer.next_message() == payload
    assert framer.next_message() is None


def test_framer_encoding_property() -> None:
    framer = specter.GrpcFramer(specter.GrpcEncoding.Gzip)
    assert framer.encoding == specter.GrpcEncoding.Gzip


def test_grpc_request_header_presets_gzip() -> None:
    client = specter.Client.builder().build()
    request = client.grpc_request(
        "https://host/helloworld.Greeter/SayHello", specter.GrpcEncoding.Gzip
    )
    assert request.method == "POST"
    headers = request.headers_list()
    assert headers == [
        ("content-type", "application/grpc+proto"),
        ("te", "trailers"),
        ("grpc-encoding", "gzip"),
    ]


def test_grpc_request_header_presets_identity() -> None:
    client = specter.Client.builder().build()
    request = client.grpc_request(
        "https://host/helloworld.Greeter/SayHello", specter.GrpcEncoding.Identity
    )
    assert request.method == "POST"
    headers = request.headers_list()
    assert headers == [
        ("content-type", "application/grpc+proto"),
        ("te", "trailers"),
    ]


async def _serve_one_plain_response(ready: "asyncio.Future[int]") -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            # Drain request headers up to the blank line.
            await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError:
            pass
        body = b"ok"
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    ready.set_result(port)
    async with server:
        await server.serve_forever()


@pytest.mark.asyncio
async def test_trailers_none_on_non_trailers_response() -> None:
    loop = asyncio.get_running_loop()
    ready: "asyncio.Future[int]" = loop.create_future()
    server_task = asyncio.ensure_future(_serve_one_plain_response(ready))
    try:
        port = await ready
        client = specter.Client.builder().build()
        response = await client.get(f"http://127.0.0.1:{port}/").send()
        assert response.status == 200
        # A plain HTTP/1.1 buffered response carries no trailers.
        assert await response.trailers() is None
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
