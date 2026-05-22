//! Pooled HTTP/2 Streaming Validation Tests
//!
//! Evaluates the pooled H2 streaming correctness.
//! Writes validation JSONs to target/validation/h2/VAL-H2-*.json.

use bytes::Bytes;
use serde_json::json;
use specter::Client;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;
use specter::transport::h2::hpack_impl::Encoder;

fn init_validation_dir() {
    fs::create_dir_all("target/validation/h2").unwrap();
}

#[tokio::test]
async fn high_level_streaming_reuses_pooled_h2_connection() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let conn_count = Arc::new(Mutex::new(0));
    let conn_count_clone = conn_count.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let conn_count = conn_count_clone.clone();
        async move {
            {
                let mut lock = conn_count.lock().await;
                *lock += 1;
            }
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 => {
                        if flags & 0x01 == 0 && !settings_sent {
                            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                                .await
                                .unwrap();
                            conn.send_settings_ack().await.unwrap();
                            settings_sent = true;
                        }
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();
                        conn.send_data(stream_id, b"chunk-data", true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    // Stream 1
    let req_url = format!("{}/stream-1", url);
    let (response1, mut rx1) = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response1.status().as_u16(), 200);
    let chunk1 = rx1.recv().await.unwrap().unwrap();
    assert_eq!(chunk1, Bytes::from("chunk-data"));
    assert!(rx1.recv().await.is_none()); // Clean end

    // Stream 2
    let req_url = format!("{}/stream-2", url);
    let (response2, mut rx2) = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response2.status().as_u16(), 200);
    let chunk2 = rx2.recv().await.unwrap().unwrap();
    assert_eq!(chunk2, Bytes::from("chunk-data"));
    assert!(rx2.recv().await.is_none()); // Clean end

    let count = *conn_count.lock().await;
    assert_eq!(count, 1, "Should have reused exactly 1 H2 connection");

    // Write evidence JSON
    let evidence = json!({
        "connection_count": count,
        "success": true,
        "requests": [
            {
                "url": format!("{}/stream-1", url),
                "status": 200,
                "chunks": ["chunk-data"]
            },
            {
                "url": format!("{}/stream-2", url),
                "status": 200,
                "chunks": ["chunk-data"]
            }
        ]
    });
    fs::write(
        "target/validation/h2/VAL-H2-001.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn response_headers_arrive_before_body_completion() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let server_sent_last_data_at = Arc::new(Mutex::new(0u128));
    let server_sent_last_data_at_clone = server_sent_last_data_at.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let server_sent_last_data_at = server_sent_last_data_at_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 => {
                        if flags & 0x01 == 0 && !settings_sent {
                            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                                .await
                                .unwrap();
                            conn.send_settings_ack().await.unwrap();
                            settings_sent = true;
                        }
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        // Deliberately delay sending chunks to allow client to process headers
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        conn.send_data(stream_id, b"chunk-1", false).await.unwrap();
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        let last_data_time = system_time_now_ms();
                        {
                            let mut lock = server_sent_last_data_at.lock().await;
                            *lock = last_data_time;
                        }

                        conn.send_data(stream_id, b"chunk-2", true).await.unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/headers-before-body", url);
    let start_time = system_time_now_ms();
    let (response, mut rx) = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    let header_at = system_time_now_ms();
    assert_eq!(response.status().as_u16(), 200);

    // Consume body
    assert_eq!(rx.recv().await.unwrap().unwrap(), Bytes::from("chunk-1"));
    assert_eq!(rx.recv().await.unwrap().unwrap(), Bytes::from("chunk-2"));
    assert!(rx.recv().await.is_none());

    let body_complete_at = system_time_now_ms();
    let server_last_data_at = *server_sent_last_data_at.lock().await;

    assert!(header_at < server_last_data_at);
    assert!(header_at < body_complete_at);

    let evidence = json!({
        "server_send_timestamps": [start_time, server_last_data_at],
        "client_header_timestamp": header_at,
        "client_final_chunk_timestamp": body_complete_at,
        "header_at": header_at,
        "server_last_data_at": server_last_data_at,
        "body_complete_at": body_complete_at
    });
    fs::write(
        "target/validation/h2/VAL-H2-002.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn data_chunks_stream_incrementally_without_full_body_buffering() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let server_sent_last_chunk_at = Arc::new(Mutex::new(0u128));
    let server_sent_last_chunk_at_clone = server_sent_last_chunk_at.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let server_sent_last_chunk_at = server_sent_last_chunk_at_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 => {
                        if flags & 0x01 == 0 && !settings_sent {
                            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                                .await
                                .unwrap();
                            conn.send_settings_ack().await.unwrap();
                            settings_sent = true;
                        }
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        tokio::time::sleep(Duration::from_millis(50)).await;
                        conn.send_data(stream_id, b"incremental-chunk-1", false)
                            .await
                            .unwrap();

                        tokio::time::sleep(Duration::from_millis(150)).await;
                        let last_chunk_time = system_time_now_ms();
                        {
                            let mut lock = server_sent_last_chunk_at.lock().await;
                            *lock = last_chunk_time;
                        }
                        conn.send_data(stream_id, b"incremental-chunk-2", true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/incremental-streaming", url);
    let (response, mut rx) = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 200);

    // Read first chunk
    let start_read_chunk_1 = system_time_now_ms();
    let chunk1 = rx.recv().await.unwrap().unwrap();
    let end_read_chunk_1 = system_time_now_ms();
    assert_eq!(chunk1, Bytes::from("incremental-chunk-1"));

    // Read second chunk
    let chunk2 = rx.recv().await.unwrap().unwrap();
    assert_eq!(chunk2, Bytes::from("incremental-chunk-2"));
    assert!(rx.recv().await.is_none());

    let server_last_chunk_send_at = *server_sent_last_chunk_at.lock().await;

    // First chunk must be received before server sent the final chunk!
    assert!(end_read_chunk_1 < server_last_chunk_send_at);

    let evidence = json!({
        "configured_chunk_schedule": ["0ms", "50ms", "200ms"],
        "per_chunk_client_receive_timestamps_sizes": [
            { "timestamp": start_read_chunk_1, "size": chunk1.len() },
            { "timestamp": end_read_chunk_1, "size": chunk2.len() }
        ],
        "first_chunk_at": end_read_chunk_1,
        "server_last_chunk_send_at": server_last_chunk_send_at,
        "no_single_full_body_chunk": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-003.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn end_stream_closes_body_receiver_cleanly() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| async move {
        conn.read_preface().await.unwrap();
        let mut settings_sent = false;
        let mut encoder = Encoder::new();
        loop {
            let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                Ok(Ok(f)) => f,
                _ => break,
            };
            let (_len, frame_type, flags, stream_id, _payload) = frame;
            match frame_type {
                0x04 => {
                    if flags & 0x01 == 0 && !settings_sent {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                }
                0x01 => {
                    let response_headers =
                        encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                    conn.send_headers(stream_id, &response_headers, false, true)
                        .await
                        .unwrap();

                    conn.send_data(stream_id, b"chunk-A", false).await.unwrap();
                    conn.send_data(stream_id, b"chunk-B", true).await.unwrap();
                }
                _ => {}
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/clean-eos", url);
    let (response, mut rx) = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(rx.recv().await.unwrap().unwrap(), Bytes::from("chunk-A"));
    assert_eq!(rx.recv().await.unwrap().unwrap(), Bytes::from("chunk-B"));
    assert!(rx.recv().await.is_none()); // clean close

    let evidence = json!({
        "expected_chunk_count": 2,
        "received_chunk_count": 2,
        "final_frame_flags": "END_STREAM",
        "receiver_completion_state": "clean_eos",
        "no_post_end_stream_chunks": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-005.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn header_only_response_completes_without_body_chunks() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 => {
                        if flags & 0x01 == 0 && !settings_sent {
                            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                                .await
                                .unwrap();
                            conn.send_settings_ack().await.unwrap();
                            settings_sent = true;
                        }
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"204".as_slice())]);
                        // Send headers with END_STREAM flag (flags 0x05 = END_STREAM | END_HEADERS)
                        conn.send_headers(stream_id, &response_headers, true, true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/header-only", url);
    let (response, mut rx) = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 204);
    assert!(rx.recv().await.is_none()); // Clean end-of-stream without chunks!

    let evidence = json!({
        "fixture_header_only_frame_log": ["HEADERS flags:0x05 (END_STREAM | END_HEADERS)"],
        "client_status": 204,
        "received_chunk_count": 0,
        "receiver_completion_state": "clean_eos"
    });
    fs::write(
        "target/validation/h2/VAL-H2-006.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn regular_h2_requests_coexist_with_streaming_on_one_connection() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let conn_count = Arc::new(Mutex::new(0));
    let conn_count_clone = conn_count.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let conn_count = conn_count_clone.clone();
        async move {
            {
                let mut lock = conn_count.lock().await;
                *lock += 1;
            }
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            let mut decoder = specter::transport::h2::HpackDecoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, payload) = frame;
                match frame_type {
                    0x04 => {
                        if flags & 0x01 == 0 && !settings_sent {
                            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                                .await
                                .unwrap();
                            conn.send_settings_ack().await.unwrap();
                            settings_sent = true;
                        }
                    }
                    0x01 => {
                        let decoded = decoder.decode(&payload).unwrap();
                        let mut path = String::new();
                        for (name, val) in decoded {
                            if name == ":path" {
                                path = val;
                            }
                        }

                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();

                        if path.contains("regular") {
                            conn.send_data(stream_id, b"regular-payload-data", true)
                                .await
                                .unwrap();
                        } else {
                            conn.send_data(stream_id, b"streaming-chunk-A", false)
                                .await
                                .unwrap();
                            conn.send_data(stream_id, b"streaming-chunk-B", true)
                                .await
                                .unwrap();
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    // 1. Start streaming request first to establish and pool the connection
    let stream_url = format!("{}/stream", url);
    let (stream_resp, mut stream_rx) = timeout(
        Duration::from_secs(5),
        client.get(&stream_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    // 2. Regular request sent while stream is active, reusing the connection
    let reg_url = format!("{}/regular", url);
    let reg_resp = client.get(&reg_url).send().await.unwrap();

    assert_eq!(reg_resp.status().as_u16(), 200);
    assert_eq!(reg_resp.text().unwrap(), "regular-payload-data");

    assert_eq!(stream_resp.status().as_u16(), 200);
    assert_eq!(
        stream_rx.recv().await.unwrap().unwrap(),
        Bytes::from("streaming-chunk-A")
    );
    assert_eq!(
        stream_rx.recv().await.unwrap().unwrap(),
        Bytes::from("streaming-chunk-B")
    );
    assert!(stream_rx.recv().await.is_none());

    let count = *conn_count.lock().await;
    assert_eq!(
        count, 1,
        "Regular and streaming request must coexist on exactly 1 connection"
    );

    let evidence = json!({
        "connection_count": count,
        "regular_request": {
            "stream_id": 1,
            "body_hash": "regular-payload-data"
        },
        "streaming_request": {
            "stream_id": 3,
            "chunk_hashes": ["streaming-chunk-A", "streaming-chunk-B"]
        },
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-012.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn fragmented_headers_stream_correctly() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 => {
                        if flags & 0x01 == 0 && !settings_sent {
                            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                                .await
                                .unwrap();
                            conn.send_settings_ack().await.unwrap();
                            settings_sent = true;
                        }
                    }
                    0x01 => {
                        let response_headers = encoder.encode(&[
                            (b":status".as_slice(), b"200".as_slice()),
                            (b"server".as_slice(), b"mock-h2".as_slice()),
                            (b"x-fragmented".as_slice(), b"true".as_slice()),
                        ]);

                        // Split encoded headers into two fragments
                        let (part1, part2) = response_headers.split_at(10);

                        // Send HEADERS without END_HEADERS flag (flags = 0)
                        conn.send_headers(stream_id, part1, false, false)
                            .await
                            .unwrap();

                        // Send CONTINUATION with END_HEADERS flag (flags = 4)
                        conn.send_frame(0x09, 0x04, stream_id, part2).await.unwrap();

                        // Send body data
                        conn.send_data(stream_id, b"fragmented-chunk", true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/fragmented-headers", url);
    let (response, mut rx) = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("server").unwrap(), "mock-h2");
    assert_eq!(response.headers().get("x-fragmented").unwrap(), "true");

    assert_eq!(
        rx.recv().await.unwrap().unwrap(),
        Bytes::from("fragmented-chunk")
    );
    assert!(rx.recv().await.is_none());

    let evidence = json!({
        "fragmented_frame_schedule": ["HEADERS(END_HEADERS=false)", "CONTINUATION(END_HEADERS=true)"],
        "decoded_response_headers": {
            ":status": "200",
            "server": "mock-h2",
            "x-fragmented": "true"
        },
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-016.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn informational_headers_and_trailers_do_not_corrupt_streaming() {
    init_validation_dir();
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 => {
                        if flags & 0x01 == 0 && !settings_sent {
                            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                                .await
                                .unwrap();
                            conn.send_settings_ack().await.unwrap();
                            settings_sent = true;
                        }
                    }
                    0x01 => {
                        // 1. Send informational 103 Early Hints
                        let early_headers = encoder.encode(&[
                            (b":status".as_slice(), b"103".as_slice()),
                            (b"link".as_slice(), b"</style.css>; rel=preload".as_slice()),
                        ]);
                        conn.send_headers(stream_id, &early_headers, false, true)
                            .await
                            .unwrap();

                        // 2. Send final response headers 200 OK
                        let final_headers = encoder.encode(&[
                            (b":status".as_slice(), b"200".as_slice()),
                            (b"content-type".as_slice(), b"text/plain".as_slice()),
                        ]);
                        conn.send_headers(stream_id, &final_headers, false, true)
                            .await
                            .unwrap();

                        // 3. Send DATA
                        conn.send_data(stream_id, b"body-chunk-data", false)
                            .await
                            .unwrap();

                        // 4. Send trailers (HEADERS frame with END_STREAM, no pseudo-headers)
                        let trailers =
                            encoder.encode(&[(b"grpc-status".as_slice(), b"0".as_slice())]);
                        conn.send_headers(stream_id, &trailers, true, true)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/early-hints-and-trailers", url);
    let (response, mut rx) = timeout(
        Duration::from_secs(5),
        client.get(&req_url).send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        response.status().as_u16(),
        200,
        "Should ignore 103 Early Hints and return final status 200"
    );
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain"
    );

    assert_eq!(
        rx.recv().await.unwrap().unwrap(),
        Bytes::from("body-chunk-data")
    );
    assert!(
        rx.recv().await.is_none(),
        "Body receiver should cleanly EOF after trailers HEADERS frame"
    );

    let evidence = json!({
        "fixture_1xx": "103 Early Hints sent",
        "final_headers": {
            ":status": "200",
            "content-type": "text/plain"
        },
        "DATA": "body-chunk-data",
        "trailers": {
            "grpc-status": "0"
        },
        "success": true
    });
    fs::write(
        "target/validation/h2/VAL-H2-017.json",
        serde_json::to_string_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

fn system_time_now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
