/**
 * Tests for the gRPC surface of the Warpsock Node.js bindings:
 * message framing (encodeMessage / GrpcFramer), grpcRequest header presets,
 * and Response.trailers().
 */

const http = require('http');
const zlib = require('zlib');

const {
  clientBuilder,
  GrpcEncoding,
  GrpcFramer,
  encodeMessage,
} = require('../index');

function createHttpFixture() {
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    const payload = Buffer.from('ok');
    res.writeHead(200, {
      'content-type': 'text/plain',
      'content-length': payload.length.toString(),
    });
    res.end(payload);
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        close: () => new Promise((done) => {
          if (typeof server.closeAllConnections === 'function') {
            server.closeAllConnections();
          }
          for (const socket of sockets) {
            socket.destroy();
          }
          server.close(done);
        }),
      });
    });
  });
}

describe('encodeMessage / GrpcFramer', () => {
  test('identity encode then frame round-trips the original payload', () => {
    const payload = Buffer.from('the quick brown fox');
    const framed = encodeMessage(payload, false, GrpcEncoding.Identity);

    // Wire shape: [flag=0][4B BE len][payload].
    expect(framed[0]).toBe(0);
    expect(framed.readUInt32BE(1)).toBe(payload.length);

    const framer = new GrpcFramer(GrpcEncoding.Identity);
    framer.push(framed);

    const message = framer.nextMessage();
    expect(message).not.toBeNull();
    expect(Buffer.from(message).equals(payload)).toBe(true);

    expect(framer.nextMessage()).toBeNull();
  });

  test('gzip encode then frame round-trips the original payload', () => {
    const payload = Buffer.from('compress me, then decompress me back exactly');
    const framed = encodeMessage(payload, true, GrpcEncoding.Gzip);

    // Compressed messages carry flag 1.
    expect(framed[0]).toBe(1);
    // Sanity: the framed body is the gzip of the payload, not the raw bytes.
    const body = framed.subarray(5);
    expect(zlib.gunzipSync(body).equals(payload)).toBe(true);

    const framer = new GrpcFramer(GrpcEncoding.Gzip);
    framer.push(framed);

    const message = framer.nextMessage();
    expect(message).not.toBeNull();
    expect(Buffer.from(message).equals(payload)).toBe(true);
    expect(framer.nextMessage()).toBeNull();
  });

  test('partial frame across the header boundary yields null until complete', () => {
    const payload = Buffer.from('payload-bytes');
    const framed = encodeMessage(payload, false, GrpcEncoding.Identity);

    const framer = new GrpcFramer(GrpcEncoding.Identity);

    // First slice: only 3 of the 5 header bytes.
    framer.push(framed.subarray(0, 3));
    expect(framer.nextMessage()).toBeNull();

    // Second slice: the remainder, completing the message.
    framer.push(framed.subarray(3));
    const message = framer.nextMessage();
    expect(message).not.toBeNull();
    expect(Buffer.from(message).equals(payload)).toBe(true);
    expect(framer.nextMessage()).toBeNull();
  });

  test('encoding getter reflects the constructor argument', () => {
    expect(new GrpcFramer(GrpcEncoding.Identity).encoding).toBe(GrpcEncoding.Identity);
    expect(new GrpcFramer(GrpcEncoding.Gzip).encoding).toBe(GrpcEncoding.Gzip);
  });
});

describe('Client.grpcRequest header presets', () => {
  let client;

  beforeAll(() => {
    client = clientBuilder().build();
  });

  test('identity preset is POST with content-type and te in order', () => {
    const req = client.grpcRequest(
      'https://127.0.0.1/helloworld.Greeter/SayHello',
      GrpcEncoding.Identity,
    );
    expect(req.method).toBe('POST');
    expect(req.headersList()).toEqual([
      ['content-type', 'application/grpc+proto'],
      ['te', 'trailers'],
    ]);
  });

  test('gzip preset appends grpc-encoding after te', () => {
    const req = client.grpcRequest(
      'https://127.0.0.1/helloworld.Greeter/SayHello',
      GrpcEncoding.Gzip,
    );
    expect(req.method).toBe('POST');
    expect(req.headersList()).toEqual([
      ['content-type', 'application/grpc+proto'],
      ['te', 'trailers'],
      ['grpc-encoding', 'gzip'],
    ]);
  });

  test('grpc preset composes with body()', () => {
    const req = client
      .grpcRequest('https://127.0.0.1/helloworld.Greeter/SayHello', GrpcEncoding.Identity)
      .body(encodeMessage(Buffer.from('hi'), false, GrpcEncoding.Identity));
    expect(req).toBeDefined();
    expect(req.headersList()[0]).toEqual(['content-type', 'application/grpc+proto']);
  });
});

describe('Response.trailers', () => {
  let fixture;
  let client;

  beforeAll(async () => {
    fixture = await createHttpFixture();
    client = clientBuilder().build();
  });

  afterAll(async () => {
    if (fixture) {
      await fixture.close();
    }
  });

  test('returns null for a non-trailers (buffered HTTP/1.1) response', async () => {
    const response = await client.get(`${fixture.baseUrl}/get`).send();
    expect(response.status).toBe(200);
    const trailers = await response.trailers();
    expect(trailers).toBeNull();
  });
});
