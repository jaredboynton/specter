/**
 * Specter - Node.js bindings for the Specter HTTP client.
 *
 * gRPC surface (unary + message framing + trailers). The full generated type
 * surface for the rest of the binding is emitted to index.gen.d.ts at build time.
 */

/** gRPC per-stream message encoding negotiated via the `grpc-encoding` header. */
export enum GrpcEncoding {
  /** No compression. */
  Identity = 0,
  /** gzip compression. */
  Gzip = 1,
}

/**
 * Frame a single gRPC message: prepend the compression flag and big-endian
 * length, gzip-compressing the payload when `compress` is set and `encoding`
 * is `Gzip`.
 */
export function encodeMessage(
  payload: Buffer,
  compress: boolean,
  encoding: GrpcEncoding,
): Buffer;

/**
 * Incremental decoder for gRPC length-prefixed messages. Push raw body chunks
 * with `push`, then call `nextMessage` repeatedly until it returns null to
 * drain every fully-available message.
 */
export class GrpcFramer {
  constructor(encoding: GrpcEncoding);
  /** The negotiated stream encoding. */
  get encoding(): GrpcEncoding;
  /** Append an incoming body chunk. */
  push(chunk: Buffer): void;
  /** Next fully-available message payload, or null if more bytes are needed. */
  nextMessage(): Buffer | null;
}

/**
 * gRPC additions to the request/response surface. These declare only the
 * gRPC-relevant members; the full type surface for Client / RequestBuilder /
 * Response is emitted to index.gen.d.ts at build time.
 *
 * `Client.grpcRequest` presets a POST with the gRPC headers in wire order
 * (`content-type: application/grpc+proto`, `te: trailers`, and `grpc-encoding:
 * gzip` only for Gzip), composing with the existing `.body()` / `.send()` path.
 * `Response.trailers` awaits HTTP/2 trailers (e.g. `grpc-status`).
 */
export interface GrpcClient {
  /** Build a gRPC unary/streaming POST request with the gRPC headers preset. */
  grpcRequest(url: string, encoding: GrpcEncoding): GrpcRequestBuilder;
}

export interface GrpcRequestBuilder {
  /** Set the request body as framed gRPC message bytes. */
  body(body: Buffer): GrpcRequestBuilder;
  /** Send the request and resolve with the response. */
  send(): Promise<GrpcResponse>;
  /** Staged headers as [key, value] pairs in wire (insertion) order. */
  headersList(): Array<Array<string>>;
  /** The HTTP method for this request. */
  get method(): string;
}

export interface GrpcResponse {
  /**
   * Await HTTP/2 response trailers (e.g. gRPC `grpc-status` / `grpc-message`).
   * Resolves with an object of header pairs when present, or null when the
   * stream ended cleanly without trailers; rejects when the stream was reset.
   */
  trailers(): Promise<Record<string, string> | null>;
}
