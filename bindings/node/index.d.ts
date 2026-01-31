/**
 * Specter - Node.js bindings for the Specter HTTP client.
 *
 * A high-performance async HTTP client with full TLS, HTTP/2, and HTTP/3
 * fingerprint control for browser impersonation.
 */

/** Browser fingerprint profiles for impersonation. */
export enum FingerprintProfile {
  /** Chrome 142 on macOS */
  Chrome142 = 0,
  /** Firefox 133 on macOS */
  Firefox133 = 1,
  /** No fingerprinting - use default TLS settings */
  None = 2,
}

/** HTTP version preference. */
export enum HttpVersion {
  /** Force HTTP/1.1 */
  Http1_1 = 0,
  /** Attempt HTTP/2, fallback to HTTP/1.1 */
  Http2 = 1,
  /** Attempt HTTP/3, fallback to HTTP/2, fallback to HTTP/1.1 */
  Http3 = 2,
  /** HTTP/3 only, no fallback */
  Http3Only = 3,
  /** Let the client decide based on server support */
  Auto = 4,
}

/** Timeout configuration for HTTP requests. */
export interface Timeouts {
  /** TCP + TLS/QUIC handshake timeout in seconds */
  connect?: number;
  /** Time-to-first-byte timeout in seconds */
  ttfb?: number;
  /** Maximum time between received bytes in seconds (resets on each chunk) */
  readIdle?: number;
  /** Maximum time between sent bytes in seconds */
  writeIdle?: number;
  /** Absolute deadline for entire request in seconds */
  total?: number;
  /** Time to wait for a pooled connection in seconds */
  poolAcquire?: number;
}

/** HTTP response with decompression support. */
export class Response {
  /** HTTP status code */
  get status(): number;
  /** Response headers as an object */
  get headers(): Record<string, string>;
  /** Get all headers as an array of [key, value] pairs */
  headersList(): string[][];
  /** Get a specific header value by name */
  getHeader(name: string): string | null;
  /** Get the response body as text (with decompression if needed) */
  text(): string;
  /** Get the response body as a Buffer */
  bytes(): Buffer;
  /** Parse the response body as JSON and return as string. Use JSON.parse to convert to an object. */
  json(): string;
  /** HTTP version string */
  get httpVersion(): string;
  /** Effective URL (after redirects) */
  get effectiveUrl(): string | null;
  /** Check if the response status is successful (2xx) */
  get isSuccess(): boolean;
  /** Check if the response is a redirect (3xx) */
  get isRedirect(): boolean;
  /** Get the redirect URL from Location header if present */
  get redirectUrl(): string | null;
  /** Get the Content-Type header value */
  get contentType(): string | null;
}

/** Builder for creating HTTP clients. */
export class ClientBuilder {
  /** Set the fingerprint profile */
  fingerprint(profile: FingerprintProfile): this;
  /** Set HTTP/2 preference */
  preferHttp2(prefer: boolean): this;
  /** Enable or disable automatic HTTP/3 upgrade via Alt-Svc headers */
  h3Upgrade(enabled: boolean): this;
  /** Set timeout configuration */
  timeouts(timeouts: Timeouts): this;
  /** Use API-optimized timeout defaults */
  apiTimeouts(): this;
  /** Use streaming-optimized timeout defaults */
  streamingTimeouts(): this;
  /** Set total request timeout in seconds */
  totalTimeout(timeoutSecs: number): this;
  /** Set connect timeout in seconds */
  connectTimeout(timeoutSecs: number): this;
  /** Set TTFB (time-to-first-byte) timeout in seconds */
  ttfbTimeout(timeoutSecs: number): this;
  /** Set read idle timeout in seconds */
  readTimeout(timeoutSecs: number): this;
  /** Skip TLS certificate verification for all connections (DANGEROUS - for testing only) */
  dangerAcceptInvalidCerts(accept: boolean): this;
  /** Automatically skip TLS certificate verification for localhost connections */
  localhostAllowsInvalidCerts(allow: boolean): this;
  /** Load root certificates from the operating system's certificate store */
  withPlatformRoots(enabled: boolean): this;
  /** Build the client */
  build(): Client;
}

/** HTTP client with TLS/HTTP2/HTTP3 fingerprint control. */
export class Client {
  /** Create a new client builder */
  static builder(): ClientBuilder;
  /** Make a GET request */
  get(url: string): Promise<Response>;
  /** Make a POST request */
  post(url: string): Promise<Response>;
  /** Make a PUT request */
  put(url: string): Promise<Response>;
  /** Make a DELETE request */
  delete(url: string): Promise<Response>;
}

/** Cookie jar for manual cookie management. */
export class CookieJar {
  constructor();
  /** Get the number of cookies in the jar */
  get length(): number;
  /** Check if the cookie jar is empty */
  get isEmpty(): boolean;
}

/** Sensible defaults for normal API calls. */
export function timeoutsApiDefaults(): Timeouts;

/** Sensible defaults for streaming responses. */
export function timeoutsStreamingDefaults(): Timeouts;
