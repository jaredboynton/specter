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

/** HTTP request builder for setting headers and body. */
export class RequestBuilder {
  /** Add a header to the request. Returns this for chaining. */
  header(key: string, value: string): this;
  /** Set all headers (replaces existing headers). Returns this for chaining. */
  headers(headers: string[][]): this;
  /** Set the request body as bytes. Returns this for chaining. */
  body(body: Buffer): this;
  /** Set the request body as JSON string and add Content-Type header. Returns this for chaining. */
  json(jsonStr: string): this;
  /** Set the request body as form data and add Content-Type header. Returns this for chaining. */
  form(formStr: string): this;
  /** Send the request and return the response. */
  send(): Promise<Response>;
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
  /** Create a GET request builder */
  get(url: string): RequestBuilder;
  /** Create a POST request builder */
  post(url: string): RequestBuilder;
  /** Create a PUT request builder */
  put(url: string): RequestBuilder;
  /** Create a DELETE request builder */
  delete(url: string): RequestBuilder;
  /** Create a PATCH request builder */
  patch(url: string): RequestBuilder;
  /** Create a HEAD request builder */
  head(url: string): RequestBuilder;
  /** Create an OPTIONS request builder */
  options(url: string): RequestBuilder;
  /** Create a request builder for an arbitrary HTTP method */
  request(method: string, url: string): RequestBuilder;
}

/** Cookie jar for manual cookie management. */
export class CookieJar {
  constructor();
  /** Get the number of cookies in the jar */
  get length(): number;
  /** Check if the cookie jar is empty */
  get isEmpty(): boolean;
}

/** Create a new client builder */
export function clientBuilder(): ClientBuilder;

/** Sensible defaults for normal API calls. */
export function timeoutsApiDefaults(): Timeouts;

/** Sensible defaults for streaming responses. */
export function timeoutsStreamingDefaults(): Timeouts;

export {};