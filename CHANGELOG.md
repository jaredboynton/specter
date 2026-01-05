# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2026-01-05

### Added
- **TLS Certificate Verification Control**:
    - Added `danger_accept_invalid_certs(bool)` to `ClientBuilder` for skipping TLS verification (testing only).
    - Added `localhost_allows_invalid_certs(bool)` to `ClientBuilder` - enabled by default.
    - Localhost connections (`localhost`, `127.0.0.1`, `::1`) now automatically skip TLS certificate verification, making local development with self-signed certificates (e.g., mkcert) seamless.
    - Added `danger_accept_invalid_certs(bool)` to `BoringConnector` for low-level control.

## [1.0.0] - 2025-12-12

### Added
- **Authentication (RFC 7616 / 7617)**:
    - Added comprehensive **Digest Access Authentication** (RFC 7616) support covering `MD5`, `SHA-256`, and `auth` QOP.
    - Added **Basic Authentication** (RFC 7617) support with Base64 encoding helpers.
    - New module: `specter::auth`.

- **HTTP/1.1 (RFC 9112)**:
    - Implemented full **Connection Pooling** with idle connection management and Keep-Alive support.
    - Added detailed response parsing compliance tests.

- **HTTP/2 (RFC 9113)**:
    - **True Multiplexing**: Implemented concurrent stream management on a single TCP connection via the new `H2Driver` actor.
    - **Flow Control**: Verified compliance with window update and connection/stream flow control frames.
    - **State Machine**: Added rigorous testing for valid stream state transitions.
    - **HPACK (RFC 7541)**: Verified header compression and decompression compliance.
    - **Prioritization**: Implemented Extensible Prioritization and legacy RFC 7540 Priority Tree simulation for Chrome/Firefox fingerprinting.

- **HTTP/3 (RFC 9114 & RFC 9204)**:
    - Enabled **gQUIC** and **RFC 9114** support for next-gen transport.
    - Verified **QPACK (RFC 9204)** header compression compliance.
    - Implemented robust error handling for malformed frames and unexpected stream closure.
    - Added `H3Handle` to support request multiplexing over QUIC.

- **State Management & Caching**:
    - **Cookies (RFC 6265)**: Implemented `specter::cookie` for strict state management and parsing.
    - **HTTP Caching (RFC 9111)**: Added `specter::cache::HttpCache` for in-memory response caching with `Expires`, `Cache-Control`, `ETag`, and `Last-Modified` validation.

- **URL & Semantics**:
    - Verified **URI Generic Syntax (RFC 3986)** compliance.
    - Verified **HTTP Semantics (RFC 9110)** for method idempotency and header field parsing.

- **Testing Infrastructure**:
    - Added `MockH2Server` and `MockH3Server` for protocol-level fault injection.
    - Added integration test suite covering all aforementioned RFCs.

### Architecture
- **Transport Refactor**: Migrated `H2Connection` and `H3Connection` to a Driver/Handle actor model.
    - `*_Driver`: Owns the socket and background I/O loop.
    - `*_Handle`: Async interface for sending requests via message passing.
- **Pooling**: Centralized connection management in `specter::pool::ConnectionPool`.
