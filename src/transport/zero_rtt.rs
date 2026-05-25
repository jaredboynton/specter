//! Shared 0-RTT safety checks for HTTP transports.

use crate::request::RequestBody;

/// Returns true when a request may be sent as TLS 1.3 / QUIC 0-RTT early data.
///
/// Only safe idempotent methods with an empty body are allowed (RFC 8470).
pub fn is_zero_rtt_safe_request(method: &str, body: &RequestBody) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS") && body.is_empty()
}

/// Returns true when a request may be sent as early data using only method/body presence.
pub fn is_zero_rtt_safe_request_parts(method: &str, body_empty: bool) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS") && body_empty
}
