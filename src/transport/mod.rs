//! HTTP transport implementations.
//!
//! - HTTP/1.1 via httparse + tokio-boring (minimal, no hyper)
//! - HTTP/2 via custom implementation (full fingerprint control)
//! - HTTP/3 via Specter's native QUIC/H3 path

use std::borrow::Cow;

use http::Uri;

pub mod connector;
pub mod dns;
pub mod h1;
pub mod h1_h2;
pub mod h2;
pub mod h3;
pub mod session;
pub mod tcp;
pub mod zero_rtt;

pub use zero_rtt::{is_zero_rtt_safe_request, is_zero_rtt_safe_request_parts};

pub(crate) fn origin_form_path(uri: &Uri) -> Cow<'_, str> {
    match uri.path_and_query().map(|path| path.as_str()) {
        Some(path) if path.starts_with('/') => Cow::Borrowed(path),
        Some(path) if path.starts_with('?') => Cow::Owned(format!("/{path}")),
        Some(path) if !path.is_empty() => Cow::Borrowed(path),
        _ => Cow::Borrowed("/"),
    }
}

#[cfg(test)]
mod tests {
    use super::origin_form_path;
    use http::Uri;

    #[test]
    fn origin_form_path_preserves_slash_for_host_only_query() {
        let uri: Uri = "http://127.0.0.1:18743?client_version=26.506.31421"
            .parse()
            .unwrap();

        assert_eq!(origin_form_path(&uri), "/?client_version=26.506.31421");
    }
}
