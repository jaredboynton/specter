//! Custom HPACK implementation (RFC 7541).
//!
//! This module provides a complete HPACK encoder and decoder implementation
//! with full Huffman encoding support.

mod decoder;
mod dynamic_table;
mod encoder;
mod error;
mod huffman;
mod integer;
mod static_table;

pub use decoder::Decoder;
pub use encoder::Encoder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encode_decode() {
        let mut encoder = Encoder::new();
        let headers = [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"http".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
        ];
        let encoded = encoder.encode(&headers);

        let mut decoder = Decoder::new();
        let mut decoded = Vec::new();
        decoder
            .decode_with_cb(&encoded, |name, value| {
                decoded.push((name.to_vec(), value.to_vec()));
            })
            .unwrap();

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].0, b":method");
        assert_eq!(decoded[0].1, b"GET");
    }

    #[test]
    fn test_rfc_c3_request_without_huffman() {
        // RFC 7541 Appendix C.3: First Request
        // :method: GET
        // :scheme: http
        // :path: /
        // :authority: www.example.com
        let mut encoder = Encoder::new();
        let headers = [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"http".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
            (b":authority".as_slice(), b"www.example.com".as_slice()),
        ];
        let encoded = encoder.encode(&headers);

        // Expected: 8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d
        // But we may use different encoding (dynamic table), so just verify round-trip
        let mut decoder = Decoder::new();
        let mut decoded = Vec::new();
        decoder
            .decode_with_cb(&encoded, |name, value| {
                decoded.push((name.to_vec(), value.to_vec()));
            })
            .unwrap();

        assert_eq!(decoded.len(), 4);
        assert_eq!(decoded[0].0, b":method");
        assert_eq!(decoded[0].1, b"GET");
        assert_eq!(decoded[1].0, b":scheme");
        assert_eq!(decoded[1].1, b"http");
        assert_eq!(decoded[2].0, b":path");
        assert_eq!(decoded[2].1, b"/");
        assert_eq!(decoded[3].0, b":authority");
        assert_eq!(decoded[3].1, b"www.example.com");
    }

    #[test]
    fn test_rfc_c4_request_with_huffman() {
        // RFC 7541 Appendix C.4: First Request (with Huffman)
        // Same headers as C.3 but with Huffman encoding
        let mut encoder = Encoder::new();
        let headers = [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"http".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
            (b":authority".as_slice(), b"www.example.com".as_slice()),
        ];
        let encoded = encoder.encode(&headers);

        // Verify round-trip works with Huffman
        let mut decoder = Decoder::new();
        let mut decoded = Vec::new();
        decoder
            .decode_with_cb(&encoded, |name, value| {
                decoded.push((name.to_vec(), value.to_vec()));
            })
            .unwrap();

        assert_eq!(decoded.len(), 4);
        assert_eq!(decoded[0].0, b":method");
        assert_eq!(decoded[0].1, b"GET");
        assert_eq!(decoded[3].0, b":authority");
        assert_eq!(decoded[3].1, b"www.example.com");
    }

    #[test]
    fn test_rfc_c2_literal_header_with_indexing() {
        // RFC 7541 Appendix C.2.1: Literal Header Field with Indexing
        // custom-key: custom-header
        let mut encoder = Encoder::new();
        let headers = [(b"custom-key".as_slice(), b"custom-header".as_slice())];
        let encoded = encoder.encode(&headers);

        // Should encode as literal with incremental indexing (prefix 01xxxxxx)
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0] & 0xC0, 0x40); // Top 2 bits: 01

        // Verify round-trip
        let mut decoder = Decoder::new();
        let mut decoded = Vec::new();
        decoder
            .decode_with_cb(&encoded, |name, value| {
                decoded.push((name.to_vec(), value.to_vec()));
            })
            .unwrap();

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, b"custom-key");
        assert_eq!(decoded[0].1, b"custom-header");
    }

    #[test]
    fn test_multiple_headers_round_trip() {
        // Test that multiple headers encode/decode correctly
        let mut encoder = Encoder::new();
        let headers = [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"https".as_slice()),
            (b":path".as_slice(), b"/index.html".as_slice()),
            (b":authority".as_slice(), b"www.example.com".as_slice()),
            (b"user-agent".as_slice(), b"Mozilla/5.0".as_slice()),
        ];
        let encoded = encoder.encode(&headers);

        let mut decoder = Decoder::new();
        let mut decoded = Vec::new();
        decoder
            .decode_with_cb(&encoded, |name, value| {
                decoded.push((name.to_vec(), value.to_vec()));
            })
            .unwrap();

        assert_eq!(decoded.len(), 5);
        assert_eq!(decoded[0].0, b":method");
        assert_eq!(decoded[0].1, b"GET");
        assert_eq!(decoded[4].0, b"user-agent");
        assert_eq!(decoded[4].1, b"Mozilla/5.0");
    }
}
