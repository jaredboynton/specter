//! RFC 7541 HPACK Header Compression Tests
//!
//! https://www.rfc-editor.org/rfc/rfc7541

use bytes::BytesMut;
use specter::transport::h2::{HpackDecoder, HpackEncoder};

#[test]
fn test_dynamic_table_size_update_rfc7541_section_6_3() {
    // We use chrome() which sets default pseudo order
    let mut encoder = HpackEncoder::chrome();
    let mut decoder = HpackDecoder::new();

    // Start with default size

    // Encode some headers to populate dynamic table
    // We must use encode_request which adds pseudo headers
    let headers = vec![
        ("custom-header".to_string(), "custom-value".to_string()),
        ("another-header".to_string(), "another-value".to_string()),
    ];

    let block = encoder.encode_request("GET", "https", "example.com", "/", &headers);

    // Decode with fresh decoder
    let decoded = decoder.decode(&block).expect("Should decode");

    // Check custom headers are present (pseudo headers are also present)
    assert!(decoded.contains(&("custom-header".to_string(), "custom-value".to_string())));

    // Now update dynamic table size to 0 to evict everything
    encoder.set_max_table_size(0);

    // Re-encode a header that would have been indexed
    let block2 = encoder.encode_request("GET", "https", "example.com", "/", &headers);

    // The decoder must be updated about limit 0
    decoder.set_max_table_size(0);

    // Decode
    let decoded2 = decoder
        .decode(&block2)
        .expect("Should decode after size update");
    assert!(decoded2.contains(&("custom-header".to_string(), "custom-value".to_string())));
}

#[test]
fn test_hpack_eviction_rfc7541() {
    // RFC 7541: When table full, evict oldest entries.
    // Set small table size
    let mut encoder = HpackEncoder::chrome();
    encoder.set_max_table_size(100); // Small size

    // "header-1": "value-1" (~16+32=48 bytes)
    // "header-2": "value-2" (~16+32=48 bytes)

    let h1 = vec![("header-1".to_string(), "value-1".to_string())];
    let h2 = vec![("header-2".to_string(), "value-2".to_string())];

    let _ = encoder.encode_request("GET", "https", "example.com", "/", &h1);
    // Dynamic table should have h1 and pseudo headers?
    // Note: Pseudo headers like :method: GET might be indexed too.
    // 100 bytes is very small.
    // :method: GET (static index 2) - not in dynamic table?
    // hpack_impl logic likely uses static table for common fields.
    // custom headers go to dynamic table.

    let _ = encoder.encode_request("GET", "https", "example.com", "/", &h2);

    // To verify eviction without internals is hard, but we can verify consistency
    // by decoding.

    let mut decoder = HpackDecoder::new();
    decoder.set_max_table_size(100);

    // We basically just verify that the encoder continues to produce valid streams
    // that the decoder can read, maintaining RFC compliance for the bitstream.

    let block3 = encoder.encode_request("GET", "https", "example.com", "/", &h1);
    let decoded3 = decoder.decode(&block3).unwrap();
    assert!(decoded3.contains(&("header-1".to_string(), "value-1".to_string())));
}
