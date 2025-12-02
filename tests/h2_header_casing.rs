use specter::transport::h2::{HpackEncoder, HpackDecoder};

#[test]
fn test_uppercase_headers_are_not_lowercased() {
    // 1. Create encoder (Chrome order)
    let mut encoder = HpackEncoder::chrome();

    // 2. Encode a request with uppercase headers
    // This simulates what happens if a user passes "Authorization" or "Content-Type"
    let headers = vec![
        ("Authorization".to_string(), "Bearer token".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("x-custom-Header".to_string(), "value".to_string()),
    ];

    let encoded = encoder.encode_request(
        "GET",
        "https",
        "example.com",
        "/resource",
        &headers,
    );

    // 3. Decode the block
    let mut decoder = HpackDecoder::new();
    let decoded = decoder.decode(&encoded).expect("Failed to decode headers");

    // 4. Verify the casing
    // We expect to find pseudo-headers first
    let mut found_auth_upper = false;
    let mut found_auth_lower = false;
    let mut found_content_type_upper = false;
    let mut found_content_type_lower = false;
    let mut found_custom_mixed = false;
    let mut found_custom_lower = false;

    for (name, _value) in decoded {
        if name == "Authorization" { found_auth_upper = true; }
        if name == "authorization" { found_auth_lower = true; }
        
        if name == "Content-Type" { found_content_type_upper = true; }
        if name == "content-type" { found_content_type_lower = true; }

        if name == "x-custom-Header" { found_custom_mixed = true; }
        if name == "x-custom-header" { found_custom_lower = true; }
    }

    // Assert correct behavior:
    // 1. Uppercase/mixed versions should NOT exist
    assert!(!found_auth_upper, "Found 'Authorization' (uppercase) - should have been lowercased");
    assert!(!found_content_type_upper, "Found 'Content-Type' (uppercase) - should have been lowercased");
    assert!(!found_custom_mixed, "Found 'x-custom-Header' (mixed) - should have been lowercased");

    // 2. Lowercase versions MUST exist
    assert!(found_auth_lower, "Missing 'authorization' header");
    assert!(found_content_type_lower, "Missing 'content-type' header");
    assert!(found_custom_lower, "Missing 'x-custom-header' header");
}
