//! RFC 7616 HTTP Digest Authentication Tests
//!
//! https://www.rfc-editor.org/rfc/rfc7616

use specter::auth::{digest_auth, parse_digest_challenge};

#[test]
fn test_digest_auth_sha256_rfc7616_example() {
    // Example values derived from RFC 7616 or similar standard vectors for SHA-256
    let username = "Mufasa";
    let realm = "http-auth@example.org";
    let password = "Circle Of Life";
    let nonce = "7ypf/xlj9xx7LHEy6n71sm1+y701z889";
    let uri = "/dir/index.html";
    let method = "GET";
    let qop = "auth";
    let nc = "00000001";
    let cnonce = "f2/wE4q74E6zIJEtWaHKCA";
    let algorithm = "SHA-256";
    let opaque = "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS";

    // Expected hash calculation:
    // A1 = "Mufasa:http-auth@example.org:Circle Of Life"
    // HA1 = SHA-256(A1) = 94560c960fdbe54a07e2bf476695b77d751773ccf39073f964baac6fe1dd3e26

    // A2 = "GET:/dir/index.html"
    // HA2 = SHA-256(A2) = 9a3fdae9a622fe8de177c24fa9c070f2b181ec85e15dcbdc32e10c82ad450b04

    // Response = SHA-256(HA1:nonce:nc:cnonce:qop:HA2)
    // 9456...:7ypf...:00000001:f2...:auth:9a3f...

    // Calculated SHA-256: b35034f0d5031aaa78d1f2f4959d3ff2afd3137a7f0db157cc630bd1b7a25e0e

    let header = digest_auth(
        username, password, method, uri, realm, nonce, cnonce, nc, qop, algorithm, opaque,
    );

    // Remove debug prints in production code or use tracing if needed.

    assert!(header.contains("Digest "));
    assert!(header.contains("username=\"Mufasa\""));
    assert!(header
        .contains("response=\"b35034f0d5031aaa78d1f2f4959d3ff2afd3137a7f0db157cc630bd1b7a25e0e\""));
    assert!(header.contains("algorithm=SHA-256"));
}

#[test]
fn test_parse_digest_challenge() {
    let header = "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    let params = parse_digest_challenge(header);

    assert_eq!(params.get("realm"), Some(&"testrealm@host.com".to_string()));
    assert_eq!(
        params.get("nonce"),
        Some(&"dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string())
    );
    assert_eq!(
        params.get("opaque"),
        Some(&"5ccc069c403ebaf9f0171e9517f40e41".to_string())
    );
}
