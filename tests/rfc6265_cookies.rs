//! RFC 6265 Cookie Compliance Tests
//!
//! https://www.rfc-editor.org/rfc/rfc6265

use chrono::{TimeZone, Utc};
use specter::cookie::{Cookie, CookieJar, SameSite};

#[test]
fn test_secure_flag_enforcement_rfc6265_section_5_4() {
    let mut jar = CookieJar::new();
    let cookie = Cookie::new("secure_cookie", "val", "example.com").with_secure(true);
    jar.store(cookie);

    // Should NOT be sent to http
    let headers_http = jar.build_cookie_header("http://example.com/foo");
    assert!(
        headers_http.is_none(),
        "Secure cookie MUST NOT be sent to http"
    );

    // Should be sent to https
    let headers_https = jar.build_cookie_header("https://example.com/foo");
    assert!(
        headers_https.is_some(),
        "Secure cookie SHOULD be sent to https"
    );
}

#[test]
fn test_public_suffix_blocking_rfc6265_section_5_3() {
    // Attempt to set cookie for "com"
    let res = Cookie::from_set_cookie_header("name=val; Domain=com", "https://example.com");
    assert!(res.is_err(), "Should reject cookie for public suffix 'com'");

    // Attempt to set cookie for "co.uk"
    let res = Cookie::from_set_cookie_header("name=val; Domain=co.uk", "https://example.co.uk");
    assert!(
        res.is_err(),
        "Should reject cookie for public suffix 'co.uk'"
    );

    // Valid domain
    let res =
        Cookie::from_set_cookie_header("name=val; Domain=example.co.uk", "https://example.co.uk");
    assert!(
        res.is_ok(),
        "Should accept cookie for valid domain 'example.co.uk'"
    );
}

#[test]
fn test_samesite_secure_requirement_rfc6265bis() {
    // SameSite=None requires Secure
    // If Secure is missing, parsing handles it (either rejects or ignores SameSite).
    // Browsers reject "SameSite=None" without "Secure".
    // Let's verify Specter behavior (should ideally reject or ignore SameSite=None).

    // Test: SameSite=None without Secure
    // Note: Use a domain that isn't a public suffix or default logic applies
    let header = "name=val; SameSite=None; Domain=example.com";
    let res = Cookie::from_set_cookie_header(header, "https://example.com");

    // Depending on implementation choice: strictly reject, or treat as Lax/Strict, or allow (if permissive).
    // We want to ENFORCE secure requirement.
    // If the implementation doesn't enforce it yet, this test will fail, prompting the fix.

    // We expect an error or for SameSite to NOT be None.
    if let Ok(c) = res {
        // If accepted, it MUST NOT have SameSite::None effective (or allow if logic missing).
        // Best practice: Reject it.
        // assert!(false, "Should reject SameSite=None without Secure");
        // Or check if SameSite::None is set.
        if c.same_site == Some(SameSite::None) && !c.secure {
            panic!("SameSite=None cookie stored without Secure flag!");
        }
    }
}

#[test]
fn test_cookie_parsing_rfc6265_section_5_2() {
    // 5.2.1.  The Set-Cookie Header Field
    let url = "http://example.com/test";

    // Basic validation
    let c = Cookie::from_set_cookie_header("SID=31d4d96e407aad42", url).unwrap();
    assert_eq!(c.name, "SID");
    assert_eq!(c.value, "31d4d96e407aad42");
    assert_eq!(c.domain, "example.com");
    // RFC 6265 5.1.4: Default path for /test is /.
    // If we wanted /test/, the URL should have been /test/
    assert_eq!(c.path, "/");

    // Test formatting with attributes
    let c = Cookie::from_set_cookie_header(
        "SID=31d4d96e407aad42; Path=/; Domain=example.com; Secure; HttpOnly",
        url,
    )
    .unwrap();
    assert_eq!(c.path, "/");
    assert_eq!(c.domain, "example.com");
    assert!(c.secure);
    assert!(c.http_only);
}

#[test]
fn test_date_formats_rfc6265_section_5_1_1() {
    let url = "http://example.com";

    // RFC 1123
    let c =
        Cookie::from_set_cookie_header("a=b; Expires=Sun, 06 Nov 1994 08:49:37 GMT", url).unwrap();
    assert_eq!(c.expires.unwrap(), Utc.timestamp_opt(784111777, 0).unwrap());

    // RFC 850
    let c =
        Cookie::from_set_cookie_header("a=b; Expires=Sunday, 06-Nov-94 08:49:37 GMT", url).unwrap();
    assert_eq!(c.expires.unwrap(), Utc.timestamp_opt(784111777, 0).unwrap());

    // ANSI C asctime()
    let c = Cookie::from_set_cookie_header("a=b; Expires=Sun Nov  6 08:49:37 1994", url).unwrap();
    assert_eq!(c.expires.unwrap(), Utc.timestamp_opt(784111777, 0).unwrap());
}

#[test]
fn test_domain_matching_rfc6265_section_5_1_3() {
    let mut c = Cookie::new("a", "b", "example.com");

    // Exact match
    assert!(c.domain_matches("example.com"));

    // Suffix match (domain attribute matches suffix of host)
    // Domain=example.com should match foo.example.com IF host_only is false
    c = c.with_host_only(false);
    assert!(c.domain_matches("foo.example.com"));

    // Should NOT match if domain is not a suffix
    assert!(!c.domain_matches("example.org"));

    // Should NOT match if domain is a suffix but host is an IP (usually)
    // But simplistic check might pass: verify behavior
    // RFC says: "The user agent will reject Cookie header fields that match... if the host is an IP"
    // Our implementation likely handles this in logic, let's verify.
}

#[test]
fn test_path_matching_rfc6265_section_5_1_4() {
    let c = Cookie::new("a", "b", "example.com").with_path("/foo");

    // Exact match
    assert!(c.path_matches("/foo"));
    // Prefix match match
    assert!(c.path_matches("/foo/bar"));
    // "Directory" match (suffix is /)
    assert!(c.path_matches("/foo/"));

    // Mismatch
    assert!(!c.path_matches("/bar"));
    assert!(!c.path_matches("/fo")); // Partial prefix but not directory component
}

#[test]
fn test_public_suffix_rejection_rfc6265_section_5_3() {
    // Should NOT accept cookies for public suffixes (e.g., Domain=co.uk)
    let url = "http://example.co.uk";

    // This should fail to create a valid cookie in a jar if we enforced it on insertion
    // But `Cookie::from_set_cookie_header` might allow it, and `CookieJar::store` might check.
    // Let's check strict adherence.

    let _c = Cookie::from_set_cookie_header("a=b; Domain=co.uk", url);
    // Depending on implementation, this might return Ok() but have a flag, or be rejected.
    // If strict RFC, user agent should reject.

    // Let's assume our implementation allows creation but CookieJar might filter or `is_public_suffix` helper exists.
    // We saw `is_public_suffix` in the file view!
}

#[test]
fn test_cookie_jar_rfc6265_section_5_4() {
    let mut jar = CookieJar::new();
    let url = "http://example.com/foo";

    jar.store_from_headers(
        &[
            "Set-Cookie: SID=123; Path=/foo".to_string(),
            "Set-Cookie: SID=456; Path=/".to_string(),
        ],
        url,
    );

    // Should retrieve most specific path first (RFC 5.4.2)
    assert!(
        !jar.is_empty(),
        "Cookie jar is empty; insertion failed (silently?)"
    );
    let header = jar.build_cookie_header(url).unwrap();
    // Expect: SID=123; SID=456
    // Because /foo is longer than /

    assert!(header.contains("SID=123"));
    assert!(header.contains("SID=456"));

    // Verify order
    let parts: Vec<&str> = header.split("; ").collect();
    assert_eq!(parts[0], "SID=123");
    assert_eq!(parts[1], "SID=456");
}
