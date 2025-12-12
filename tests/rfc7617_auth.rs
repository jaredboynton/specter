//! RFC 7617 HTTP Basic Authentication Tests
//!
//! https://www.rfc-editor.org/rfc/rfc7617

use specter::auth::{basic_auth, parse_basic_auth};

#[test]
fn test_basic_auth_encoding_rfc7617_section_2() {
    // "Aladdin" : "open sesame" -> "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    let header = basic_auth("Aladdin", "open sesame");
    assert_eq!(header, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
}

#[test]
fn test_basic_auth_roundtrip() {
    let user = "testuser";
    let pass = "secret123";
    let header = basic_auth(user, pass);

    let (u, p) = parse_basic_auth(&header).unwrap();
    assert_eq!(u, user);
    assert_eq!(p, pass);
}

#[test]
fn test_basic_auth_colon_in_password() {
    let user = "admin";
    let pass = "pass:word";
    let header = basic_auth(user, pass);

    let (u, p) = parse_basic_auth(&header).unwrap();
    assert_eq!(u, user);
    assert_eq!(p, pass);
}
