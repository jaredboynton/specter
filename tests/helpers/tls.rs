use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use boring::x509::X509;

/// Generate a self-signed certificate for 127.0.0.1 and return SslAcceptorBuilder + CA cert bytes.
pub fn generate_cert_bundle() -> (SslAcceptorBuilder, Vec<u8>) {
    let subject_alt_names = vec!["127.0.0.1".to_string(), "localhost".to_string()];

    // Generate self-signed certificate
    let cert =
        rcgen::generate_simple_self_signed(subject_alt_names).expect("Failed to generate cert");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    let pkey = PKey::private_key_from_pem(key_pem.as_bytes()).expect("Failed to parse private key");
    let x509 = X509::from_pem(cert_pem.as_bytes()).expect("Failed to parse certificate");

    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .expect("Failed to create SslAcceptor builder");
    builder
        .set_private_key(&pkey)
        .expect("Failed to set private key");
    builder
        .set_certificate(&x509)
        .expect("Failed to set certificate");

    // Return builder and the cert bytes (which acts as CA since self-signed)
    (builder, cert_pem.into_bytes())
}
