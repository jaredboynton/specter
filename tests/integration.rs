use specter::Client;

/// Test mixed protocol scenarios
#[tokio::test]
#[ignore]
async fn test_mixed_protocols() {
    let _client = Client::builder()
        .prefer_http2(false) // Prefer H1, but server may negotiate H2
        .build()
        .unwrap();

    // Test that protocol selection works correctly
    // TODO: Implement with mock servers for both protocols
    println!("Mixed protocol test - requires mock servers");
}

/// Test connection failure handling
#[tokio::test]
#[ignore]
async fn test_connection_failure() {
    // Test that pool cleanup works when connection fails
    // TODO: Implement with server that closes connections
    println!("Connection failure test - requires failure simulation");
}

/// Test concurrent clients don't interfere
#[tokio::test]
#[ignore]
async fn test_concurrent_clients() {
    let _client1 = Client::builder().prefer_http2(true).build().unwrap();
    let _client2 = Client::builder().prefer_http2(true).build().unwrap();

    // Verify clients have separate connection pools
    // TODO: Add instrumentation to verify pool isolation
    println!("Concurrent clients test - requires pool instrumentation");
}
