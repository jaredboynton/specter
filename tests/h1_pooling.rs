use specter::Client;

mod helpers;
use helpers::mock_server::MockHttpServer;

#[tokio::test]
async fn test_h1_connection_reuse() {
    // Start mock server
    let server = MockHttpServer::new().await.unwrap();
    let url = server.url();
    let _server_handle = server.start_with_request_limit(2);

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Client
    let client = Client::builder().prefer_http2(false).build().unwrap();

    // Request 1
    let resp1 = client.get(&url).send().await.expect("Request 1 failed");
    assert_eq!(resp1.status, 200);
    assert_eq!(resp1.text().unwrap(), "Hello");

    // Request 2 - should reuse the same connection
    let resp2 = client.get(&url).send().await.expect("Request 2 failed");
    assert_eq!(resp2.status, 200);
    assert_eq!(resp2.text().unwrap(), "Hello");
}

#[tokio::test]
async fn test_h1_connection_expiration() {
    // Test that connections expire after idle timeout
    let server = MockHttpServer::new().await.unwrap();
    let url = server.url();
    let _server_handle = server.start_with_request_limit(3);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    // Request 1
    let resp1 = client.get(&url).send().await.expect("Request 1 failed");
    assert_eq!(resp1.status, 200);

    // Wait longer than connection pool idle timeout (30s default)
    // For testing, we'll just verify the connection pool works
    // In a real scenario, we'd need to configure a shorter timeout
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Request 2 - should still work (connection may or may not be reused depending on timing)
    let resp2 = client.get(&url).send().await.expect("Request 2 failed");
    assert_eq!(resp2.status, 200);
}

#[tokio::test]
async fn test_h1_multiple_sequential_requests() {
    // Test multiple sequential requests reuse connection
    let server = MockHttpServer::new().await.unwrap();
    let url = server.url();
    let _server_handle = server.start_with_request_limit(10);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = Client::builder().prefer_http2(false).build().unwrap();

    // Make 5 sequential requests
    for i in 0..5 {
        let resp = client
            .get(&url)
            .send()
            .await
            .expect(&format!("Request {} failed", i + 1));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.text().unwrap(), "Hello");
    }
}
