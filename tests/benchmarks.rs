use specter::Client;
use std::time::Instant;

/// Benchmark HTTP/1.1 connection pooling performance
#[tokio::test]
#[ignore] // Run with: cargo test --test benchmarks -- --ignored
async fn benchmark_h1_pooling() {
    // This test requires H1 pooling to be integrated into Client
    // Currently, Client doesn't use ConnectionPool for H1

    let _client = Client::builder().prefer_http2(false).build().unwrap();

    // TODO: Use mock server once H1 pooling is integrated
    println!("H1 pooling benchmark - requires integration");
}

/// Benchmark HTTP/2 multiplexing performance
#[tokio::test]
#[ignore]
async fn benchmark_h2_multiplexing() {
    let client = Client::builder().prefer_http2(true).build().unwrap();

    let url = "https://nghttp2.org/httpbin/delay/1";

    // Pre-warm connection
    let _ = client
        .get("https://nghttp2.org/robots.txt")
        .send()
        .await
        .expect("Pre-warm failed");

    // Measure 10 concurrent requests
    let start = Instant::now();
    let mut tasks = Vec::new();

    for _ in 0..10 {
        let client_clone = client.clone();
        tasks.push(tokio::spawn(
            async move { client_clone.get(url).send().await },
        ));
    }

    for task in tasks {
        let _ = task.await.unwrap().expect("Request failed");
    }

    let elapsed = start.elapsed();
    println!("10 concurrent H2 requests completed in {:?}", elapsed);

    // With true multiplexing: ~1s (all parallel)
    // With serialization: ~10s (all sequential)
    // Current: ~23s (severe serialization)
}
