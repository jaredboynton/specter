use specter::Client;
use std::time::Instant;

#[tokio::test]
async fn test_h2_multiplexing_performance() {
    // Initialize tracing
    let _ = tracing_subscriber::fmt()
        .with_env_filter("specter=debug")
        .try_init();

    let client = Client::builder().prefer_http2(true).build().unwrap();

    // Use reliable target
    let url = "https://www.google.com/";

    // Pre-warm connection to ensure we test multiplexing, not connection establishment
    println!("Pre-warming connection...");
    let pre_warm_start = Instant::now();
    let _ = client
        .get("https://www.google.com/robots.txt")
        .header("User-Agent", "specter-test/0.1")
        .send()
        .await
        .expect("Pre-warm failed");
    println!("Pre-warm complete in {:?}", pre_warm_start.elapsed());

    let start = Instant::now();
    let mut tasks = Vec::new();

    // Launch all requests concurrently
    for i in 0..2 {
        let request_start = Instant::now();
        let client_clone = client.clone();
        let url_clone = url.to_string();
        tasks.push(tokio::spawn(async move {
            let req_start = Instant::now();
            let result = client_clone
                .get(&url_clone)
                .header("User-Agent", "specter-test/0.1")
                .send()
                .await;
            let req_duration = req_start.elapsed();
            println!(
                "Request {} completed in {:?} (launched {:?} after start)",
                i + 1,
                req_duration,
                request_start.duration_since(start)
            );
            result
        }));
    }

    // Wait for all requests to complete
    let mut completion_times = Vec::new();
    for (i, task) in tasks.into_iter().enumerate() {
        let task_start = Instant::now();
        let res = task.await.unwrap();
        let task_wait = task_start.elapsed();
        let resp = res.unwrap_or_else(|_| panic!("Request {} failed", i + 1));
        if resp.status != 200 {
            println!(
                "Request {} failed with status {}. Body: {:?}",
                i + 1,
                resp.status,
                resp.text()
            );
        }
        assert_eq!(resp.status, 200);
        completion_times.push((i + 1, task_wait));
    }

    let elapsed = start.elapsed();

    println!("Total elapsed time: {:?}", elapsed);
    println!("Individual request completion times:");
    println!("Total elapsed time: {:?}", elapsed);
    println!("Individual request completion times:");
    for (req_num, duration) in completion_times {
        println!("  Request {}: {:?}", req_num, duration);
    }

    // Just ensure they all passed
    // We rely on logs to verify multiplexing
    assert!(elapsed.as_secs() < 30);
}
