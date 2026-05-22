use specter::transport::h3::H3Client;
use std::sync::atomic::Ordering;
use std::time::Duration;

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Server};

#[tokio::test]
async fn h3_client_reuses_pooled_connection_for_same_authority() {
    let server = MockH3Server::new().await.unwrap();
    let connection_count = server.connection_count();
    let url = server.url();

    server.start(|conn| async move {
        for _ in 0..2 {
            let stream_id = loop {
                match conn.read_event().await {
                    Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                    Some(_) => continue,
                    None => return,
                }
            };

            conn.send_response_headers(
                stream_id,
                vec![(":status", "200"), ("content-type", "text/plain")],
                false,
            )
            .await;
            conn.send_response_data(stream_id, b"ok", true).await;
        }
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let first = client
        .send_request(&url, "GET", vec![], None)
        .await
        .unwrap();
    let second = client
        .send_request(&url, "GET", vec![], None)
        .await
        .unwrap();

    assert_eq!(first.status(), 200);
    assert_eq!(second.status(), 200);
    assert_eq!(first.body().as_ref(), b"ok");
    assert_eq!(second.body().as_ref(), b"ok");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(connection_count.load(Ordering::SeqCst), 1);
}
