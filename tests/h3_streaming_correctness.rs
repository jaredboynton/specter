use bytes::Bytes;
use specter::transport::h3::H3Client;
use std::time::Duration;

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Server};

#[tokio::test]
async fn h3_streaming_returns_headers_before_body_completion_and_chunks_incrementally() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        let stream_id = loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id, .. }) => break stream_id,
                Some(_) => continue,
                None => return,
            }
        };

        conn.send_response_headers(stream_id, vec![(":status", "200")], false)
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn.send_response_data(stream_id, b"one", false).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn.send_response_data(stream_id, b"two", true).await;
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let (response, mut body_rx) = tokio::time::timeout(
        Duration::from_secs(3),
        client.send_streaming(&url, "GET", vec![], None),
    )
    .await
    .expect("headers should arrive before body finishes")
    .unwrap();

    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());

    let first = body_rx.recv().await.unwrap().unwrap();
    assert_eq!(first, Bytes::from_static(b"one"));
    let second = body_rx.recv().await.unwrap().unwrap();
    assert_eq!(second, Bytes::from_static(b"two"));
    assert!(body_rx.recv().await.is_none());
}

#[tokio::test]
async fn h3_streaming_sends_request_body() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url();

    server.start(|conn| async move {
        let mut stream_id = None;
        let mut received = Vec::new();
        loop {
            match conn.read_event().await {
                Some(MockEvent::Headers { stream_id: id, .. }) => stream_id = Some(id),
                Some(MockEvent::Data { data, .. }) => received.extend_from_slice(&data),
                Some(MockEvent::Finished { stream_id: id }) => {
                    assert_eq!(stream_id, Some(id));
                    assert_eq!(received, b"upload-body");
                    conn.send_response_headers(id, vec![(":status", "200")], false)
                        .await;
                    conn.send_response_data(id, b"accepted", true).await;
                    return;
                }
                Some(_) => {}
                None => return,
            }
        }
    });

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let (response, mut body_rx) = client
        .send_streaming(&url, "POST", vec![], Some(b"upload-body".to_vec()))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(
        body_rx.recv().await.unwrap().unwrap(),
        Bytes::from_static(b"accepted")
    );
    assert!(body_rx.recv().await.is_none());
}
