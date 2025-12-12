//! RFC 9110 HTTP Semantics Tests
//!
//! Covers Redirects, Content Negotiation, and Conditional Requests.
//! https://www.rfc-editor.org/rfc/rfc9110

use http::Method;
use specter::transport::h1::H1Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn run_mock_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        let request = String::from_utf8_lossy(&buf[..n]);

                        if request.contains("GET /redirect") {
                            let response = "HTTP/1.1 301 Moved Permanently\r\n\
                                            Location: /target\r\n\
                                            Content-Length: 0\r\n\
                                            Connection: close\r\n\r\n";
                            let _ = socket.write_all(response.as_bytes()).await;
                        } else if request.contains("GET /negotiate") {
                            // Check Accept header
                            if request.contains("Accept: application/json") {
                                let response = "HTTP/1.1 200 OK\r\n\
                                                 Content-Type: application/json\r\n\
                                                 Content-Length: 2\r\n\
                                                 Connection: close\r\n\r\n{}";
                                let _ = socket.write_all(response.as_bytes()).await;
                            } else {
                                let response = "HTTP/1.1 406 Not Acceptable\r\n\
                                                 Content-Length: 0\r\n\
                                                 Connection: close\r\n\r\n";
                                let _ = socket.write_all(response.as_bytes()).await;
                            }
                        } else if request.contains("GET /conditional") {
                            // Check If-None-Match
                            if request.contains("If-None-Match: \"123\"") {
                                let response = "HTTP/1.1 304 Not Modified\r\n\
                                                ETag: \"123\"\r\n\
                                                Content-Length: 0\r\n\
                                                Connection: close\r\n\r\n";
                                let _ = socket.write_all(response.as_bytes()).await;
                            } else {
                                let response = "HTTP/1.1 200 OK\r\n\
                                                ETag: \"123\"\r\n\
                                                Content-Length: 4\r\n\
                                                Connection: close\r\n\r\ndata";
                                let _ = socket.write_all(response.as_bytes()).await;
                            }
                        }
                    }
                });
            }
        }
    });

    (format!("http://{}", addr), handle)
}

#[tokio::test]
async fn test_redirect_response_301() {
    // Tests that client receives 301. Manual redirect handling.
    // Auto-redirect is not currently implemented in Client (based on previous observations),
    // so we verify we get the 301 status.
    let (base_url, _server) = run_mock_server().await;

    // We use H1Connection directly or Client? Client is easier if available.
    // Client depends on BoringConnector which might need setup.
    // H1Connection is lower level. Let's use H1Connection for test simplicity if possible,
    // or standard Client if exposed.
    // Using simple TcpStream for H1Connection.

    use specter::transport::connector::MaybeHttpsStream;
    use tokio::net::TcpStream;

    let uri: http::Uri = format!("{}/redirect", base_url).parse().unwrap();
    let host = uri.host().unwrap();
    let port = uri.port_u16().unwrap();

    let stream = TcpStream::connect((host, port)).await.unwrap();
    let maybe_ssl = MaybeHttpsStream::Http(stream);

    let mut conn = H1Connection::new(maybe_ssl);
    let response = conn
        .send_request(
            Method::GET,
            &uri,
            vec![("Host".to_string(), host.to_string())],
            None,
        )
        .await
        .expect("Request failed");

    assert_eq!(response.status, 301);
    assert_eq!(response.get_header("location").unwrap(), "/target");
}

#[tokio::test]
async fn test_content_negotiation_accept_header() {
    let (base_url, _server) = run_mock_server().await;
    let uri: http::Uri = format!("{}/negotiate", base_url).parse().unwrap();
    let host = uri.host().unwrap();
    let port = uri.port_u16().unwrap();

    use specter::transport::connector::MaybeHttpsStream;
    use tokio::net::TcpStream;
    let stream = TcpStream::connect((host, port)).await.unwrap();
    let mut conn = H1Connection::new(MaybeHttpsStream::Http(stream));

    // Client sends Accept header
    let response = conn
        .send_request(
            Method::GET,
            &uri,
            vec![
                ("Host".to_string(), host.to_string()),
                ("Accept".to_string(), "application/json".to_string()),
            ],
            None,
        )
        .await
        .expect("Request failed");

    assert_eq!(response.status, 200);
    assert_eq!(
        response.get_header("content-type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn test_conditional_request_if_none_match() {
    let (base_url, _server) = run_mock_server().await;
    let uri: http::Uri = format!("{}/conditional", base_url).parse().unwrap();
    let host = uri.host().unwrap();
    let port = uri.port_u16().unwrap();

    use specter::transport::connector::MaybeHttpsStream;
    use tokio::net::TcpStream;
    let stream = TcpStream::connect((host, port)).await.unwrap();
    let mut conn = H1Connection::new(MaybeHttpsStream::Http(stream));

    // Send If-None-Match
    let response = conn
        .send_request(
            Method::GET,
            &uri,
            vec![
                ("Host".to_string(), host.to_string()),
                ("If-None-Match".to_string(), "\"123\"".to_string()),
            ],
            None,
        )
        .await
        .expect("Request failed");

    assert_eq!(response.status, 304); // Not Modified
}
