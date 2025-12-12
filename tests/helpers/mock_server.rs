use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing;

/// A simple HTTP/1.1 mock server that handles keep-alive connections.
pub struct MockHttpServer {
    listener: TcpListener,
    port: u16,
}

impl MockHttpServer {
    /// Create a new mock server bound to a random port.
    pub async fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    /// Get the port the server is listening on.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the base URL for this server.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Start the server in a background task.
    /// The server will handle keep-alive connections and process multiple requests on the same socket.
    #[allow(dead_code)]
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match self.listener.accept().await {
                    Ok((stream, _)) => {
                        // Spawn a task to handle each connection
                        tokio::spawn(handle_connection(stream));
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                        break;
                    }
                }
            }
        })
    }

    /// Start the server and handle a specific number of requests, then shutdown.
    pub fn start_with_request_limit(self, max_requests: usize) -> tokio::task::JoinHandle<()> {
        let listener = self.listener;
        tokio::spawn(async move {
            // Use a shared counter to track total requests across all connections
            let request_count = Arc::new(tokio::sync::Mutex::new(0usize));

            loop {
                let count = *request_count.lock().await;
                if count >= max_requests {
                    break;
                }

                match listener.accept().await {
                    Ok((stream, _)) => {
                        let request_count_clone = Arc::clone(&request_count);
                        // Spawn a task to handle this connection
                        // Each connection can handle multiple requests
                        tokio::spawn(async move {
                            handle_connection_with_shared_counter(
                                stream,
                                request_count_clone,
                                max_requests,
                            )
                            .await;
                        });
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                        break;
                    }
                }
            }
        })
    }
}

/// Handle a single connection, processing multiple requests if keep-alive is enabled.
#[allow(dead_code)]
async fn handle_connection(mut stream: TcpStream) {
    loop {
        // Read request with timeout to detect connection close
        let mut buf = [0u8; 8192];
        let read_result = timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

        let n = match read_result {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                tracing::error!("Read error: {}", e);
                break;
            }
            Err(_) => {
                // Timeout - connection likely closed or idle
                break;
            }
        };

        if n == 0 {
            // Connection closed by client
            break;
        }

        // Parse request to check for Connection header
        let request_str = match std::str::from_utf8(&buf[..n]) {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!("Invalid UTF-8 in request");
                break;
            }
        };

        let keep_alive = request_str
            .lines()
            .find(|line| line.to_lowercase().starts_with("connection:"))
            .map(|line| line.to_lowercase().contains("keep-alive"))
            .unwrap_or(false);

        // Send response
        let response: &[u8] = if keep_alive {
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nHello"
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHello"
        };

        if let Err(_e) = stream.write_all(response).await {
            break;
        }

        if let Err(_e) = stream.flush().await {
            break;
        }

        // If Connection: close, break after this response
        if !keep_alive {
            break;
        }
    }
}

/// Handle a connection with a shared request counter.
async fn handle_connection_with_shared_counter(
    mut stream: TcpStream,
    request_count: Arc<tokio::sync::Mutex<usize>>,
    max_requests: usize,
) {
    loop {
        let mut buf = [0u8; 8192];
        let read_result = timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

        let n = match read_result {
            Ok(Ok(n)) => n,
            Ok(Err(_e)) => {
                break;
            }
            Err(_) => {
                break;
            }
        };

        if n == 0 {
            break;
        }

        // Increment request counter
        let should_close = {
            let mut count = request_count.lock().await;
            *count += 1;
            *count >= max_requests
        };

        let request_str = match std::str::from_utf8(&buf[..n]) {
            Ok(s) => s,
            Err(_) => break,
        };

        let keep_alive = request_str
            .lines()
            .find(|line| line.to_lowercase().starts_with("connection:"))
            .map(|line| line.to_lowercase().contains("keep-alive"))
            .unwrap_or(false);

        // Decide whether to close after this response
        let close_after = should_close || !keep_alive;

        let response: &[u8] = if close_after {
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHello"
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nHello"
        };

        if let Err(_e) = stream.write_all(response).await {
            break;
        }

        if let Err(_e) = stream.flush().await {
            break;
        }

        // Close after sending response if needed
        if close_after {
            break;
        }
    }
}

/// Handle a connection with a request limit.
#[allow(dead_code)]
async fn handle_connection_with_limit(mut stream: TcpStream, max_requests: usize) {
    let mut request_count = 0;
    loop {
        if request_count >= max_requests {
            break;
        }

        let mut buf = [0u8; 8192];
        let read_result = timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

        let n = match read_result {
            Ok(Ok(n)) => n,
            Ok(Err(_e)) => {
                break;
            }
            Err(_) => {
                break;
            }
        };

        if n == 0 {
            break;
        }

        request_count += 1;

        let request_str = match std::str::from_utf8(&buf[..n]) {
            Ok(s) => s,
            Err(_) => break,
        };

        let keep_alive = request_str
            .lines()
            .find(|line| line.to_lowercase().starts_with("connection:"))
            .map(|line| line.to_lowercase().contains("keep-alive"))
            .unwrap_or(false);

        let response: &[u8] = if keep_alive {
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nHello"
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHello"
        };

        if let Err(_e) = stream.write_all(response).await {
            break;
        }

        if let Err(_e) = stream.flush().await {
            break;
        }

        if !keep_alive {
            break;
        }
    }
}
