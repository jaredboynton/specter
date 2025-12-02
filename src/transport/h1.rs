//! Minimal HTTP/1.1 client implementation.
//!
//! Uses httparse for response parsing and raw I/O for maximum control
//! over request formatting and header order.

use bytes::Bytes;
use http::{Method, Uri};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::response::Response;
use crate::transport::connector::MaybeHttpsStream;

/// Maximum response header size (64KB).
const MAX_HEADERS_SIZE: usize = 64 * 1024;

/// Maximum number of headers to parse.
const MAX_HEADERS_COUNT: usize = 100;

/// HTTP/1.1 connection for sending requests.
pub struct H1Connection {
    stream: MaybeHttpsStream,
}

impl H1Connection {
    /// Create a new HTTP/1.1 connection from an existing stream.
    pub fn new(stream: MaybeHttpsStream) -> Self {
        Self { stream }
    }

    /// Send an HTTP/1.1 request and receive the response.
    pub async fn send_request(
        &mut self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        // Build and send the request
        let request_bytes = self.build_request(&method, uri, &headers, body.as_ref())?;
        self.stream.write_all(&request_bytes).await
            .map_err(|e| Error::HttpProtocol(format!("Failed to write request: {}", e)))?;

        // Send body if present
        if let Some(body) = body {
            self.stream.write_all(&body).await
                .map_err(|e| Error::HttpProtocol(format!("Failed to write body: {}", e)))?;
        }

        self.stream.flush().await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush: {}", e)))?;

        // Read and parse the response
        self.read_response().await
    }

    /// Build the HTTP/1.1 request as bytes.
    fn build_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &[(String, String)],
        body: Option<&Bytes>,
    ) -> Result<Vec<u8>> {
        let mut request = Vec::with_capacity(1024);

        // Request line: METHOD /path HTTP/1.1\r\n
        let path = uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        request.extend_from_slice(method.as_str().as_bytes());
        request.push(b' ');
        request.extend_from_slice(path.as_bytes());
        request.extend_from_slice(b" HTTP/1.1\r\n");

        // Host header (required for HTTP/1.1)
        let host = uri.host().ok_or_else(|| Error::HttpProtocol("Missing host".into()))?;
        request.extend_from_slice(b"Host: ");
        request.extend_from_slice(host.as_bytes());
        if let Some(port) = uri.port() {
            request.push(b':');
            request.extend_from_slice(port.as_str().as_bytes());
        }
        request.extend_from_slice(b"\r\n");

        // User-provided headers (preserving order)
        for (name, value) in headers {
            // Skip Host header if user provided one (we already added it)
            if name.eq_ignore_ascii_case("host") {
                continue;
            }
            request.extend_from_slice(name.as_bytes());
            request.extend_from_slice(b": ");
            request.extend_from_slice(value.as_bytes());
            request.extend_from_slice(b"\r\n");
        }

        // Content-Length if body present and not already set
        if let Some(body) = body {
            let has_content_length = headers.iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
            if !has_content_length {
                request.extend_from_slice(b"Content-Length: ");
                request.extend_from_slice(body.len().to_string().as_bytes());
                request.extend_from_slice(b"\r\n");
            }
        }

        // End of headers
        request.extend_from_slice(b"\r\n");

        Ok(request)
    }

    /// Read and parse an HTTP/1.1 response.
    async fn read_response(&mut self) -> Result<Response> {
        let mut buffer = vec![0u8; MAX_HEADERS_SIZE];
        let mut total_read = 0;

        // Read until we find the end of headers (\r\n\r\n)
        loop {
            if total_read >= MAX_HEADERS_SIZE {
                return Err(Error::HttpProtocol("Response headers too large".into()));
            }

            let n = self.stream.read(&mut buffer[total_read..]).await
                .map_err(|e| Error::HttpProtocol(format!("Failed to read response: {}", e)))?;

            if n == 0 {
                return Err(Error::HttpProtocol("Connection closed before response complete".into()));
            }

            total_read += n;

            // Check if we have the complete headers
            if let Some(header_end) = find_header_end(&buffer[..total_read]) {
                return self.parse_response(&buffer[..total_read], header_end).await;
            }
        }
    }

    /// Parse the response headers and body.
    async fn parse_response(&mut self, buffer: &[u8], _header_end: usize) -> Result<Response> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS_COUNT];
        let mut response = httparse::Response::new(&mut headers);

        let parsed = response.parse(buffer)
            .map_err(|e| Error::HttpProtocol(format!("Failed to parse response: {}", e)))?;

        let headers_len = match parsed {
            httparse::Status::Complete(len) => len,
            httparse::Status::Partial => {
                return Err(Error::HttpProtocol("Incomplete response headers".into()));
            }
        };

        let status = response.code.ok_or_else(|| Error::HttpProtocol("Missing status code".into()))?;
        let version = format!("HTTP/1.{}", response.version.unwrap_or(1));

        // Collect headers
        let response_headers: Vec<String> = response.headers.iter()
            .filter(|h| !h.name.is_empty())
            .map(|h| {
                format!("{}: {}", h.name, String::from_utf8_lossy(h.value))
            })
            .collect();

        // Determine body handling from headers
        let content_length = find_header_value(&response_headers, "content-length")
            .and_then(|v| v.parse::<usize>().ok());
        let transfer_encoding = find_header_value(&response_headers, "transfer-encoding");
        let is_chunked = transfer_encoding.map(|v| v.contains("chunked")).unwrap_or(false);

        // Read body
        let body_start = &buffer[headers_len..];
        let body = if is_chunked {
            self.read_chunked_body(body_start.to_vec()).await?
        } else if let Some(len) = content_length {
            self.read_fixed_body(body_start, len).await?
        } else {
            // No Content-Length and not chunked - might be empty or connection-close
            Bytes::from(body_start.to_vec())
        };

        Ok(Response::new(status, response_headers, body, version))
    }

    /// Read a fixed-length body.
    async fn read_fixed_body(&mut self, initial: &[u8], content_length: usize) -> Result<Bytes> {
        let mut body = Vec::with_capacity(content_length);
        body.extend_from_slice(initial);

        while body.len() < content_length {
            let mut chunk = vec![0u8; content_length - body.len()];
            let n = self.stream.read(&mut chunk).await
                .map_err(|e| Error::HttpProtocol(format!("Failed to read body: {}", e)))?;

            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }

        Ok(Bytes::from(body))
    }

    /// Read a chunked transfer-encoded body.
    async fn read_chunked_body(&mut self, initial: Vec<u8>) -> Result<Bytes> {
        let mut body = Vec::new();
        let mut buffer = initial;
        let mut read_buf = vec![0u8; 8192];

        loop {
            // Find chunk size line
            let (chunk_size, line_end) = match find_chunk_size(&buffer) {
                Some((size, end)) => (size, end),
                None => {
                    // Need more data
                    let n = self.stream.read(&mut read_buf).await
                        .map_err(|e| Error::HttpProtocol(format!("Failed to read chunk: {}", e)))?;
                    if n == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&read_buf[..n]);
                    continue;
                }
            };

            // Remove the size line from buffer
            buffer = buffer[line_end..].to_vec();

            // Zero size indicates end
            if chunk_size == 0 {
                break;
            }

            // Read chunk data + CRLF
            let chunk_end = chunk_size + 2; // data + \r\n
            while buffer.len() < chunk_end {
                let n = self.stream.read(&mut read_buf).await
                    .map_err(|e| Error::HttpProtocol(format!("Failed to read chunk data: {}", e)))?;
                if n == 0 {
                    break;
                }
                buffer.extend_from_slice(&read_buf[..n]);
            }

            // Append chunk data (without trailing CRLF)
            body.extend_from_slice(&buffer[..chunk_size.min(buffer.len())]);
            if buffer.len() > chunk_end {
                buffer = buffer[chunk_end..].to_vec();
            } else {
                buffer.clear();
            }
        }

        Ok(Bytes::from(body))
    }
}

/// Find the end of HTTP headers (\r\n\r\n).
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    for i in 0..buffer.len().saturating_sub(3) {
        if &buffer[i..i+4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Find a header value by name (case-insensitive).
fn find_header_value<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    for header in headers {
        if let Some((hname, hvalue)) = header.split_once(": ") {
            if hname.eq_ignore_ascii_case(name) {
                return Some(hvalue);
            }
        }
    }
    None
}

/// Parse a chunk size from the buffer, returning (size, end_of_line_position).
fn find_chunk_size(buffer: &[u8]) -> Option<(usize, usize)> {
    // Find CRLF
    for i in 0..buffer.len().saturating_sub(1) {
        if &buffer[i..i+2] == b"\r\n" {
            // Parse hex size (may have chunk extensions after ;)
            let line = &buffer[..i];
            let size_str = String::from_utf8_lossy(line);
            let size_part = size_str.split(';').next()?;
            let size = usize::from_str_radix(size_part.trim(), 16).ok()?;
            return Some((size, i + 2));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_header_end() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(find_header_end(data), Some(38));

        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        assert_eq!(find_header_end(partial), None);
    }

    #[test]
    fn test_find_chunk_size() {
        assert_eq!(find_chunk_size(b"5\r\nhello"), Some((5, 3)));
        assert_eq!(find_chunk_size(b"a\r\n0123456789"), Some((10, 3)));
        assert_eq!(find_chunk_size(b"0\r\n"), Some((0, 3)));
        // "5;ext=val\r\n" is 11 bytes (indices 0-10), so position after \r\n is 11
        assert_eq!(find_chunk_size(b"5;ext=val\r\ndata"), Some((5, 11)));
    }

    #[test]
    fn test_find_header_value() {
        let headers = vec![
            "Content-Type: text/html".to_string(),
            "Content-Length: 100".to_string(),
        ];
        assert_eq!(find_header_value(&headers, "content-type"), Some("text/html"));
        assert_eq!(find_header_value(&headers, "Content-Length"), Some("100"));
        assert_eq!(find_header_value(&headers, "missing"), None);
    }
}
