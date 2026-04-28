use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::proxy::ProxyAuth;

/// Maximum response header size (8 KB) to prevent abuse.
const MAX_HEADER_SIZE: usize = 8192;

/// Establishes an HTTP CONNECT tunnel through a proxy.
///
/// On success, the returned `TcpStream` is connected end-to-end to
/// `target_host:target_port` — all further I/O goes straight to the target.
pub(crate) async fn http_connect(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    auth: Option<&ProxyAuth>,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect((proxy_host, proxy_port))
        .await
        .map_err(|e| {
            Error::connection(format!(
                "failed to connect to proxy {proxy_host}:{proxy_port}: {e}"
            ))
        })?;

    // Build CONNECT request.
    let mut request = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let Some(auth) = auth {
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", auth.username, auth.password));
        request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
    }
    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| Error::connection(format!("failed to send CONNECT request: {e}")))?;

    // Read response headers until \r\n\r\n.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| Error::connection(format!("failed to read proxy response: {e}")))?;

        if n == 0 {
            return Err(Error::connection(
                "proxy closed connection before completing CONNECT handshake",
            ));
        }

        buf.extend_from_slice(&tmp[..n]);

        if buf.len() > MAX_HEADER_SIZE {
            return Err(Error::connection(
                "proxy response headers exceeded 8 KB limit",
            ));
        }

        // Check for end-of-headers marker.
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // Parse status line: HTTP/1.x STATUS_CODE REASON\r\n
    let header_str = String::from_utf8_lossy(&buf);
    let status_line = header_str
        .lines()
        .next()
        .ok_or_else(|| Error::connection("empty response from proxy"))?;

    let status_code = parse_status_code(status_line)?;

    if status_code != 200 {
        return Err(Error::connection(format!(
            "proxy CONNECT failed: {status_line}"
        )));
    }

    Ok(stream)
}

/// Extracts the numeric status code from an HTTP status line.
///
/// Accepts both `HTTP/1.0` and `HTTP/1.1` prefixes.
fn parse_status_code(status_line: &str) -> Result<u16> {
    // Expected: "HTTP/1.x <code> <reason>"
    let mut parts = status_line.split_whitespace();

    let version = parts
        .next()
        .ok_or_else(|| Error::connection("malformed proxy status line: missing version"))?;

    if !version.starts_with("HTTP/") {
        return Err(Error::connection(format!(
            "malformed proxy status line: unexpected version '{version}'"
        )));
    }

    let code_str = parts
        .next()
        .ok_or_else(|| Error::connection("malformed proxy status line: missing status code"))?;

    code_str.parse::<u16>().map_err(|_| {
        Error::connection(format!(
            "malformed proxy status line: invalid status code '{code_str}'"
        ))
    })
}
