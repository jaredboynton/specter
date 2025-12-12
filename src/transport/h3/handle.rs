//! HTTP/3 connection handle - non-blocking interface for sending requests.
//!
//! The handle sends commands to a driver task and receives responses via channels.
//! Multiple handles can share the same driver, enabling true multiplexing.

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::error::{Error, Result};
use crate::response::Response;
use crate::transport::h3::driver::DriverCommand;

/// HTTP/3 connection handle for sending requests
#[derive(Clone)]
pub struct H3Handle {
    /// Channel for sending commands to the driver
    command_tx: mpsc::Sender<DriverCommand>,
}

impl H3Handle {
    /// Create a new handle with a command channel to the driver
    pub fn new(command_tx: mpsc::Sender<DriverCommand>) -> Self {
        Self { command_tx }
    }

    /// Send an HTTP/3 request and receive the response.
    /// This is non-blocking - it sends the request to the driver and awaits the response channel.
    /// The driver allocates stream IDs internally via quiche.
    pub async fn send_request(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        // Allocate a oneshot channel for the response
        let (response_tx, response_rx) = oneshot::channel();

        // Send command to driver
        let command = DriverCommand::SendRequest {
            method,
            uri: uri.clone(),
            headers,
            body,
            response_tx,
        };

        self.command_tx
            .send(command)
            .await
            .map_err(|_| Error::HttpProtocol("H3 Driver channel closed".into()))?;

        // Wait for response
        let stream_response = response_rx
            .await
            .map_err(|_| Error::HttpProtocol("H3 Response channel closed".into()))??;

        // Convert StreamResponse to Response
        Ok(Response::new(
            stream_response.status,
            stream_response
                .headers
                .iter()
                .map(|(n, v)| format!("{}: {}", n, v))
                .collect(),
            stream_response.body,
            "HTTP/3".to_string(),
        ))
    }
}
