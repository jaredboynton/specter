//! HTTP response handling with explicit decompression.

use crate::error::{Error, Result};
use crate::headers::Headers;
use bytes::Bytes;
use http::StatusCode;
use std::io::Read;
use url::Url;

/// HTTP response with explicit decompression.
#[derive(Debug, Clone)]
pub struct Response {
    pub(crate) status: u16,
    headers: Headers,
    body: Bytes,
    http_version: String,
    effective_url: Option<Url>,
}

impl Response {
    pub fn new(status: u16, headers: Headers, body: Bytes, http_version: String) -> Self {
        Self {
            status,
            headers,
            body,
            http_version,
            effective_url: None,
        }
    }

    /// Set the effective URL (the URL that was actually requested).
    /// This is used by the redirect engine to track the current URL.
    pub fn with_url(mut self, url: Url) -> Self {
        self.effective_url = Some(url);
        self
    }

    pub fn http_version(&self) -> &str {
        &self.http_version
    }

    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub fn status_code(&self) -> u16 {
        self.status
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn url(&self) -> Option<&Url> {
        self.effective_url.as_ref()
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    pub fn bytes_raw(&self) -> Bytes {
        self.body.clone()
    }

    pub fn into_body(self) -> Bytes {
        self.body
    }

    pub fn bytes(&self) -> Result<Bytes> {
        self.decoded_body()
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }
    pub fn redirect_url(&self) -> Option<&str> {
        self.get_header("Location")
    }

    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }

    pub fn get_headers(&self, name: &str) -> Vec<&str> {
        self.headers.get_all(name)
    }

    pub fn content_type(&self) -> Option<&str> {
        self.get_header("Content-Type")
    }
    pub fn content_encoding(&self) -> Option<&str> {
        self.get_header("Content-Encoding")
    }

    /// Decode body based on Content-Encoding (gzip, deflate, br, zstd).
    /// Supports chained encodings (e.g., "gzip, deflate") by applying decodings in reverse order.
    pub fn decoded_body(&self) -> Result<Bytes> {
        let encodings: Vec<&str> = self
            .content_encoding()
            .map(|s| s.split(',').map(str::trim).collect())
            .unwrap_or_default();

        // If Content-Encoding header is present, process encodings in reverse order
        // (last encoding applied first during decode)
        if !encodings.is_empty() {
            let mut data = self.body.clone();
            for encoding in encodings.iter().rev() {
                data = match encoding.to_lowercase().as_str() {
                    "gzip" | "x-gzip" => decode_gzip(&data)?,
                    "deflate" => decode_deflate(&data)?,
                    "br" => decode_brotli(&data)?,
                    "zstd" => decode_zstd(&data)?,
                    "identity" => data,
                    _ => {
                        // Unknown encoding, pass through
                        data
                    }
                };
            }
            return Ok(data);
        }

        // No Content-Encoding header: check magic bytes
        if self.body.len() >= 4 {
            // zstd magic: 0x28 0xB5 0x2F 0xFD
            if self.body[0] == 0x28
                && self.body[1] == 0xB5
                && self.body[2] == 0x2F
                && self.body[3] == 0xFD
            {
                return decode_zstd(&self.body);
            }
        }
        if self.body.len() >= 2 {
            // gzip magic: 0x1f 0x8b
            if self.body[0] == 0x1f && self.body[1] == 0x8b {
                return decode_gzip(&self.body);
            }
        }

        Ok(self.body.clone())
    }

    pub fn text(&self) -> Result<String> {
        let decoded = self.decoded_body()?;
        String::from_utf8(decoded.to_vec())
            .map_err(|e| Error::Decompression(format!("UTF-8 decode error: {}", e)))
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let text = self.text()?;
        serde_json::from_str(&text).map_err(Error::from)
    }

    pub fn error_for_status(self) -> Result<Self> {
        if self.status().is_client_error() || self.status().is_server_error() {
            let message = self
                .status()
                .canonical_reason()
                .unwrap_or("HTTP error")
                .to_string();
            Err(Error::http_status(self.status, message))
        } else {
            Ok(self)
        }
    }

    pub fn error_for_status_ref(&self) -> Result<&Self> {
        if self.status().is_client_error() || self.status().is_server_error() {
            let message = self
                .status()
                .canonical_reason()
                .unwrap_or("HTTP error")
                .to_string();
            Err(Error::http_status(self.status, message))
        } else {
            Ok(self)
        }
    }
}

fn decode_gzip(data: &[u8]) -> Result<Bytes> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Decompression(format!("gzip: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_deflate(data: &[u8]) -> Result<Bytes> {
    let mut decoded = Vec::new();
    if flate2::read::ZlibDecoder::new(data)
        .read_to_end(&mut decoded)
        .is_ok()
    {
        return Ok(Bytes::from(decoded));
    }
    decoded.clear();
    flate2::read::DeflateDecoder::new(data)
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Decompression(format!("deflate: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_brotli(data: &[u8]) -> Result<Bytes> {
    let mut decoder = brotli::Decompressor::new(data, 4096);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Decompression(format!("brotli: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_zstd(data: &[u8]) -> Result<Bytes> {
    zstd::stream::decode_all(data)
        .map(Bytes::from)
        .map_err(|e| Error::Decompression(format!("zstd: {}", e)))
}
