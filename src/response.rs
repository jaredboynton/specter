//! HTTP response handling with explicit decompression.

use std::io::Read;
use bytes::Bytes;
use crate::error::{Error, Result};

/// HTTP response with explicit decompression.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<String>,
    body: Bytes,
    http_version: String,
    pub effective_url: Option<String>,
}

impl Response {
    pub fn new(status: u16, headers: Vec<String>, body: Bytes, http_version: String) -> Self {
        Self { status, headers, body, http_version, effective_url: None }
    }

    /// Set the effective URL (the URL that was actually requested).
    /// This is used by the redirect engine to track the current URL.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.effective_url = Some(url.into());
        self
    }

    pub fn http_version(&self) -> &str { &self.http_version }
    pub fn body(&self) -> &Bytes { &self.body }
    pub fn into_body(self) -> Bytes { self.body }
    pub fn is_success(&self) -> bool { (200..300).contains(&self.status) }
    pub fn is_redirect(&self) -> bool { (300..400).contains(&self.status) }
    pub fn redirect_url(&self) -> Option<&str> { self.get_header("Location") }

    pub fn get_header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        for header in &self.headers {
            if let Some((key, value)) = header.split_once(':') {
                if key.trim().to_lowercase() == name_lower {
                    return Some(value.trim());
                }
            }
        }
        None
    }

    pub fn get_headers(&self, name: &str) -> Vec<&str> {
        let name_lower = name.to_lowercase();
        self.headers.iter().filter_map(|h| {
            let (key, value) = h.split_once(':')?;
            if key.trim().to_lowercase() == name_lower { Some(value.trim()) } else { None }
        }).collect()
    }

    pub fn content_type(&self) -> Option<&str> { self.get_header("Content-Type") }
    pub fn content_encoding(&self) -> Option<&str> { self.get_header("Content-Encoding") }

    /// Decode body based on Content-Encoding (gzip, deflate, br, zstd).
    pub fn decoded_body(&self) -> Result<Bytes> {
        match self.content_encoding().map(|s| s.to_lowercase()).as_deref() {
            Some("gzip") | Some("x-gzip") => decode_gzip(&self.body),
            Some("deflate") => decode_deflate(&self.body),
            Some("br") => decode_brotli(&self.body),
            Some("zstd") => decode_zstd(&self.body),
            _ => {
                // Check magic bytes when Content-Encoding is missing
                if self.body.len() >= 4 {
                    // zstd magic: 0x28 0xB5 0x2F 0xFD
                    if self.body[0] == 0x28 && self.body[1] == 0xB5 && self.body[2] == 0x2F && self.body[3] == 0xFD {
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
        }
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
}

fn decode_gzip(data: &[u8]) -> Result<Bytes> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).map_err(|e| Error::Decompression(format!("gzip: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_deflate(data: &[u8]) -> Result<Bytes> {
    let mut decoded = Vec::new();
    if flate2::read::ZlibDecoder::new(data).read_to_end(&mut decoded).is_ok() {
        return Ok(Bytes::from(decoded));
    }
    decoded.clear();
    flate2::read::DeflateDecoder::new(data).read_to_end(&mut decoded)
        .map_err(|e| Error::Decompression(format!("deflate: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_brotli(data: &[u8]) -> Result<Bytes> {
    let mut decoder = brotli::Decompressor::new(data, 4096);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).map_err(|e| Error::Decompression(format!("brotli: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_zstd(data: &[u8]) -> Result<Bytes> {
    zstd::stream::decode_all(data)
        .map(Bytes::from)
        .map_err(|e| Error::Decompression(format!("zstd: {}", e)))
}
