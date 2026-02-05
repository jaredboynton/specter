//! Request and body types with reqwest-like ergonomics.

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::version::HttpVersion;
use bytes::Bytes;
use http::Method;
use std::time::Duration;
use url::Url;

/// Convert common URL inputs into a `Url`.
pub trait IntoUrl {
    fn into_url(self) -> Result<Url>;
}

impl IntoUrl for Url {
    fn into_url(self) -> Result<Url> {
        Ok(self)
    }
}

impl IntoUrl for &Url {
    fn into_url(self) -> Result<Url> {
        Ok(self.clone())
    }
}

impl IntoUrl for &str {
    fn into_url(self) -> Result<Url> {
        Url::parse(self).map_err(Error::from)
    }
}

impl IntoUrl for String {
    fn into_url(self) -> Result<Url> {
        Url::parse(&self).map_err(Error::from)
    }
}

impl IntoUrl for http::Uri {
    fn into_url(self) -> Result<Url> {
        Url::parse(&self.to_string()).map_err(Error::from)
    }
}

impl IntoUrl for &http::Uri {
    fn into_url(self) -> Result<Url> {
        Url::parse(&self.to_string()).map_err(Error::from)
    }
}

/// Request body variants.
#[derive(Clone, Debug, Default)]
pub enum Body {
    #[default]
    Empty,
    Bytes(Bytes),
    Text(String),
    Json(Vec<u8>),
    Form(String),
    Raw(Vec<u8>),
}

impl Body {
    pub fn empty() -> Self {
        Body::Empty
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Body::Empty)
    }

    pub fn into_bytes(self) -> Result<Bytes> {
        Ok(match self {
            Body::Empty => Bytes::new(),
            Body::Bytes(bytes) => bytes,
            Body::Text(text) => Bytes::from(text.into_bytes()),
            Body::Json(bytes) => Bytes::from(bytes),
            Body::Form(text) => Bytes::from(text.into_bytes()),
            Body::Raw(bytes) => Bytes::from(bytes),
        })
    }
}

impl From<Bytes> for Body {
    fn from(value: Bytes) -> Self {
        Body::Bytes(value)
    }
}

impl From<Vec<u8>> for Body {
    fn from(value: Vec<u8>) -> Self {
        Body::Raw(value)
    }
}

impl From<&[u8]> for Body {
    fn from(value: &[u8]) -> Self {
        Body::Raw(value.to_vec())
    }
}

impl From<String> for Body {
    fn from(value: String) -> Self {
        Body::Text(value)
    }
}

impl From<&str> for Body {
    fn from(value: &str) -> Self {
        Body::Text(value.to_string())
    }
}

/// High-level request object for execution.
#[derive(Clone, Debug)]
pub struct Request {
    pub(crate) method: Method,
    pub(crate) url: Url,
    pub(crate) headers: Headers,
    pub(crate) body: Body,
    pub(crate) version: Option<HttpVersion>,
    pub(crate) timeout: Option<Duration>,
}

impl Request {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Headers::new(),
            body: Body::Empty,
            version: None,
            timeout: None,
        }
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn version(&self) -> Option<HttpVersion> {
        self.version
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

/// Redirect policy for the client.
#[derive(Clone, Debug, Default)]
pub enum RedirectPolicy {
    #[default]
    None,
    Limited(u32),
}
