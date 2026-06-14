use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

use crate::url::Url;

use super::{WebSocketError, WebSocketResult};

const PMD_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WebSocketExtensions {
    pub(crate) permessage_deflate: Option<PermessageDeflateConfig>,
}

impl WebSocketExtensions {
    pub(crate) fn none() -> Self {
        Self::default()
    }

    pub(crate) fn permessage_deflate(config: PermessageDeflateConfig) -> Self {
        Self {
            permessage_deflate: Some(config),
        }
    }

    pub(crate) fn has_permessage_deflate(self) -> bool {
        self.permessage_deflate.is_some()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PermessageDeflateConfig {
    pub(crate) client_no_context_takeover: bool,
    pub(crate) server_no_context_takeover: bool,
}

impl PermessageDeflateConfig {
    pub(crate) const OFFER_HEADER: &'static str =
        "permessage-deflate; client_no_context_takeover; server_no_context_takeover";
}

#[derive(Debug)]
pub(crate) struct PermessageDeflateEncoder {
    config: PermessageDeflateConfig,
    inner: Compress,
}

impl PermessageDeflateEncoder {
    pub(crate) fn new(config: PermessageDeflateConfig) -> Self {
        Self {
            config,
            inner: Compress::new(Compression::fast(), false),
        }
    }

    pub(crate) fn compress(&mut self, url: &Url, payload: &[u8]) -> WebSocketResult<Vec<u8>> {
        let mut out = Vec::with_capacity(payload.len().saturating_div(2).max(32));
        let status = self
            .inner
            .compress_vec(payload, &mut out, FlushCompress::Sync)
            .map_err(|err| {
                WebSocketError::protocol(url, format!("permessage-deflate compress failed: {err}"))
            })?;
        if !matches!(status, Status::Ok) {
            return Err(WebSocketError::protocol(
                url,
                format!("permessage-deflate compress ended unexpectedly: {status:?}"),
            ));
        }
        if out.ends_with(&PMD_TAIL) {
            out.truncate(out.len() - PMD_TAIL.len());
        }
        if self.config.client_no_context_takeover {
            self.inner = Compress::new(Compression::fast(), false);
        }
        Ok(out)
    }
}

#[derive(Debug)]
pub(crate) struct PermessageDeflateDecoder {
    config: PermessageDeflateConfig,
    inner: Decompress,
}

impl PermessageDeflateDecoder {
    pub(crate) fn new(config: PermessageDeflateConfig) -> Self {
        Self {
            config,
            inner: Decompress::new(false),
        }
    }

    pub(crate) fn decompress(&mut self, url: &Url, payload: &[u8]) -> WebSocketResult<Vec<u8>> {
        let mut input = Vec::with_capacity(payload.len() + PMD_TAIL.len());
        input.extend_from_slice(payload);
        input.extend_from_slice(&PMD_TAIL);
        let mut out = Vec::with_capacity(payload.len().saturating_mul(2).max(32));
        let status = self
            .inner
            .decompress_vec(&input, &mut out, FlushDecompress::Sync)
            .map_err(|err| {
                WebSocketError::protocol(
                    url,
                    format!("permessage-deflate decompress failed: {err}"),
                )
            })?;
        if !matches!(status, Status::Ok | Status::StreamEnd) {
            return Err(WebSocketError::protocol(
                url,
                format!("permessage-deflate decompress ended unexpectedly: {status:?}"),
            ));
        }
        if self.config.server_no_context_takeover {
            self.inner = Decompress::new(false);
        }
        Ok(out)
    }
}

pub(crate) fn parse_permessage_deflate_response(
    url: &Url,
    value: &str,
) -> WebSocketResult<Option<PermessageDeflateConfig>> {
    let mut matched = None;
    for offer in value.split(',') {
        let mut parts = offer
            .split(';')
            .map(str::trim)
            .filter(|part| !part.is_empty());
        let Some(name) = parts.next() else {
            continue;
        };
        if !name.eq_ignore_ascii_case("permessage-deflate") {
            return Err(WebSocketError::UnexpectedExtension {
                url: url.to_string(),
            });
        }
        if matched.is_some() {
            return Err(WebSocketError::protocol(
                url,
                "duplicate permessage-deflate extension response",
            ));
        }
        let mut config = PermessageDeflateConfig::default();
        for param in parts {
            let key = param
                .split_once('=')
                .map(|(key, _)| key.trim())
                .unwrap_or(param)
                .trim();
            match key.to_ascii_lowercase().as_str() {
                "client_no_context_takeover" => config.client_no_context_takeover = true,
                "server_no_context_takeover" => config.server_no_context_takeover = true,
                "client_max_window_bits" | "server_max_window_bits" => {
                    return Err(WebSocketError::protocol(
                        url,
                        "permessage-deflate max_window_bits parameters are not supported",
                    ));
                }
                _ => {
                    return Err(WebSocketError::protocol(
                        url,
                        format!("unsupported permessage-deflate parameter {key}"),
                    ));
                }
            }
        }
        matched = Some(config);
    }
    Ok(matched)
}
