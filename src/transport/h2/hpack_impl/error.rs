//! HPACK-specific error types.

use thiserror::Error;

/// HPACK encoding/decoding errors.
#[derive(Debug, Error)]
pub enum HpackError {
    #[error("Unexpected end of input")]
    UnexpectedEof,

    #[error("Invalid prefix size")]
    InvalidPrefixSize,

    #[error("Integer overflow")]
    IntegerOverflow,

    #[error("Invalid Huffman code")]
    InvalidHuffmanCode,

    #[error("Invalid index: {0}")]
    InvalidIndex(usize),

    #[error("Decode error: {0}")]
    Decode(String),
}

impl From<HpackError> for String {
    fn from(e: HpackError) -> Self {
        e.to_string()
    }
}
