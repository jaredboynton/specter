//! HPACK decoder (RFC 7541).

use super::dynamic_table::DynamicTable;
use super::error::HpackError;
use super::huffman::huffman_decode;
use super::integer::decode_integer;
use super::static_table::get_static_entry;

const STATIC_TABLE_SIZE: usize = 61;

/// HPACK decoder.
pub struct Decoder {
    dynamic_table: DynamicTable,
}

impl Decoder {
    /// Create a new decoder.
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(4096),
        }
    }

    /// Set the maximum dynamic table size.
    pub fn set_max_table_size(&mut self, size: usize) {
        self.dynamic_table.set_max_size(size);
    }

    /// Decode a header block using a callback.
    ///
    /// The callback is invoked for each decoded header field with (name, value).
    pub fn decode_with_cb<F>(&mut self, data: &[u8], mut cb: F) -> Result<(), HpackError>
    where
        F: FnMut(&[u8], &[u8]),
    {
        let mut pos = 0;

        while pos < data.len() {
            let byte = data[pos];

            // Check for dynamic table size update (RFC 7541 Section 6.3)
            // Prefix: 001xxxxx (3-bit pattern)
            if (byte & 0xE0) == 0x20 {
                let (size, consumed) = decode_integer(&data[pos..], 5, 0x1F)?;
                self.dynamic_table.set_max_size(size);
                pos += consumed + 1;
                continue;
            }

            // Indexed header field representation (RFC 7541 Section 6.1)
            // Prefix: 1xxxxxxx
            if (byte & 0x80) != 0 {
                let (index, consumed) = decode_integer(&data[pos..], 7, 0x7F)?;
                pos += consumed + 1;

                let (name, value) = self.get_entry(index)?;
                cb(name, value);
                continue;
            }

            // Literal header field with incremental indexing (RFC 7541 Section 6.2.1)
            // Prefix: 01xxxxxx
            if (byte & 0xC0) == 0x40 {
                let (name_idx, consumed) = decode_integer(&data[pos..], 6, 0x3F)?;
                pos += consumed + 1;

                let name = if name_idx == 0 {
                    // New name
                    let (name_bytes, name_consumed) = self.decode_string_literal(&data[pos..])?;
                    pos += name_consumed;
                    name_bytes
                } else {
                    // Indexed name
                    let (name_bytes, _) = self.get_entry(name_idx)?;
                    name_bytes.to_vec()
                };

                let (value_bytes, value_consumed) = self.decode_string_literal(&data[pos..])?;
                pos += value_consumed;

                cb(&name, &value_bytes);

                // Add to dynamic table
                self.dynamic_table.add(name, value_bytes);
                continue;
            }

            // Literal header field without indexing (RFC 7541 Section 6.2.2)
            // Prefix: 0000xxxx
            if (byte & 0xF0) == 0x00 {
                let (name_idx, consumed) = decode_integer(&data[pos..], 4, 0x0F)?;
                pos += consumed + 1;

                let name = if name_idx == 0 {
                    let (name_bytes, name_consumed) = self.decode_string_literal(&data[pos..])?;
                    pos += name_consumed;
                    name_bytes
                } else {
                    let (name_bytes, _) = self.get_entry(name_idx)?;
                    name_bytes.to_vec()
                };

                let (value_bytes, value_consumed) = self.decode_string_literal(&data[pos..])?;
                pos += value_consumed;

                cb(&name, &value_bytes);
                continue;
            }

            // Literal header field never indexed (RFC 7541 Section 6.2.3)
            // Prefix: 0001xxxx
            if (byte & 0xF0) == 0x10 {
                let (name_idx, consumed) = decode_integer(&data[pos..], 4, 0x0F)?;
                pos += consumed + 1;

                let name = if name_idx == 0 {
                    let (name_bytes, name_consumed) = self.decode_string_literal(&data[pos..])?;
                    pos += name_consumed;
                    name_bytes
                } else {
                    let (name_bytes, _) = self.get_entry(name_idx)?;
                    name_bytes.to_vec()
                };

                let (value_bytes, value_consumed) = self.decode_string_literal(&data[pos..])?;
                pos += value_consumed;

                cb(&name, &value_bytes);
                continue;
            }

            return Err(HpackError::Decode(format!(
                "Invalid header field representation: 0x{:02x}",
                byte
            )));
        }

        Ok(())
    }

    /// Get an entry from either static or dynamic table by combined index.
    fn get_entry(&self, index: usize) -> Result<(&[u8], &[u8]), HpackError> {
        if index == 0 {
            return Err(HpackError::InvalidIndex(0));
        }

        if index <= STATIC_TABLE_SIZE {
            // Static table entry
            get_static_entry(index).ok_or(HpackError::InvalidIndex(index))
        } else {
            // Dynamic table entry
            let dynamic_idx = index - STATIC_TABLE_SIZE;
            self.dynamic_table
                .get(dynamic_idx)
                .map(|e| (e.name(), e.value()))
                .ok_or(HpackError::InvalidIndex(index))
        }
    }

    /// Decode a string literal (RFC 7541 Section 5.2).
    fn decode_string_literal(&self, data: &[u8]) -> Result<(Vec<u8>, usize), HpackError> {
        if data.is_empty() {
            return Err(HpackError::UnexpectedEof);
        }

        let h_flag = (data[0] & 0x80) != 0;
        let (length, length_consumed) = decode_integer(data, 7, 0x7F)?;

        let data_start = length_consumed + 1;
        if data_start + length > data.len() {
            return Err(HpackError::UnexpectedEof);
        }

        let string_data = &data[data_start..data_start + length];

        let decoded = if h_flag {
            // Huffman encoded
            huffman_decode(string_data)?
        } else {
            // Literal
            string_data.to_vec()
        };

        Ok((decoded, data_start + length))
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::h2::hpack_impl::encoder::Encoder;

    #[test]
    fn test_decode_indexed_header() {
        let mut decoder = Decoder::new();
        // Encode index 2 (:method GET) = 0x82
        let data = [0x82];
        let mut headers = Vec::new();
        decoder
            .decode_with_cb(&data, |name, value| {
                headers.push((name.to_vec(), value.to_vec()));
            })
            .unwrap();

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, b":method");
        assert_eq!(headers[0].1, b"GET");
    }

    #[test]
    fn test_decode_literal() {
        let mut encoder = Encoder::new();
        let headers = [(b"custom-key".as_slice(), b"custom-value".as_slice())];
        let encoded = encoder.encode(&headers);

        let mut decoder = Decoder::new();
        let mut headers = Vec::new();
        decoder
            .decode_with_cb(&encoded, |name, value| {
                headers.push((name.to_vec(), value.to_vec()));
            })
            .unwrap();

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, b"custom-key");
        assert_eq!(headers[0].1, b"custom-value");
    }

    #[test]
    fn test_round_trip() {
        let headers = [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"http".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
            (b":authority".as_slice(), b"www.example.com".as_slice()),
        ];

        let mut encoder = Encoder::new();
        let encoded = encoder.encode(&headers);

        let mut decoder = Decoder::new();
        let mut decoded = Vec::new();
        decoder
            .decode_with_cb(&encoded, |name, value| {
                decoded.push((name.to_vec(), value.to_vec()));
            })
            .unwrap();

        assert_eq!(decoded.len(), 4);
        assert_eq!(decoded[0].0, b":method");
        assert_eq!(decoded[0].1, b"GET");
    }
}
