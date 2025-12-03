//! HPACK encoder (RFC 7541).

use super::dynamic_table::DynamicTable;
use super::huffman::huffman_encode_if_smaller;
use super::integer::encode_integer;
use super::static_table::{find_static_entry, find_static_entry_by_name};

const STATIC_TABLE_SIZE: usize = 61;

/// HPACK encoder.
pub struct Encoder {
    dynamic_table: DynamicTable,
}

impl Encoder {
    /// Create a new encoder.
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(4096),
        }
    }

    /// Set the maximum dynamic table size.
    pub fn set_max_table_size(&mut self, size: usize) {
        self.dynamic_table.set_max_size(size);
    }

    /// Encode a list of headers.
    ///
    /// Headers should be provided as a slice of (name, value) byte slices.
    pub fn encode(&mut self, headers: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut output = Vec::new();

        for (name, value) in headers {
            self.encode_header(name, value, &mut output);
        }

        output
    }

    /// Encode a single header field.
    fn encode_header(&mut self, name: &[u8], value: &[u8], output: &mut Vec<u8>) {
        // Try to find exact match (name + value) in static table
        if let Some(static_idx) = find_static_entry(name, value) {
            // Indexed header field representation (RFC 7541 Section 6.1)
            // Prefix: 1xxxxxxx (7-bit index)
            // Always push a new byte for this header
            output.push(0x80); // Set top bit
            encode_integer(static_idx, 7, 0x7F, output).unwrap();
            return;
        }

        // Try to find exact match in dynamic table
        if let Some(dynamic_idx) = self.dynamic_table.find(name, value) {
            let combined_idx = STATIC_TABLE_SIZE + dynamic_idx;
            // Indexed header field representation
            // Always push a new byte for this header
            output.push(0x80);
            encode_integer(combined_idx, 7, 0x7F, output).unwrap();
            return;
        }

        // Try to find name match in static table
        if let Some(static_name_idx) = find_static_entry_by_name(name) {
            // Literal header field with incremental indexing (RFC 7541 Section 6.2.1)
            // Prefix: 01xxxxxx (6-bit index)
            // Always push a new byte for this header
            output.push(0x40); // Set top 2 bits to 01
            encode_integer(static_name_idx, 6, 0x3F, output).unwrap();
            self.encode_string_literal(value, output);

            // Add to dynamic table
            self.dynamic_table.add(name.to_vec(), value.to_vec());
            return;
        }

        // Try to find name match in dynamic table
        if let Some(dynamic_name_idx) = self.dynamic_table.find_by_name(name) {
            let combined_name_idx = STATIC_TABLE_SIZE + dynamic_name_idx;
            // Literal header field with incremental indexing
            // Always push a new byte for this header
            output.push(0x40);
            encode_integer(combined_name_idx, 6, 0x3F, output).unwrap();
            self.encode_string_literal(value, output);

            // Add to dynamic table
            self.dynamic_table.add(name.to_vec(), value.to_vec());
            return;
        }

        // New name: literal header field with incremental indexing
        // Prefix: 01xxxxxx, index = 0 means new name
        // Always push a new byte for this header
        output.push(0x40);
        encode_integer(0, 6, 0x3F, output).unwrap();
        self.encode_string_literal(name, output);
        self.encode_string_literal(value, output);

        // Add to dynamic table
        self.dynamic_table.add(name.to_vec(), value.to_vec());
    }

    /// Encode a string literal (RFC 7541 Section 5.2).
    fn encode_string_literal(&self, input: &[u8], output: &mut Vec<u8>) {
        let (encoded, use_huffman) = huffman_encode_if_smaller(input);

        // Write H flag and length (7-bit prefix)
        // Always start a new byte for the string literal header
        output.push(if use_huffman { 0x80 } else { 0x00 });
        encode_integer(encoded.len(), 7, 0x7F, output).unwrap();
        output.extend_from_slice(&encoded);
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_static_entry() {
        let mut encoder = Encoder::new();
        let headers = [(b":method".as_slice(), b"GET".as_slice())];
        let encoded = encoder.encode(&headers);
        // Should encode as indexed header (index 2)
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0] & 0x80, 0x80); // Top bit set
    }

    #[test]
    fn test_encode_literal() {
        let mut encoder = Encoder::new();
        let headers = [(b"custom-key".as_slice(), b"custom-value".as_slice())];
        let encoded = encoder.encode(&headers);
        // Should encode as literal with incremental indexing
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0] & 0xC0, 0x40); // Top 2 bits: 01
    }

    #[test]
    fn test_encode_multiple_headers() {
        let mut encoder = Encoder::new();
        let headers = [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"http".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
        ];
        let encoded = encoder.encode(&headers);
        assert!(!encoded.is_empty());
    }
}
