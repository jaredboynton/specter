//! HPACK integer encoding (RFC 7541 Section 5.1).
//!
//! Integers are encoded with a variable-length prefix that can start
//! anywhere within an octet and always finishes at the end of an octet.

use super::error::HpackError;

/// Encode an integer with an N-bit prefix.
///
/// The integer is written to the buffer starting at the current bit position.
/// The prefix size N must be between 1 and 8 bits.
///
/// Returns the number of bytes written.
pub fn encode_integer(
    value: usize,
    prefix_bits: u8,
    prefix_mask: u8,
    buf: &mut Vec<u8>,
) -> Result<usize, HpackError> {
    if prefix_bits == 0 || prefix_bits > 8 {
        return Err(HpackError::InvalidPrefixSize);
    }

    let max_prefix_value = (1u16 << prefix_bits) - 1;

    if value < max_prefix_value as usize {
        // Value fits in prefix
        if buf.is_empty() {
            buf.push(0);
        }
        let last_idx = buf.len() - 1;
        buf[last_idx] = (buf[last_idx] & !prefix_mask) | (value as u8 & prefix_mask);
        Ok(0)
    } else {
        // Value exceeds prefix, need continuation bytes
        if buf.is_empty() {
            buf.push(0);
        }
        let last_idx = buf.len() - 1;
        // Set all prefix bits to 1
        buf[last_idx] = (buf[last_idx] & !prefix_mask) | prefix_mask;

        let mut remaining = value - max_prefix_value as usize;
        let mut bytes_written = 0;

        while remaining >= 128 {
            buf.push((remaining % 128 + 128) as u8);
            remaining /= 128;
            bytes_written += 1;
        }
        buf.push(remaining as u8);
        bytes_written += 1;

        Ok(bytes_written)
    }
}

/// Decode an integer with an N-bit prefix.
///
/// Reads from the buffer starting at the current bit position.
/// Returns (value, bytes_consumed).
pub fn decode_integer(
    data: &[u8],
    prefix_bits: u8,
    prefix_mask: u8,
) -> Result<(usize, usize), HpackError> {
    if data.is_empty() {
        return Err(HpackError::UnexpectedEof);
    }

    if prefix_bits == 0 || prefix_bits > 8 {
        return Err(HpackError::InvalidPrefixSize);
    }

    // Read prefix value
    let prefix_value = (data[0] & prefix_mask) as usize;
    let max_prefix_value = (1usize << prefix_bits) - 1;

    if prefix_value < max_prefix_value {
        // Value is entirely in prefix
        Ok((prefix_value, 0))
    } else {
        // Value continues in following bytes
        let mut value = max_prefix_value;
        let mut shift = 0;
        let mut pos = 1;

        loop {
            if pos >= data.len() {
                return Err(HpackError::UnexpectedEof);
            }

            let byte = data[pos];
            value += ((byte & 0x7F) as usize) << shift;
            shift += 7;
            pos += 1;

            if (byte & 0x80) == 0 {
                // Last byte
                break;
            }

            // Prevent overflow
            if shift > 28 {
                return Err(HpackError::IntegerOverflow);
            }
        }

        Ok((value, pos - 1))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_small_integer() {
        let mut buf = vec![0x00];
        encode_integer(10, 5, 0x1F, &mut buf).unwrap();
        assert_eq!(buf[0] & 0x1F, 10);
    }

    #[test]
    fn test_encode_large_integer() {
        let mut buf = vec![0x00];
        encode_integer(1337, 5, 0x1F, &mut buf).unwrap();
        // Prefix should be all 1s (31)
        assert_eq!(buf[0] & 0x1F, 0x1F);
        // Following bytes: 1337 - 31 = 1306
        // 1306 >= 128: 1306 % 128 = 26, 26 + 128 = 154 = 0x9A
        // 1306 / 128 = 10, 10 < 128: 10 = 0x0A
        assert_eq!(buf.len(), 3);
        assert_eq!(buf[1], 0x9A);
        assert_eq!(buf[2], 0x0A);
    }

    #[test]
    fn test_decode_small_integer() {
        let data = [0x0A];
        let (value, consumed) = decode_integer(&data, 5, 0x1F).unwrap();
        assert_eq!(value, 10);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn test_decode_large_integer() {
        // Encode 1337 with 5-bit prefix
        let mut buf = vec![0x00];
        encode_integer(1337, 5, 0x1F, &mut buf).unwrap();
        buf[0] |= 0xE0; // Set top 3 bits to test

        let (value, consumed) = decode_integer(&buf, 5, 0x1F).unwrap();
        assert_eq!(value, 1337);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_rfc_example_10() {
        // RFC 7541 C.1.1: Encoding 10 with 5-bit prefix
        let mut buf = vec![0x00];
        encode_integer(10, 5, 0x1F, &mut buf).unwrap();
        assert_eq!(buf[0] & 0x1F, 10);
    }

    #[test]
    fn test_rfc_example_1337() {
        // RFC 7541 C.1.2: Encoding 1337 with 5-bit prefix
        let mut buf = vec![0x00];
        encode_integer(1337, 5, 0x1F, &mut buf).unwrap();
        assert_eq!(buf[0] & 0x1F, 0x1F); // Prefix = 31
        assert_eq!(buf[1], 0x9A); // 154 = 26 + 128
        assert_eq!(buf[2], 0x0A); // 10
    }

}
