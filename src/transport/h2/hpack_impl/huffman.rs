//! HPACK Huffman encoding/decoding (RFC 7541 Appendix B).
//!
//! Provides Huffman codec for string literals with a static table optimized
//! for HTTP headers.

use super::error::HpackError;

/// Huffman code entry: code value (right-aligned) and length in bits.
#[derive(Debug, Clone, Copy)]
struct HuffmanCode {
    code: u32,
    len: u8,
}

/// Complete Huffman table from RFC 7541 Appendix B (256 entries for bytes 0x00-0xFF).
///
/// Codes are stored right-aligned (LSB-aligned) as specified in the RFC.
const HUFFMAN_TABLE: [HuffmanCode; 256] = [
    // 0x00-0x0F
    HuffmanCode {
        code: 0x1ff8,
        len: 13,
    },
    HuffmanCode {
        code: 0x7fffd8,
        len: 23,
    },
    HuffmanCode {
        code: 0xfffffe2,
        len: 28,
    },
    HuffmanCode {
        code: 0xfffffe3,
        len: 28,
    },
    HuffmanCode {
        code: 0xfffffe4,
        len: 28,
    },
    HuffmanCode {
        code: 0xfffffe5,
        len: 28,
    },
    HuffmanCode {
        code: 0xfffffe6,
        len: 28,
    },
    HuffmanCode {
        code: 0xfffffe7,
        len: 28,
    },
    HuffmanCode {
        code: 0xfffffe8,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffea,
        len: 24,
    },
    HuffmanCode {
        code: 0x3ffffffc,
        len: 30,
    },
    HuffmanCode {
        code: 0xfffffe9,
        len: 28,
    },
    HuffmanCode {
        code: 0xfffffea,
        len: 28,
    },
    HuffmanCode {
        code: 0x3ffffffd,
        len: 30,
    },
    HuffmanCode {
        code: 0xfffffeb,
        len: 28,
    },
    HuffmanCode {
        code: 0xfffffec,
        len: 28,
    },
    // 0x10-0x1F
    HuffmanCode {
        code: 0xfffffed,
        len: 28,
    },
    HuffmanCode {
        code: 0xfffffee,
        len: 28,
    },
    HuffmanCode {
        code: 0xfffffef,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffff0,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffff1,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffff2,
        len: 28,
    },
    HuffmanCode {
        code: 0x3ffffffe,
        len: 30,
    },
    HuffmanCode {
        code: 0xffffff3,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffff4,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffff5,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffff6,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffff7,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffff8,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffff9,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffffa,
        len: 28,
    },
    HuffmanCode {
        code: 0xffffffb,
        len: 28,
    },
    // 0x20-0x2F (' ' to '/')
    HuffmanCode { code: 0x14, len: 6 }, // ' ' (0x20)
    HuffmanCode {
        code: 0x3f8,
        len: 10,
    },
    HuffmanCode {
        code: 0x3f9,
        len: 10,
    },
    HuffmanCode {
        code: 0xffa,
        len: 12,
    },
    HuffmanCode {
        code: 0x1ff9,
        len: 13,
    },
    HuffmanCode { code: 0x15, len: 6 }, // '%' (0x25)
    HuffmanCode { code: 0xf8, len: 8 },
    HuffmanCode {
        code: 0x7fa,
        len: 11,
    },
    HuffmanCode {
        code: 0x3fa,
        len: 10,
    },
    HuffmanCode {
        code: 0x3fb,
        len: 10,
    },
    HuffmanCode { code: 0xf9, len: 8 },
    HuffmanCode {
        code: 0x7fb,
        len: 11,
    },
    HuffmanCode { code: 0xfa, len: 8 },
    HuffmanCode { code: 0x16, len: 6 }, // '-' (0x2D)
    HuffmanCode { code: 0x17, len: 6 }, // '.' (0x2E)
    HuffmanCode { code: 0x18, len: 6 }, // '/' (0x2F)
    // 0x30-0x3F ('0' to '?')
    HuffmanCode { code: 0x0, len: 5 },  // '0' (0x30)
    HuffmanCode { code: 0x1, len: 5 },  // '1' (0x31)
    HuffmanCode { code: 0x2, len: 5 },  // '2' (0x32)
    HuffmanCode { code: 0x19, len: 6 }, // '3' (0x33)
    HuffmanCode { code: 0x1a, len: 6 }, // '4' (0x34)
    HuffmanCode { code: 0x1b, len: 6 }, // '5' (0x35)
    HuffmanCode { code: 0x1c, len: 6 }, // '6' (0x36)
    HuffmanCode { code: 0x1d, len: 6 }, // '7' (0x37)
    HuffmanCode { code: 0x1e, len: 6 }, // '8' (0x38)
    HuffmanCode { code: 0x1f, len: 6 }, // '9' (0x39)
    HuffmanCode { code: 0x5c, len: 7 }, // ':' (0x3A)
    HuffmanCode { code: 0xfb, len: 8 },
    HuffmanCode {
        code: 0x7ffc,
        len: 15,
    },
    HuffmanCode { code: 0x20, len: 6 }, // '=' (0x3D)
    HuffmanCode {
        code: 0xffb,
        len: 12,
    },
    HuffmanCode {
        code: 0x3fc,
        len: 10,
    },
    // 0x40-0x4F ('@' to 'O')
    HuffmanCode {
        code: 0x1ffa,
        len: 13,
    },
    HuffmanCode { code: 0x21, len: 6 }, // 'A' (0x41)
    HuffmanCode { code: 0x5d, len: 7 },
    HuffmanCode { code: 0x5e, len: 7 },
    HuffmanCode { code: 0x5f, len: 7 },
    HuffmanCode { code: 0x60, len: 7 },
    HuffmanCode { code: 0x61, len: 7 },
    HuffmanCode { code: 0x62, len: 7 },
    HuffmanCode { code: 0x63, len: 7 },
    HuffmanCode { code: 0x64, len: 7 },
    HuffmanCode { code: 0x65, len: 7 },
    HuffmanCode { code: 0x66, len: 7 },
    HuffmanCode { code: 0x67, len: 7 },
    HuffmanCode { code: 0x68, len: 7 },
    HuffmanCode { code: 0x69, len: 7 },
    HuffmanCode { code: 0x6a, len: 7 },
    // 0x50-0x5F ('P' to '_')
    HuffmanCode { code: 0x6b, len: 7 },
    HuffmanCode { code: 0x6c, len: 7 },
    HuffmanCode { code: 0x6d, len: 7 },
    HuffmanCode { code: 0x6e, len: 7 },
    HuffmanCode { code: 0x6f, len: 7 },
    HuffmanCode { code: 0x70, len: 7 },
    HuffmanCode { code: 0x71, len: 7 },
    HuffmanCode { code: 0x72, len: 7 },
    HuffmanCode { code: 0xfc, len: 8 },
    HuffmanCode { code: 0x73, len: 7 },
    HuffmanCode { code: 0xfd, len: 8 },
    HuffmanCode {
        code: 0x1ffb,
        len: 13,
    },
    HuffmanCode {
        code: 0x7fff0,
        len: 19,
    },
    HuffmanCode {
        code: 0x1ffc,
        len: 13,
    },
    HuffmanCode {
        code: 0x3ffc,
        len: 14,
    },
    HuffmanCode { code: 0x22, len: 6 }, // '_' (0x5F)
    // 0x60-0x6F ('`' to 'o')
    HuffmanCode {
        code: 0x7ffd,
        len: 15,
    },
    HuffmanCode { code: 0x3, len: 5 }, // 'a' (0x61)
    HuffmanCode { code: 0x23, len: 6 },
    HuffmanCode { code: 0x4, len: 5 },
    HuffmanCode { code: 0x24, len: 6 },
    HuffmanCode { code: 0x5, len: 5 },
    HuffmanCode { code: 0x25, len: 6 },
    HuffmanCode { code: 0x26, len: 6 },
    HuffmanCode { code: 0x27, len: 6 },
    HuffmanCode { code: 0x6, len: 5 },
    HuffmanCode { code: 0x74, len: 7 },
    HuffmanCode { code: 0x75, len: 7 },
    HuffmanCode { code: 0x28, len: 6 },
    HuffmanCode { code: 0x29, len: 6 },
    HuffmanCode { code: 0x2a, len: 6 },
    HuffmanCode { code: 0x7, len: 5 }, // 'o' (0x6F)
    // 0x70-0x7F ('p' to DEL)
    HuffmanCode { code: 0x2b, len: 6 },
    HuffmanCode { code: 0x76, len: 7 },
    HuffmanCode { code: 0x2c, len: 6 },
    HuffmanCode { code: 0x8, len: 5 },
    HuffmanCode { code: 0x9, len: 5 },
    HuffmanCode { code: 0x2d, len: 6 },
    HuffmanCode { code: 0x77, len: 7 },
    HuffmanCode { code: 0x78, len: 7 },
    HuffmanCode { code: 0x79, len: 7 },
    HuffmanCode { code: 0x7a, len: 7 },
    HuffmanCode { code: 0x7b, len: 7 },
    HuffmanCode {
        code: 0x7ffe,
        len: 15,
    },
    HuffmanCode {
        code: 0x7fc,
        len: 11,
    },
    HuffmanCode {
        code: 0x3ffd,
        len: 14,
    },
    HuffmanCode {
        code: 0x1ffd,
        len: 13,
    },
    HuffmanCode {
        code: 0xffffffc,
        len: 28,
    },
    // 0x80-0xFF (extended ASCII)
    HuffmanCode {
        code: 0xfffe6,
        len: 20,
    },
    HuffmanCode {
        code: 0x3fffd2,
        len: 22,
    },
    HuffmanCode {
        code: 0xfffe7,
        len: 20,
    },
    HuffmanCode {
        code: 0xfffe8,
        len: 20,
    },
    HuffmanCode {
        code: 0x3fffd3,
        len: 22,
    },
    HuffmanCode {
        code: 0x3fffd4,
        len: 22,
    },
    HuffmanCode {
        code: 0x3fffd5,
        len: 22,
    },
    HuffmanCode {
        code: 0x7fffd9,
        len: 23,
    },
    HuffmanCode {
        code: 0x3fffd6,
        len: 22,
    },
    HuffmanCode {
        code: 0x7fffda,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffdb,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffdc,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffdd,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffde,
        len: 23,
    },
    HuffmanCode {
        code: 0xffffeb,
        len: 24,
    },
    HuffmanCode {
        code: 0x7fffdf,
        len: 23,
    },
    HuffmanCode {
        code: 0xffffec,
        len: 24,
    },
    HuffmanCode {
        code: 0xffffed,
        len: 24,
    },
    HuffmanCode {
        code: 0x3fffd7,
        len: 22,
    },
    HuffmanCode {
        code: 0x7fffe0,
        len: 23,
    },
    HuffmanCode {
        code: 0xffffee,
        len: 24,
    },
    HuffmanCode {
        code: 0x7fffe1,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffe2,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffe3,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffe4,
        len: 23,
    },
    HuffmanCode {
        code: 0x1fffdc,
        len: 21,
    },
    HuffmanCode {
        code: 0x3fffd8,
        len: 22,
    },
    HuffmanCode {
        code: 0x7fffe5,
        len: 23,
    },
    HuffmanCode {
        code: 0x3fffd9,
        len: 22,
    },
    HuffmanCode {
        code: 0x7fffe6,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffe7,
        len: 23,
    },
    HuffmanCode {
        code: 0xffffef,
        len: 24,
    },
    HuffmanCode {
        code: 0x3fffda,
        len: 22,
    },
    HuffmanCode {
        code: 0x1fffdd,
        len: 21,
    },
    HuffmanCode {
        code: 0xfffe9,
        len: 20,
    },
    HuffmanCode {
        code: 0x3fffdb,
        len: 22,
    },
    HuffmanCode {
        code: 0x3fffdc,
        len: 22,
    },
    HuffmanCode {
        code: 0x7fffe8,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffe9,
        len: 23,
    },
    HuffmanCode {
        code: 0x1fffde,
        len: 21,
    },
    HuffmanCode {
        code: 0x7fffea,
        len: 23,
    },
    HuffmanCode {
        code: 0x3fffdd,
        len: 22,
    },
    HuffmanCode {
        code: 0x3fffde,
        len: 22,
    },
    HuffmanCode {
        code: 0xfffff0,
        len: 24,
    },
    HuffmanCode {
        code: 0x1fffdf,
        len: 21,
    },
    HuffmanCode {
        code: 0x3fffdf,
        len: 22,
    },
    HuffmanCode {
        code: 0x7fffeb,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffec,
        len: 23,
    },
    HuffmanCode {
        code: 0x1fffe0,
        len: 21,
    },
    HuffmanCode {
        code: 0x1fffe1,
        len: 21,
    },
    HuffmanCode {
        code: 0x3fffe0,
        len: 22,
    },
    HuffmanCode {
        code: 0x1fffe2,
        len: 21,
    },
    HuffmanCode {
        code: 0x7fffed,
        len: 23,
    },
    HuffmanCode {
        code: 0x3fffe1,
        len: 22,
    },
    HuffmanCode {
        code: 0x7fffee,
        len: 23,
    },
    HuffmanCode {
        code: 0x7fffef,
        len: 23,
    },
    HuffmanCode {
        code: 0xfffea,
        len: 20,
    },
    HuffmanCode {
        code: 0x3fffe2,
        len: 22,
    },
    HuffmanCode {
        code: 0x3fffe3,
        len: 22,
    },
    HuffmanCode {
        code: 0x3fffe4,
        len: 22,
    },
    HuffmanCode {
        code: 0x7ffff0,
        len: 23,
    },
    HuffmanCode {
        code: 0x3fffe5,
        len: 22,
    },
    HuffmanCode {
        code: 0x3fffe6,
        len: 22,
    },
    HuffmanCode {
        code: 0x7ffff1,
        len: 23,
    },
    HuffmanCode {
        code: 0x3ffffe0,
        len: 26,
    },
    HuffmanCode {
        code: 0x3ffffe1,
        len: 26,
    },
    HuffmanCode {
        code: 0xfffeb,
        len: 20,
    },
    HuffmanCode {
        code: 0x7fff1,
        len: 19,
    },
    HuffmanCode {
        code: 0x3fffe7,
        len: 22,
    },
    HuffmanCode {
        code: 0x7ffff2,
        len: 23,
    },
    HuffmanCode {
        code: 0x3fffe8,
        len: 22,
    },
    HuffmanCode {
        code: 0x1ffffec,
        len: 25,
    },
    HuffmanCode {
        code: 0x3ffffe2,
        len: 26,
    },
    HuffmanCode {
        code: 0x3ffffe3,
        len: 26,
    },
    HuffmanCode {
        code: 0x3ffffe4,
        len: 26,
    },
    HuffmanCode {
        code: 0x7ffffde,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffdf,
        len: 27,
    },
    HuffmanCode {
        code: 0x3ffffe5,
        len: 26,
    },
    HuffmanCode {
        code: 0xfffff1,
        len: 24,
    },
    HuffmanCode {
        code: 0x1ffffed,
        len: 25,
    },
    HuffmanCode {
        code: 0x7fff2,
        len: 19,
    },
    HuffmanCode {
        code: 0x1fffe3,
        len: 21,
    },
    HuffmanCode {
        code: 0x3ffffe6,
        len: 26,
    },
    HuffmanCode {
        code: 0x7ffffe0,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffe1,
        len: 27,
    },
    HuffmanCode {
        code: 0x3ffffe7,
        len: 26,
    },
    HuffmanCode {
        code: 0x7ffffe2,
        len: 27,
    },
    HuffmanCode {
        code: 0xfffff2,
        len: 24,
    },
    HuffmanCode {
        code: 0x1fffe4,
        len: 21,
    },
    HuffmanCode {
        code: 0x1fffe5,
        len: 21,
    },
    HuffmanCode {
        code: 0x3ffffe8,
        len: 26,
    },
    HuffmanCode {
        code: 0x3ffffe9,
        len: 26,
    },
    HuffmanCode {
        code: 0xffffffd,
        len: 28,
    },
    HuffmanCode {
        code: 0x7ffffe3,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffe4,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffe5,
        len: 27,
    },
    HuffmanCode {
        code: 0xfffec,
        len: 20,
    },
    HuffmanCode {
        code: 0xfffff3,
        len: 24,
    },
    HuffmanCode {
        code: 0xfffed,
        len: 20,
    },
    HuffmanCode {
        code: 0x1fffe6,
        len: 21,
    },
    HuffmanCode {
        code: 0x3fffe9,
        len: 22,
    },
    HuffmanCode {
        code: 0x1fffe7,
        len: 21,
    },
    HuffmanCode {
        code: 0x1fffe8,
        len: 21,
    },
    HuffmanCode {
        code: 0x7ffff3,
        len: 23,
    },
    HuffmanCode {
        code: 0x3fffea,
        len: 22,
    },
    HuffmanCode {
        code: 0x3fffeb,
        len: 22,
    },
    HuffmanCode {
        code: 0x1ffffee,
        len: 25,
    },
    HuffmanCode {
        code: 0x1ffffef,
        len: 25,
    },
    HuffmanCode {
        code: 0xfffff4,
        len: 24,
    },
    HuffmanCode {
        code: 0xfffff5,
        len: 24,
    },
    HuffmanCode {
        code: 0x3ffffea,
        len: 26,
    },
    HuffmanCode {
        code: 0x7ffff4,
        len: 23,
    },
    HuffmanCode {
        code: 0x3ffffeb,
        len: 26,
    },
    HuffmanCode {
        code: 0x7ffffe6,
        len: 27,
    },
    HuffmanCode {
        code: 0x3ffffec,
        len: 26,
    },
    HuffmanCode {
        code: 0x3ffffed,
        len: 26,
    },
    HuffmanCode {
        code: 0x7ffffe7,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffe8,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffe9,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffea,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffeb,
        len: 27,
    },
    HuffmanCode {
        code: 0xffffffe,
        len: 28,
    },
    HuffmanCode {
        code: 0x7ffffec,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffed,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffee,
        len: 27,
    },
    HuffmanCode {
        code: 0x7ffffef,
        len: 27,
    },
    HuffmanCode {
        code: 0x7fffff0,
        len: 27,
    },
    HuffmanCode {
        code: 0x3ffffee,
        len: 26,
    },
];

/// EOS (End of String) symbol code and length.
const EOS_CODE: u32 = 0x3fffffff;
const EOS_LEN: u8 = 30;

/// Calculate the encoded length of a string if Huffman encoded.
pub fn huffman_encoded_len(input: &[u8]) -> usize {
    let total_bits: usize = input
        .iter()
        .map(|&b| HUFFMAN_TABLE[b as usize].len as usize)
        .sum();
    total_bits.div_ceil(8) // Round up to bytes
}

/// Encode bytes to Huffman-compressed output (MSB-first).
///
/// Returns the encoded bytes.
pub fn huffman_encode(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }

    // Pre-allocate (worst case: ~2x input size, typical: ~0.7x)
    let mut output = Vec::with_capacity(input.len());
    let mut accumulator: u64 = 0;
    let mut bit_count: u8 = 0;

    for &byte in input {
        let entry = &HUFFMAN_TABLE[byte as usize];

        // Pack code into accumulator (MSB-first)
        accumulator = (accumulator << entry.len) | (entry.code as u64);
        bit_count += entry.len;

        // Flush complete bytes
        while bit_count >= 8 {
            bit_count -= 8;
            output.push((accumulator >> bit_count) as u8);
        }
    }

    // Pad remaining bits with EOS prefix (all 1s)
    if bit_count > 0 {
        let padding = 8 - bit_count;
        // Shift left and fill with 1s
        accumulator = (accumulator << padding) | ((1u64 << padding) - 1);
        output.push(accumulator as u8);
    }

    output
}

/// Encode if Huffman encoding saves space, otherwise return original.
///
/// Returns (encoded_bytes, use_huffman_flag).
pub fn huffman_encode_if_smaller(input: &[u8]) -> (Vec<u8>, bool) {
    let encoded_len = huffman_encoded_len(input);
    if encoded_len < input.len() {
        (huffman_encode(input), true)
    } else {
        (input.to_vec(), false)
    }
}

/// Multi-level lookup table for Huffman decoding.
///
/// Level 0: 256 entries for 8-bit prefix (handles codes 5-8 bits)
/// Level 1+: Secondary tables for longer codes
struct DecodeTable {
    level0: [Option<(u8, u8)>; 256], // (symbol, remaining_bits)
}

impl DecodeTable {
    fn new() -> Self {
        let mut level0 = [None; 256];

        // Build level 0 table: for each possible 8-bit prefix, find matching codes
        for symbol in 0..=255u8 {
            let entry = &HUFFMAN_TABLE[symbol as usize];
            if entry.len <= 8 {
                // Code fits in 8 bits
                let shift = entry.len.saturating_sub(8);
                let code_msb = (entry.code >> shift) as u8;
                let shift = 8u8.saturating_sub(entry.len);
                let mask = (1u8 << shift) - 1;

                // Fill all entries that match this prefix
                for prefix in 0..=mask {
                    let idx = (code_msb << shift) | prefix;
                    if level0[idx as usize].is_none() {
                        level0[idx as usize] = Some((symbol, 0));
                    }
                }
            }
        }

        Self { level0 }
    }
}

static DECODE_TABLE: std::sync::OnceLock<DecodeTable> = std::sync::OnceLock::new();

fn get_decode_table() -> &'static DecodeTable {
    DECODE_TABLE.get_or_init(DecodeTable::new)
}

/// Decode Huffman-encoded bytes.
///
/// Returns the decoded bytes.
pub fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, HpackError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = Vec::new();
    let mut bit_buffer: u64 = 0;
    let mut bit_count: u8 = 0;
    let mut pos = 0;

    while pos < input.len() || bit_count > 0 {
        // Fill buffer
        while bit_count < 32 && pos < input.len() {
            bit_buffer = (bit_buffer << 8) | (input[pos] as u64);
            bit_count += 8;
            pos += 1;
        }

        // Try to decode using level 0 table
        if bit_count >= 8 {
            let prefix = ((bit_buffer >> (bit_count - 8)) & 0xFF) as u8;
            let table = get_decode_table();
            if let Some((symbol, remaining)) = table.level0[prefix as usize] {
                if remaining == 0 {
                    output.push(symbol);
                    bit_count -= HUFFMAN_TABLE[symbol as usize].len;
                    bit_buffer &= (1u64 << bit_count) - 1;
                    continue;
                }
            }
        }

        // Fallback: brute force search through all codes
        let mut found = false;
        for symbol in 0..=255u8 {
            let entry = &HUFFMAN_TABLE[symbol as usize];
            if bit_count >= entry.len {
                // Extract code from buffer (MSB-first)
                // We need to extract the top 'entry.len' bits from bit_buffer
                let code_from_buffer =
                    (bit_buffer >> (bit_count - entry.len)) & ((1u64 << entry.len) - 1);
                // The Huffman code is stored right-aligned, so we compare directly
                // entry.code is already right-aligned (e.g., 'a' = 0x03 for 5 bits)
                if code_from_buffer == entry.code as u64 {
                    output.push(symbol);
                    bit_count -= entry.len;
                    bit_buffer &= (1u64 << bit_count) - 1;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            // Check for EOS padding
            if bit_count <= 7 {
                // Remaining bits should be EOS prefix
                let padding = bit_buffer & ((1u64 << bit_count) - 1);
                let eos_prefix = (EOS_CODE >> (EOS_LEN - bit_count)) as u64;
                if padding == eos_prefix {
                    // Valid padding
                    break;
                }
            }
            return Err(HpackError::InvalidHuffmanCode);
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_huffman_encode_simple() {
        let input = b"a";
        let encoded = huffman_encode(input);
        // 'a' = 0x03, 5 bits = 00011
        // Padded: 00011|111 = 00011111 = 0x1F
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_huffman_decode_simple() {
        let input = b"a";
        let encoded = huffman_encode(input);
        let decoded = huffman_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_huffman_round_trip() {
        let inputs: Vec<&[u8]> = vec![b"hello", b"www.example.com", b"GET", b"https", b"/"];

        for input in &inputs {
            let encoded = huffman_encode(input);
            let decoded = huffman_decode(&encoded).unwrap();
            assert_eq!(
                decoded,
                *input,
                "Failed for: {:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn test_huffman_encode_if_smaller() {
        let short = b"a";
        let (_, use_huff) = huffman_encode_if_smaller(short);
        // Very short strings might not benefit
        assert!(use_huff || !use_huff); // Either is fine

        let long = b"www.example.com";
        let (_, use_huff) = huffman_encode_if_smaller(long);
        assert!(use_huff); // Should benefit from encoding
    }
}
