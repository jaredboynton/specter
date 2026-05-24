use bytes::{Buf, Bytes, BytesMut};

use crate::websocket::error::{WebSocketError, WebSocketResult};
use crate::websocket::message::{CloseFrame, Message};

/// CSPRNG-backed source of WebSocket masking keys.
///
/// RFC 6455 §10.3 requires the masking key to come from a strong source of
/// entropy that is not predictable. Calling `getrandom::fill` per frame is
/// a kernel syscall per outgoing frame; instead we refill a 256-byte buffer
/// from the OS CSPRNG once every 64 frames and slice 4-byte masks out of it.
///
/// The kernel still supplies all bytes; we just amortise the syscall cost
/// across many frames. The mask is never reused and remains unpredictable
/// to a network observer.
pub(crate) struct MaskRng {
    cache: [u8; 256],
    pos: usize,
}

impl MaskRng {
    pub(crate) fn new() -> Self {
        let mut cache = [0u8; 256];
        getrandom::fill(&mut cache).expect("getrandom seed for WebSocket mask rng");
        Self { cache, pos: 0 }
    }

    #[inline]
    pub(crate) fn next_mask(&mut self) -> [u8; 4] {
        if self.pos + 4 > self.cache.len() {
            getrandom::fill(&mut self.cache).expect("getrandom refill for WebSocket mask rng");
            self.pos = 0;
        }
        let mask = [
            self.cache[self.pos],
            self.cache[self.pos + 1],
            self.cache[self.pos + 2],
            self.cache[self.pos + 3],
        ];
        self.pos += 4;
        mask
    }
}

impl Default for MaskRng {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MaskRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaskRng").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameConfig {
    pub max_frame_size: usize,
    pub max_message_size: usize,
}

impl FrameConfig {
    pub(crate) fn new(max_frame_size: usize, max_message_size: usize) -> Self {
        Self {
            max_frame_size,
            max_message_size,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpCode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xa,
}

impl OpCode {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xa => Self::Pong,
            _ => return None,
        })
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Frame {
    pub fin: bool,
    pub opcode: OpCode,
    pub payload: Bytes,
}

#[derive(Debug, Default)]
pub(crate) struct FrameDecoder {
    fragments: BytesMut,
    fragmented_opcode: Option<OpCode>,
}

impl FrameDecoder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub(crate) fn decode_message(
        &mut self,
        url: &url::Url,
        frame: Frame,
        config: FrameConfig,
    ) -> WebSocketResult<Option<Message>> {
        match frame.opcode {
            OpCode::Text | OpCode::Binary => {
                if self.fragmented_opcode.is_some() {
                    return Err(WebSocketError::protocol(
                        url,
                        "new data frame while fragmented message is active",
                    ));
                }
                if frame.fin {
                    return self.data_message(url, frame.opcode, frame.payload, config);
                }
                self.fragmented_opcode = Some(frame.opcode);
                self.push_fragment(url, frame.payload, config)?;
                Ok(None)
            }
            OpCode::Continuation => {
                let opcode = self.fragmented_opcode.ok_or_else(|| {
                    WebSocketError::protocol(url, "continuation without active fragmented message")
                })?;
                self.push_fragment(url, frame.payload, config)?;
                if !frame.fin {
                    return Ok(None);
                }
                self.fragmented_opcode = None;
                let payload = self.fragments.split().freeze();
                self.data_message(url, opcode, payload, config)
            }
            OpCode::Close => Ok(Some(Message::Close(CloseFrame::decode(
                url,
                &frame.payload,
            )?))),
            OpCode::Ping => Ok(Some(Message::Ping(frame.payload))),
            OpCode::Pong => Ok(Some(Message::Pong(frame.payload))),
        }
    }

    fn push_fragment(
        &mut self,
        url: &url::Url,
        payload: Bytes,
        config: FrameConfig,
    ) -> WebSocketResult<()> {
        if self.fragments.len().saturating_add(payload.len()) > config.max_message_size {
            return Err(WebSocketError::limit_exceeded(
                url,
                format!("message exceeds {} bytes", config.max_message_size),
            ));
        }
        self.fragments.extend_from_slice(&payload);
        Ok(())
    }

    fn data_message(
        &self,
        url: &url::Url,
        opcode: OpCode,
        payload: Bytes,
        config: FrameConfig,
    ) -> WebSocketResult<Option<Message>> {
        if payload.len() > config.max_message_size {
            return Err(WebSocketError::limit_exceeded(
                url,
                format!("message exceeds {} bytes", config.max_message_size),
            ));
        }

        match opcode {
            OpCode::Text => {
                let text = std::str::from_utf8(&payload)
                    .map_err(|e| WebSocketError::utf8(url, e.to_string()))?
                    .to_owned();
                Ok(Some(Message::Text(text)))
            }
            OpCode::Binary => Ok(Some(Message::Binary(payload))),
            _ => Err(WebSocketError::protocol(url, "invalid data opcode")),
        }
    }
}

#[inline]
pub(crate) fn encode_frame_into(
    opcode: OpCode,
    payload: &[u8],
    mask_rng: &mut MaskRng,
    out: &mut BytesMut,
) {
    out.clear();
    out.reserve(14 + payload.len());

    let key = mask_rng.next_mask();

    // Build the entire 2-14 byte header in a stack array and write it in
    // one extend_from_slice call instead of 3-4. Saves per-call bounds
    // checks and BytesMut len updates on the hot path.
    let mask_bit = 0x80_u8;
    let mut hdr = [0u8; 14];
    hdr[0] = 0x80 | opcode as u8;
    let hdr_len = match payload.len() {
        0..=125 => {
            hdr[1] = mask_bit | (payload.len() as u8);
            hdr[2..6].copy_from_slice(&key);
            6
        }
        126..=65535 => {
            hdr[1] = mask_bit | 126;
            hdr[2..4].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            hdr[4..8].copy_from_slice(&key);
            8
        }
        _ => {
            hdr[1] = mask_bit | 127;
            hdr[2..10].copy_from_slice(&(payload.len() as u64).to_be_bytes());
            hdr[10..14].copy_from_slice(&key);
            14
        }
    };
    out.extend_from_slice(&hdr[..hdr_len]);

    // Fuse the payload copy with the XOR mask: a single pass reads from
    // `payload`, XORs with the key word, and writes into the reserved tail
    // of `out`. Previously this was two passes: extend_from_slice (one
    // memcpy) followed by mask_payload_words (one read+write over the same
    // region). Halves the memory bandwidth consumed by the payload on every
    // frame; meaningful for 1KB+ payloads where this is the dominant cost.
    extend_masked(out, payload, key);
}

#[inline]
fn extend_masked(out: &mut BytesMut, payload: &[u8], key: [u8; 4]) {
    const WORD_BYTES: usize = std::mem::size_of::<usize>();
    let len = payload.len();
    let prev_len = out.len();
    debug_assert!(out.capacity() >= prev_len + len);

    let mut key_word_bytes = [0u8; WORD_BYTES];
    for (index, byte) in key_word_bytes.iter_mut().enumerate() {
        *byte = key[index & 3];
    }
    let key_word = usize::from_ne_bytes(key_word_bytes);

    let word_chunks = len / WORD_BYTES;
    let aligned = word_chunks * WORD_BYTES;

    // SAFETY: caller reserved `len` bytes past prev_len. We write the
    // entire region before calling set_len, so no uninitialised bytes are
    // ever exposed. Unaligned word reads/writes are explicitly used.
    unsafe {
        let src = payload.as_ptr();
        let dst = out.as_mut_ptr().add(prev_len);

        let mut offset = 0;
        while offset < aligned {
            let src_word = src.add(offset).cast::<usize>().read_unaligned();
            dst.add(offset)
                .cast::<usize>()
                .write_unaligned(src_word ^ key_word);
            offset += WORD_BYTES;
        }

        while offset < len {
            *dst.add(offset) = *src.add(offset) ^ key[offset & 3];
            offset += 1;
        }

        out.set_len(prev_len + len);
    }
}

#[inline]
pub(crate) fn decode_frame(
    url: &url::Url,
    buffer: &mut BytesMut,
    config: FrameConfig,
) -> WebSocketResult<Option<Frame>> {
    if buffer.len() < 2 {
        return Ok(None);
    }

    let b0 = buffer[0];
    let b1 = buffer[1];
    if b0 & 0x70 != 0 {
        return Err(WebSocketError::protocol(
            url,
            "RSV bits are set but no extensions are negotiated",
        ));
    }

    let fin = b0 & 0x80 != 0;
    let opcode = OpCode::from_u8(b0 & 0x0f).ok_or_else(|| {
        WebSocketError::protocol(url, format!("unsupported opcode {}", b0 & 0x0f))
    })?;
    let masked = b1 & 0x80 != 0;
    if masked {
        return Err(WebSocketError::protocol(
            url,
            "server frame must not be masked",
        ));
    }

    let mut header_len = 2;
    let mut payload_len = (b1 & 0x7f) as u64;
    if payload_len == 126 {
        if buffer.len() < 4 {
            return Ok(None);
        }
        payload_len = u16::from_be_bytes([buffer[2], buffer[3]]) as u64;
        if payload_len < 126 {
            return Err(WebSocketError::protocol(
                url,
                "payload length used non-minimal 16-bit encoding",
            ));
        }
        header_len = 4;
    } else if payload_len == 127 {
        if buffer.len() < 10 {
            return Ok(None);
        }
        let len = u64::from_be_bytes([
            buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9],
        ]);
        if len & (1 << 63) != 0 {
            return Err(WebSocketError::protocol(
                url,
                "64-bit payload length has most significant bit set",
            ));
        }
        payload_len = len;
        if payload_len <= 65535 {
            return Err(WebSocketError::protocol(
                url,
                "payload length used non-minimal 64-bit encoding",
            ));
        }
        header_len = 10;
    }

    if opcode.is_control() {
        if !fin {
            return Err(WebSocketError::protocol(
                url,
                "control frame must not be fragmented",
            ));
        }
        if payload_len > 125 {
            return Err(WebSocketError::protocol(
                url,
                "control frame payload exceeds 125 bytes",
            ));
        }
    }

    let payload_len_usize = usize::try_from(payload_len)
        .map_err(|_| WebSocketError::limit_exceeded(url, "payload length exceeds usize"))?;
    if payload_len_usize > config.max_frame_size {
        return Err(WebSocketError::limit_exceeded(
            url,
            format!("frame exceeds {} bytes", config.max_frame_size),
        ));
    }

    let total_len = header_len + payload_len_usize;
    if buffer.len() < total_len {
        return Ok(None);
    }

    buffer.advance(header_len);
    let payload = buffer.split_to(payload_len_usize).freeze();
    Ok(Some(Frame {
        fin,
        opcode,
        payload,
    }))
}
