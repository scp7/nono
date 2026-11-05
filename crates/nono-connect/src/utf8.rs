//! Carry incomplete UTF-8 sequences across output writes.
//!
//! The Windows console decodes each `WriteFile` call independently under
//! code page 65001; a multi-byte character split across two WebSocket frames
//! would otherwise render as two replacement characters. Invalid bytes are
//! passed through for the console to replace; only a *possibly valid*
//! incomplete tail (at most 3 bytes) is held back.

/// Holds back an incomplete trailing UTF-8 sequence until the next chunk.
#[derive(Debug, Default)]
pub struct Utf8Carry {
    pending: Vec<u8>,
}

impl Utf8Carry {
    /// Return the bytes of `pending + input` that are safe to emit now.
    pub fn push(&mut self, input: &[u8]) -> Vec<u8> {
        let mut bytes = std::mem::take(&mut self.pending);
        bytes.extend_from_slice(input);
        let split = incomplete_tail_start(&bytes);
        self.pending = bytes.split_off(split);
        bytes
    }

    /// Any held-back bytes, emitted as-is at end of stream.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }
}

/// Index where a trailing, possibly-valid incomplete UTF-8 sequence starts,
/// or `bytes.len()` when there is none.
fn incomplete_tail_start(bytes: &[u8]) -> usize {
    let len = bytes.len();
    // A lead byte can be at most 3 bytes before the end of an incomplete sequence.
    for back in 1..=3.min(len) {
        let index = len - back;
        let byte = bytes[index];
        if byte & 0b1100_0000 == 0b1000_0000 {
            continue; // continuation byte: keep looking for the lead
        }
        let needed = match byte {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => return len, // ASCII or invalid lead: nothing to hold
        };
        return if back < needed { index } else { len };
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_multibyte_characters_across_writes() {
        let text = "a€b😀".as_bytes();
        for split in 0..=text.len() {
            let mut carry = Utf8Carry::default();
            let mut out = carry.push(&text[..split]);
            assert!(std::str::from_utf8(&out).is_ok(), "split {split}");
            out.extend(carry.push(&text[split..]));
            out.extend(carry.finish());
            assert_eq!(out, text);
        }
    }

    #[test]
    fn invalid_bytes_pass_through() {
        let mut carry = Utf8Carry::default();
        assert_eq!(carry.push(b"\xff\xfe"), b"\xff\xfe");
        assert_eq!(carry.push(b"x\x80"), b"x\x80");
        assert!(carry.finish().is_empty());
    }
}
