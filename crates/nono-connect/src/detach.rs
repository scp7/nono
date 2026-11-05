//! Detach key recognition in local terminal input.
//!
//! Ported from `nono-cli` (`connect_client::DetachMatcher` and the CSI-u
//! helpers in `pty_proxy`). The sequence is recognized in traditional
//! control-byte form and in kitty CSI-u / xterm `modifyOtherKeys` encodings,
//! because a hosted application may switch the local terminal into them.

/// Ctrl-] then d.
pub const DEFAULT_DETACH_SEQUENCE: &[u8] = &[0x1d, b'd'];

/// Longest CSI sequence buffered while deciding whether it is a detach key.
pub const MAX_ENHANCED_KEY_SEQUENCE_LEN: usize = 32;

const KITTY_EVENT_PRESS: u32 = 1;
/// Caps Lock and Num Lock bits of a kitty modifier mask.
const KITTY_LOCK_MODIFIER_BITS: u32 = 64 | 128;

/// Result of feeding input to a [`DetachMatcher`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DetachMatch {
    /// Bytes to forward to the remote PTY.
    pub forward: Vec<u8>,
    /// The detach sequence completed; bytes after it in this chunk are dropped.
    pub detach: bool,
}

/// Streaming matcher that withholds a partial detach sequence until it
/// either completes or is proven to be ordinary input.
#[derive(Debug)]
pub struct DetachMatcher {
    sequence: Vec<u8>,
    pending_match_len: usize,
    pending_escape: Vec<u8>,
}

impl DetachMatcher {
    /// A matcher for `sequence`; an empty sequence disables detaching.
    pub fn new(sequence: Vec<u8>) -> Self {
        Self {
            sequence,
            pending_match_len: 0,
            pending_escape: Vec::new(),
        }
    }

    /// Whether any input is being withheld.
    pub fn has_pending(&self) -> bool {
        self.pending_match_len > 0 || !self.pending_escape.is_empty()
    }

    /// Feed one chunk of local input.
    pub fn push(&mut self, input: &[u8]) -> DetachMatch {
        let mut forward = Vec::with_capacity(input.len());
        for (index, &byte) in input.iter().enumerate() {
            if !self.pending_escape.is_empty() {
                self.pending_escape.push(byte);
                let Some(&expected) = self.sequence.get(self.pending_match_len) else {
                    self.flush_pending(&mut forward);
                    continue;
                };
                match match_enhanced_key_sequence(&self.pending_escape, expected) {
                    EnhancedKeyMatch::Pending => {
                        if self.pending_escape.len() > MAX_ENHANCED_KEY_SEQUENCE_LEN {
                            self.flush_pending(&mut forward);
                        }
                    }
                    EnhancedKeyMatch::Matched => {
                        self.pending_escape.clear();
                        self.pending_match_len += 1;
                        if self.pending_match_len == self.sequence.len() {
                            self.pending_match_len = 0;
                            return DetachMatch {
                                forward,
                                detach: true,
                            };
                        }
                    }
                    EnhancedKeyMatch::Invalid => {
                        let echo = self.sequence[..self.pending_match_len]
                            .iter()
                            .any(|&key| is_enhanced_key_echo(&self.pending_escape, key));
                        if echo {
                            self.pending_escape.clear();
                        } else {
                            self.flush_pending(&mut forward);
                        }
                    }
                }
                continue;
            }

            if self.sequence.is_empty() {
                forward.push(byte);
                continue;
            }

            if byte == self.sequence[self.pending_match_len] {
                self.pending_match_len += 1;
                if self.pending_match_len == self.sequence.len() {
                    self.pending_match_len = 0;
                    return DetachMatch {
                        forward,
                        detach: true,
                    };
                }
                continue;
            }

            if byte == b'\x1b'
                && input.get(index + 1).copied() == Some(b'[')
                && self
                    .sequence
                    .get(self.pending_match_len)
                    .copied()
                    .is_some_and(detach_key_supports_enhanced_match)
            {
                self.pending_escape.push(byte);
                continue;
            }

            if self.pending_match_len > 0 {
                forward.extend_from_slice(&self.sequence[..self.pending_match_len]);
                self.pending_match_len = 0;
                if byte == self.sequence[0] {
                    self.pending_match_len = 1;
                    continue;
                }
            }
            forward.push(byte);
        }
        DetachMatch {
            forward,
            detach: false,
        }
    }

    fn flush_pending(&mut self, forward: &mut Vec<u8>) {
        if self.pending_match_len > 0 {
            forward.extend_from_slice(&self.sequence[..self.pending_match_len]);
            self.pending_match_len = 0;
        }
        forward.extend_from_slice(&self.pending_escape);
        self.pending_escape.clear();
    }
}

/// Human-readable form of a detach sequence, e.g. `Ctrl-] then d`.
pub fn format_detach_sequence(sequence: &[u8]) -> String {
    sequence
        .iter()
        .map(|byte| match byte {
            0x00 => "Ctrl-@".to_string(),
            0x01..=0x1a => format!("Ctrl-{}", char::from(byte + b'@')),
            0x1b => "Esc".to_string(),
            0x1c => "Ctrl-\\".to_string(),
            0x1d => "Ctrl-]".to_string(),
            0x1e => "Ctrl-^".to_string(),
            0x1f => "Ctrl-_".to_string(),
            b' ' => "Space".to_string(),
            0x7f => "Backspace".to_string(),
            byte if byte.is_ascii_graphic() => char::from(*byte).to_string(),
            byte => format!("0x{byte:02x}"),
        })
        .collect::<Vec<_>>()
        .join(" then ")
}

enum EnhancedKeyMatch {
    Pending,
    Matched,
    Invalid,
}

fn detach_key_supports_enhanced_match(key: u8) -> bool {
    key.is_ascii_graphic() || key == b' ' || control_key_candidates(key).is_some()
}

fn match_enhanced_key_sequence(bytes: &[u8], expected_key: u8) -> EnhancedKeyMatch {
    match bytes {
        [] | [b'\x1b'] | [b'\x1b', b'['] => return EnhancedKeyMatch::Pending,
        [b'\x1b', b'[', ..] => {}
        _ => return EnhancedKeyMatch::Invalid,
    }
    let payload = &bytes[2..];
    let Some((&last, body)) = payload.split_last() else {
        return EnhancedKeyMatch::Pending;
    };

    if last == b'u' {
        let Some(report) = parse_csi_u_key_report(body) else {
            return EnhancedKeyMatch::Invalid;
        };
        return if report.event_type == KITTY_EVENT_PRESS
            && enhanced_key_matches(expected_key, report.codepoint, report.modifiers)
        {
            EnhancedKeyMatch::Matched
        } else {
            EnhancedKeyMatch::Invalid
        };
    }

    if last == b'~' {
        let fields: Vec<&[u8]> = body.split(|b| *b == b';').collect();
        if fields.len() == 3
            && fields[0] == b"27"
            && fields[1].iter().all(u8::is_ascii_digit)
            && fields[2].iter().all(u8::is_ascii_digit)
        {
            let (Some(modifiers), Some(codepoint)) =
                (parse_ascii_u32(fields[1]), parse_ascii_u32(fields[2]))
            else {
                return EnhancedKeyMatch::Invalid;
            };
            return if enhanced_key_matches(expected_key, codepoint, modifiers) {
                EnhancedKeyMatch::Matched
            } else {
                EnhancedKeyMatch::Invalid
            };
        }
    }

    if (last.is_ascii_digit() || matches!(last, b';' | b':'))
        && body
            .iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b';' | b':' | b'~'))
    {
        return EnhancedKeyMatch::Pending;
    }
    EnhancedKeyMatch::Invalid
}

/// A complete kitty CSI-u repeat or release report for `key`.
fn is_enhanced_key_echo(bytes: &[u8], key: u8) -> bool {
    let Some(body) = bytes
        .strip_prefix(b"\x1b[")
        .and_then(|rest| rest.strip_suffix(b"u"))
    else {
        return false;
    };
    parse_csi_u_key_report(body).is_some_and(|report| {
        report.event_type != KITTY_EVENT_PRESS
            && enhanced_key_matches(key, report.codepoint, report.modifiers)
    })
}

struct CsiUKeyReport {
    codepoint: u32,
    modifiers: u32,
    event_type: u32,
}

/// Parse the body of `CSI key[:shifted[:base]] [; modifiers[:event] [; text]] u`.
fn parse_csi_u_key_report(body: &[u8]) -> Option<CsiUKeyReport> {
    if body.is_empty()
        || !body
            .iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b';' | b':'))
    {
        return None;
    }
    let mut fields = body.split(|b| *b == b';');
    let codepoint = parse_ascii_u32(fields.next()?.split(|b| *b == b':').next()?)?;
    let (modifiers, event_type) = match fields.next() {
        None => (1, KITTY_EVENT_PRESS),
        Some(field) => {
            let mut parts = field.split(|b| *b == b':');
            let modifiers = match parts.next() {
                Some(m) if !m.is_empty() => parse_ascii_u32(m)?,
                _ => 1,
            };
            let event_type = match parts.next() {
                Some(e) if !e.is_empty() => parse_ascii_u32(e)?,
                _ => KITTY_EVENT_PRESS,
            };
            (modifiers, event_type)
        }
    };
    let modifiers = modifiers
        .checked_sub(1)
        .map(|bits| (bits & !KITTY_LOCK_MODIFIER_BITS).saturating_add(1))?;
    Some(CsiUKeyReport {
        codepoint,
        modifiers,
        event_type,
    })
}

fn parse_ascii_u32(bytes: &[u8]) -> Option<u32> {
    std::str::from_utf8(bytes).ok()?.parse::<u32>().ok()
}

fn enhanced_key_matches(expected_key: u8, codepoint: u32, modifiers: u32) -> bool {
    match modifiers {
        1 => {
            (expected_key.is_ascii_graphic() || expected_key == b' ')
                && codepoint == u32::from(expected_key)
        }
        5 => control_key_candidates(expected_key)
            .is_some_and(|candidates| candidates.contains(&codepoint)),
        _ => false,
    }
}

fn control_key_candidates(expected_key: u8) -> Option<[u32; 2]> {
    match expected_key {
        0x01..=0x1a => Some([
            u32::from(expected_key + 0x40),
            u32::from(expected_key + 0x60),
        ]),
        0x1b..=0x1f => Some([u32::from(expected_key + 0x40); 2]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher() -> DetachMatcher {
        DetachMatcher::new(DEFAULT_DETACH_SEQUENCE.to_vec())
    }

    #[test]
    fn readable_key_names() {
        assert_eq!(
            format_detach_sequence(DEFAULT_DETACH_SEQUENCE),
            "Ctrl-] then d"
        );
        assert_eq!(format_detach_sequence(&[0x03, b' ']), "Ctrl-C then Space");
    }

    #[test]
    fn preserves_partial_and_mismatched_input() {
        let mut m = matcher();
        let first = m.push(b"abc\x1d");
        assert_eq!(first.forward, b"abc");
        assert!(!first.detach);
        assert!(m.has_pending());
        let mismatch = m.push(b"x");
        assert_eq!(mismatch.forward, b"\x1dx");
        let matched = m.push(b"z\x1ddtail");
        assert_eq!(matched.forward, b"z");
        assert!(matched.detach);
    }

    #[test]
    fn repeated_prefix_restarts_the_match() {
        let mut m = matcher();
        let result = m.push(b"\x1d\x1dd");
        assert_eq!(result.forward, b"\x1d");
        assert!(result.detach);
    }

    #[test]
    fn accepts_csi_u_control_prefix_even_when_chunked() {
        let mut m = matcher();
        assert!(m.push(b"\x1b[93;5ud").detach);
        let mut m = matcher();
        assert!(m.push(b"\x1b[93;").forward.is_empty());
        assert!(m.push(b"5u").forward.is_empty());
        assert!(m.push(b"d").detach);
    }

    #[test]
    fn accepts_modify_other_keys_form() {
        let mut m = matcher();
        assert!(m.push(b"\x1b[27;5;93~d").detach);
    }

    #[test]
    fn ignores_kitty_release_of_matched_prefix() {
        let mut m = matcher();
        assert!(m.push(b"\x1b[93;5u\x1b[93;5:3ud").detach);
        assert!(!m.has_pending());
    }

    #[test]
    fn forwards_unrelated_csi_input() {
        let mut m = matcher();
        let result = m.push(b"\x1b[99;5u\x1b[A");
        assert_eq!(result.forward, b"\x1b[99;5u\x1b[A");
        assert!(!result.detach);
        assert!(!m.has_pending());
    }

    #[test]
    fn overlong_pending_escape_is_flushed() {
        let mut m = matcher();
        let long = [b"\x1b[".as_slice(), &[b'1'; 40]].concat();
        let result = m.push(&long);
        assert_eq!(result.forward, long);
        assert!(!m.has_pending());
    }

    #[test]
    fn empty_sequence_never_detaches() {
        let mut m = DetachMatcher::new(Vec::new());
        let result = m.push(b"\x1dd");
        assert_eq!(result.forward, b"\x1dd");
        assert!(!result.detach);
    }
}
