//! Local terminal-emulator state that must be undone after an attachment.
//!
//! PTY output from the hosted session is forwarded verbatim, so the hosted
//! application can switch the *local* terminal into the alternate screen,
//! mouse tracking, bracketed paste, kitty keyboard, or (Windows Terminal)
//! win32-input-mode. Restoring console/termios modes alone does not undo
//! those, so the client tracks the alternate screen and emits a reset.

const ENTER_ALT_SCREEN: &[u8] = b"\x1b[?1049h";
const EXIT_ALT_SCREEN: &[u8] = b"\x1b[?1049l";

const TERMINAL_RESTORE_NORMAL: &[u8] = concat!(
    "\x1b[<u",                                                  // pop kitty keyboard flags
    "\x1b[>0n\x1b[>1n\x1b[>2n\x1b[>3n\x1b[>4n\x1b[>6n\x1b[>7n", // disable key reporting
    "\x1b[?1000l\x1b[?1002l\x1b[?1003l",                        // mouse tracking
    "\x1b[?1005l\x1b[?1006l\x1b[?1015l",                        // mouse encodings
    "\x1b[?1004l",                                              // focus events
    "\x1b[?2004l",                                              // bracketed paste
    "\x1b[?9001l",                                              // win32-input-mode
    "\x1b[?1l",                                                 // application cursor keys
    "\x1b>",                                                    // normal keypad
    "\x1b[?25h",                                                // show cursor
)
.as_bytes();

/// Tracks alternate-screen enter/exit in output, across chunk boundaries.
#[derive(Debug, Default)]
pub struct AltScreenTracker {
    in_alt_screen: bool,
    tail: Vec<u8>,
}

impl AltScreenTracker {
    /// Whether the last observed transition entered the alternate screen.
    pub fn in_alt_screen(&self) -> bool {
        self.in_alt_screen
    }

    /// Observe one chunk of output.
    pub fn observe(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut combined = std::mem::take(&mut self.tail);
        combined.extend_from_slice(bytes);
        let len = ENTER_ALT_SCREEN.len();
        let mut i = 0;
        while i + len <= combined.len() {
            let window = &combined[i..i + len];
            if window == ENTER_ALT_SCREEN {
                self.in_alt_screen = true;
                i += len;
            } else if window == EXIT_ALT_SCREEN {
                self.in_alt_screen = false;
                i += len;
            } else {
                i += 1;
            }
        }
        // Keep at most len - 1 bytes: enough to complete a split sequence.
        let keep_from = combined.len().saturating_sub(len - 1).max(i);
        self.tail = combined[keep_from..].to_vec();
    }
}

/// Bytes that return the local terminal to a sane shell state.
pub fn restore_escape(in_alt_screen: bool, rows: u16) -> Vec<u8> {
    let mut bytes = b"\x1b[?2026l\x1b[0m\x1b[r\x1b[?6l".to_vec();
    bytes.extend_from_slice(TERMINAL_RESTORE_NORMAL);
    if in_alt_screen {
        bytes.extend_from_slice(EXIT_ALT_SCREEN);
    }
    bytes.extend_from_slice(b"\x1b[0m\x1b[r\x1b[?6l");
    bytes.extend_from_slice(format!("\x1b[{}S\x1b[2J\x1b[H", rows.max(1)).as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_alt_screen_across_chunks() {
        let mut tracker = AltScreenTracker::default();
        tracker.observe(b"hello\x1b[?10");
        assert!(!tracker.in_alt_screen());
        tracker.observe(b"49hworld");
        assert!(tracker.in_alt_screen());
        tracker.observe(b"\x1b[?1049l");
        assert!(!tracker.in_alt_screen());
    }

    #[test]
    fn tail_stays_bounded() {
        let mut tracker = AltScreenTracker::default();
        tracker.observe(&[b'x'; 10_000]);
        assert!(tracker.tail.len() < ENTER_ALT_SCREEN.len());
    }

    #[test]
    fn restore_leaves_alt_screen_only_when_entered() {
        assert!(
            restore_escape(true, 24)
                .windows(EXIT_ALT_SCREEN.len())
                .any(|w| w == EXIT_ALT_SCREEN)
        );
        assert!(
            !restore_escape(false, 24)
                .windows(EXIT_ALT_SCREEN.len())
                .any(|w| w == EXIT_ALT_SCREEN)
        );
    }
}
