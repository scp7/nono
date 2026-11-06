//! Strip terminal control sequences from console-controlled display text.

/// Remove CSI and string escape sequences, and replace other control
/// characters with spaces, so console metadata cannot drive the terminal.
pub fn sanitize_for_terminal(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    chars.next();
                    for seq_c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&seq_c) {
                            break;
                        }
                    }
                } else if matches!(next, ']' | 'P' | '_' | '^' | 'X') {
                    chars.next();
                    let mut prev = '\0';
                    for seq_c in chars.by_ref() {
                        if seq_c == '\x07' || (prev == '\x1b' && seq_c == '\\') {
                            break;
                        }
                        prev = seq_c;
                    }
                }
            }
            continue;
        }
        // `is_control` covers C0, DEL and C1 (including the 8-bit CSI U+009B);
        // bidi and invisible format characters could reorder or hide text.
        if c.is_control() || is_deceptive_format(c) {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

/// Bidirectional overrides/isolates, zero-width and line-separator
/// characters that can visually reorder or hide console-supplied text.
fn is_deceptive_format(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_escape_sequences_and_controls() {
        assert_eq!(sanitize_for_terminal("a\x1b[31mred\x1b[0m"), "ared");
        assert_eq!(sanitize_for_terminal("t\x1b]0;title\x07x"), "tx");
        assert_eq!(sanitize_for_terminal("t\x1b]52;c;Zm9v\x1b\\x"), "tx");
        assert_eq!(sanitize_for_terminal("a\rb\nc\u{9b}2J"), "a b c 2J");
        assert_eq!(sanitize_for_terminal("ab\u{202e}cd\u{200b}e"), "ab cd e");
        assert_eq!(sanitize_for_terminal("café ✓"), "café ✓");
    }
}
