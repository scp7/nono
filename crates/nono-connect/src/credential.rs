//! Console credentials.
//!
//! Phase 1 of the experimental client accepts only an explicit bearer token:
//! `NONO_CONNECT_TOKEN`, or `--token-file` on Unix. `nono login` (DPoP) and
//! the enrolled-device flow need protected local key storage, which is not
//! yet designed for Windows; see `docs/experimental/windows-remote-connect.md`.

use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{ConnectError, Result};

/// Environment variable carrying a console bearer token.
pub const TOKEN_ENV: &str = "NONO_CONNECT_TOKEN";

const TOKEN_FILE_LIMIT_BYTES: u64 = 64 * 1024;

/// A short-lived console bearer token. Never printed.
pub struct BearerToken(Zeroizing<String>);

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

impl BearerToken {
    /// Validate a token. Only visible ASCII is accepted, so the value is
    /// always a valid HTTP header value and cannot smuggle header syntax.
    pub fn parse(value: &str) -> Result<Self> {
        let token = value.trim();
        if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(ConnectError::Config(
                "connect token is empty or contains whitespace or non-ASCII characters".to_string(),
            ));
        }
        Ok(Self(Zeroizing::new(token.to_string())))
    }

    /// The `Authorization` header value.
    pub fn authorization(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("Bearer {}", self.0.as_str()))
    }
}

/// Load the console credential: `--token-file` first, then `NONO_CONNECT_TOKEN`.
pub fn load(token_file: Option<&Path>) -> Result<BearerToken> {
    if let Some(path) = token_file {
        return load_file(path);
    }
    match std::env::var(TOKEN_ENV) {
        Ok(value) => BearerToken::parse(&Zeroizing::new(value)),
        Err(std::env::VarError::NotPresent) => Err(ConnectError::ActionRequired(format!(
            "no console credential: set {TOKEN_ENV} (or pass --token-file on Unix). \
             Browser sign-in is not available in this experimental client yet."
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConnectError::Config(format!(
            "{TOKEN_ENV} is not valid UTF-8"
        ))),
    }
}

/// Open once and validate the opened file (`fstat`), so the checks and the
/// read cannot be split by a path swap. `O_NONBLOCK` keeps a FIFO planted at
/// the path from blocking the open; regular-file reads ignore it. The read is
/// bounded independently of the size reported by `fstat`.
#[cfg(unix)]
fn load_file(path: &Path) -> Result<BearerToken> {
    use std::io::Read;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ConnectError::Config(
            "connect token path must be a regular file".to_string(),
        ));
    }
    if metadata.len() > TOKEN_FILE_LIMIT_BYTES {
        return Err(ConnectError::Config(
            "connect token file exceeds 64 KiB".to_string(),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ConnectError::ActionRequired(
            "connect token file must not be readable or writable by group/other (use mode 0600)"
                .to_string(),
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(TOKEN_FILE_LIMIT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > TOKEN_FILE_LIMIT_BYTES {
        return Err(ConnectError::Config(
            "connect token file exceeds 64 KiB".to_string(),
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ConnectError::Config("connect token file is not UTF-8".to_string()))?;
    BearerToken::parse(text)
}

/// Fail secure: on Windows the client cannot yet verify that a token file's
/// DACL excludes other principals, so it refuses the file rather than reading
/// a credential that may be exposed. The environment variable is per-process.
#[cfg(not(unix))]
fn load_file(_path: &Path) -> Result<BearerToken> {
    let _ = TOKEN_FILE_LIMIT_BYTES;
    Err(ConnectError::ActionRequired(format!(
        "--token-file is not supported on this platform yet: the client cannot verify the \
         file's access control list. Set {TOKEN_ENV} instead."
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tokens_must_be_visible_ascii() {
        assert!(BearerToken::parse("abc.def-123_~").is_ok());
        assert!(BearerToken::parse("  padded\n").is_ok());
        assert!(BearerToken::parse("").is_err());
        assert!(BearerToken::parse("a b").is_err());
        assert!(BearerToken::parse("a\r\nX-Evil: 1").is_err());
        assert!(BearerToken::parse("tökén").is_err());
    }

    #[test]
    fn debug_never_reveals_the_token() {
        let token = BearerToken::parse("super-secret").unwrap();
        assert!(!format!("{token:?}").contains("super-secret"));
        assert_eq!(token.authorization().as_str(), "Bearer super-secret");
    }

    #[cfg(unix)]
    #[test]
    fn token_files_must_be_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nono-connect-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "tok\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(Some(&path)).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(Some(&path)).is_ok());
        let fifo = dir.join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        assert!(
            load(Some(&fifo)).is_err(),
            "a FIFO must be refused without blocking"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
