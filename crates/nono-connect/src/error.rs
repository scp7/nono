//! Error type for the portable connect client.
//!
//! This crate deliberately does not depend on `nono` (the sandbox library):
//! the library has no Windows backend, and a remote-attach client applies no
//! local sandbox. Errors never carry credentials or captured terminal input.

/// Failures of the remote attach client.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The operator must do something (sign in, pass a flag, use a TTY).
    #[error("{0}")]
    ActionRequired(String),
    /// Invalid local configuration or arguments.
    #[error("{0}")]
    Config(String),
    /// The console or terminal stream violated remote-attach-v1.
    #[error("{0}")]
    Protocol(String),
    /// Network or TLS failure.
    #[error("{0}")]
    Transport(String),
    /// No remote session matched a selector.
    #[error("remote session '{0}' not found")]
    SessionNotFound(String),
    /// Local terminal or file I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, ConnectError>;
