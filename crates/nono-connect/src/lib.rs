//! Experimental portable client for nono remote terminal attach.
//!
//! Implements the client side of `docs/protocols/remote-attach-v1.md` with
//! no dependency on the `nono` sandbox library, so it builds on Windows. The
//! local machine only hosts the terminal; the session (and its sandbox) runs
//! on the nono platform. See `docs/experimental/windows-remote-connect.md`.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod attach;
pub mod credential;
pub mod detach;
pub mod error;
pub mod protocol;
pub mod sanitize;
pub mod screen;
pub mod sessions;
pub mod terminal;
pub mod urls;
pub mod utf8;

pub use error::{ConnectError, Result};
