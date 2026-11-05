//! Unix terminal backend: termios raw mode, TIOCGWINSZ, SIGWINCH.

use std::io::{self, Read, Write};

use nix::sys::termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr};
use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::error::{ConnectError, Result};

pub(super) fn size() -> Option<(u16, u16)> {
    let mut size = nix::libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes only the fixed-size `winsize` we pass, and
    // STDOUT_FILENO is a valid descriptor number for the life of the process.
    let result =
        unsafe { nix::libc::ioctl(nix::libc::STDOUT_FILENO, nix::libc::TIOCGWINSZ, &mut size) };
    (result == 0 && size.ws_col > 0 && size.ws_row > 0).then_some((size.ws_col, size.ws_row))
}

pub(super) fn write_all(bytes: &[u8]) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.flush()
}

pub(super) struct RawMode {
    original: Termios,
}

impl RawMode {
    pub(super) fn enter() -> Result<Self> {
        let stdin = io::stdin();
        let original = tcgetattr(&stdin).map_err(|error| {
            ConnectError::Config(format!("could not read terminal mode: {error}"))
        })?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(&stdin, SetArg::TCSANOW, &raw).map_err(|error| {
            ConnectError::Config(format!("could not enter raw terminal mode: {error}"))
        })?;
        Ok(Self { original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = tcsetattr(io::stdin(), SetArg::TCSADRAIN, &self.original);
    }
}

pub(super) struct InputReader {
    buffer: Vec<u8>,
}

impl InputReader {
    pub(super) fn new() -> Self {
        Self {
            buffer: vec![0; 8192],
        }
    }

    pub(super) fn read(&mut self) -> io::Result<Vec<u8>> {
        loop {
            match io::stdin().lock().read(&mut self.buffer) {
                Ok(read) => return Ok(self.buffer[..read].to_vec()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) struct ResizeSource {
    signal: Signal,
}

impl ResizeSource {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            signal: signal(SignalKind::window_change()).map_err(ConnectError::Io)?,
        })
    }

    pub(super) async fn wait(&mut self) {
        if self.signal.recv().await.is_none() {
            // The signal stream ended; never report again.
            std::future::pending::<()>().await;
        }
    }
}
