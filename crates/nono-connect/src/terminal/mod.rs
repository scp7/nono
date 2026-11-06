//! The local terminal: raw mode, size, input, output and resize events.
//!
//! "Local PTY" on Windows means the console the client runs in (Windows
//! Terminal or conhost) switched into virtual-terminal mode, so keystrokes
//! arrive as VT byte sequences and the hosted PTY's VT output renders
//! directly. No ConPTY is created: nothing runs locally except this client.
//!
//! Input is read and output is written on dedicated threads connected to the
//! async attach loop by bounded channels. Console reads cannot be cancelled
//! portably, so the input thread may outlive the attachment; the binary exits
//! the process right after the terminal is restored.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::error::{ConnectError, Result};
use crate::screen::{AltScreenTracker, restore_escape};
use crate::utf8::Utf8Carry;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(not(any(unix, windows)))]
compile_error!("nono-connect supports Unix and Windows terminals only");

const CHANNEL_DEPTH: usize = 64;
/// How long teardown waits for queued output before restoring the terminal.
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Alternate-screen state of the local terminal, for restoration from a
/// console control handler that cannot reach the [`TerminalSession`].
static IN_ALT_SCREEN: AtomicBool = AtomicBool::new(false);

/// Bytes that reset the local terminal's VT state for the current screen.
#[cfg(windows)]
fn current_restore_escape() -> Vec<u8> {
    restore_escape(IN_ALT_SCREEN.load(Ordering::Acquire), size().1)
}

/// Resolves when the process is asked to stop (SIGTERM/SIGHUP/SIGINT/SIGQUIT
/// on Unix, Ctrl-Break on Windows), so the attachment can detach and restore
/// the terminal instead of dying in raw mode.
pub struct Termination {
    inner: platform::TerminationSource,
}

impl Termination {
    /// Start listening.
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: platform::TerminationSource::new()?,
        })
    }

    /// Wait for a termination request.
    pub async fn requested(&mut self) {
        self.inner.wait().await;
    }
}

/// Whether stdin and stdout are both interactive terminals.
pub fn is_interactive() -> bool {
    use std::io::IsTerminal;
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

/// The visible terminal size as `(cols, rows)`, defaulting to 80x24.
pub fn size() -> (u16, u16) {
    platform::size().unwrap_or((80, 24))
}

/// Receives terminal size changes. Sizes are de-duplicated.
pub struct ResizeWatcher {
    inner: platform::ResizeSource,
    last: (u16, u16),
}

impl ResizeWatcher {
    /// Start watching, treating `initial` as already reported.
    pub fn new(initial: (u16, u16)) -> Result<Self> {
        Ok(Self {
            inner: platform::ResizeSource::new()?,
            last: initial,
        })
    }

    /// Record `size` as reported (for example after re-reading it once
    /// connected) and return it.
    pub fn mark_reported(&mut self, size: (u16, u16)) -> (u16, u16) {
        self.last = size;
        size
    }

    /// Wait for the next size change.
    pub async fn changed(&mut self) -> (u16, u16) {
        loop {
            self.inner.wait().await;
            let current = size();
            if current != self.last {
                self.last = current;
                return current;
            }
        }
    }
}

/// A raw-mode terminal attached to the hosted session.
///
/// Dropping it flushes pending output, writes the mode-reset escape, and
/// restores the original console/termios modes, in that order.
pub struct TerminalSession {
    raw: Option<platform::RawMode>,
    output: Option<mpsc::Sender<Vec<u8>>>,
    stopping: Arc<AtomicBool>,
    writer_done: std::sync::mpsc::Receiver<()>,
    input: mpsc::Receiver<io::Result<Vec<u8>>>,
    screen: AltScreenTracker,
}

impl TerminalSession {
    /// Enter raw/VT mode and start the input and output threads.
    pub fn start() -> Result<Self> {
        let raw = platform::RawMode::enter()?;
        let (input_tx, input) = mpsc::channel(CHANNEL_DEPTH);
        std::thread::Builder::new()
            .name("nono-connect-input".to_string())
            .spawn(move || input_thread(input_tx))
            .map_err(ConnectError::Io)?;
        let (output_tx, output_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (done_tx, writer_done) = std::sync::mpsc::channel();
        let stopping = Arc::new(AtomicBool::new(false));
        let writer_stopping = Arc::clone(&stopping);
        std::thread::Builder::new()
            .name("nono-connect-output".to_string())
            .spawn(move || {
                let _ = output_thread(output_rx, &writer_stopping);
                let _ = done_tx.send(());
            })
            .map_err(ConnectError::Io)?;
        IN_ALT_SCREEN.store(false, Ordering::Release);
        Ok(Self {
            raw: Some(raw),
            output: Some(output_tx),
            stopping,
            writer_done,
            input,
            screen: AltScreenTracker::default(),
        })
    }

    /// Next chunk of local input; `None` or an empty chunk means end of input.
    pub async fn read(&mut self) -> Option<io::Result<Vec<u8>>> {
        self.input.recv().await
    }

    /// Queue hosted-session output for the terminal.
    pub async fn write(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.screen.observe(&bytes);
        IN_ALT_SCREEN.store(self.screen.in_alt_screen(), Ordering::Release);
        let sender = self.output.as_ref().ok_or_else(closed_output)?;
        sender.send(bytes).await.map_err(|_| closed_output())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        // The writer owns the console output. Tell it to discard the backlog
        // (the restore escape clears the screen anyway) and write the restore
        // escape as its last act, so no hosted output can follow the reset.
        self.stopping.store(true, Ordering::Release);
        self.output.take();
        if self.writer_done.recv_timeout(OUTPUT_DRAIN_TIMEOUT).is_err() {
            // The console is stalled in a single write. Restore anyway rather
            // than leave raw mode on; at most that one in-flight chunk can
            // still land after the reset.
            let _ = platform::write_all(&restore_escape(self.screen.in_alt_screen(), size().1));
        }
        // Restore console/termios modes last, after the VT reset is out.
        self.raw.take();
    }
}

fn closed_output() -> ConnectError {
    ConnectError::Io(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "terminal output closed",
    ))
}

fn input_thread(sender: mpsc::Sender<io::Result<Vec<u8>>>) {
    let mut reader = platform::InputReader::new();
    loop {
        let chunk = reader.read();
        let stop = !matches!(&chunk, Ok(bytes) if !bytes.is_empty());
        if sender.blocking_send(chunk).is_err() || stop {
            return;
        }
    }
}

fn output_thread(mut receiver: mpsc::Receiver<Vec<u8>>, stopping: &AtomicBool) -> io::Result<()> {
    let mut carry = Utf8Carry::default();
    let mut screen = AltScreenTracker::default();
    while let Some(bytes) = receiver.blocking_recv() {
        if stopping.load(Ordering::Acquire) {
            break;
        }
        let ready = carry.push(&bytes);
        if !ready.is_empty() {
            screen.observe(&ready);
            platform::write_all(&ready)?;
        }
    }
    // Track what actually reached the terminal, not what was queued.
    platform::write_all(&restore_escape(screen.in_alt_screen(), size().1))
}
