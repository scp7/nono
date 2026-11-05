//! Windows console backend.
//!
//! Requires a console with virtual-terminal support (Windows 10 1809+:
//! Windows Terminal or conhost). The console is put into VT input/output
//! mode with UTF-8 code pages; every change is undone on drop, and also from
//! a console control handler so Ctrl-Break or closing the window does not
//! leave the shell's console in raw mode.
//!
//! Terminals that are not Windows consoles (mintty/MSYS pipes) fail
//! `GetConsoleMode` and are refused rather than half-supported.

use std::io;
use std::sync::Mutex;
use std::time::Duration;

use windows_sys::Win32::Foundation::{FALSE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT,
    CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT,
    ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleCP,
    GetConsoleMode, GetConsoleOutputCP, GetConsoleScreenBufferInfo, GetStdHandle, ReadConsoleW,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCP, SetConsoleCtrlHandler, SetConsoleMode,
    SetConsoleOutputCP,
};

use crate::error::{ConnectError, Result};

const CP_UTF8: u32 = 65001;
const RESIZE_POLL: Duration = Duration::from_millis(250);

/// Console state to restore. Shared with the control handler.
#[derive(Clone, Copy)]
struct SavedConsole {
    input: HANDLE,
    output: HANDLE,
    input_mode: CONSOLE_MODE,
    output_mode: CONSOLE_MODE,
    input_cp: u32,
    output_cp: u32,
}

// SAFETY: console handles are process-wide pseudo-handles owned by the
// process; using them from another thread (the control handler) is valid.
unsafe impl Send for SavedConsole {}

static SAVED: Mutex<Option<SavedConsole>> = Mutex::new(None);

fn std_handle(kind: u32) -> io::Result<HANDLE> {
    // SAFETY: GetStdHandle has no preconditions; it returns a borrowed handle.
    let handle = unsafe { GetStdHandle(kind) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no console handle is attached",
        ))
    } else {
        Ok(handle)
    }
}

fn console_mode(handle: HANDLE) -> io::Result<CONSOLE_MODE> {
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: `handle` came from GetStdHandle and `mode` is a valid out pointer.
    if unsafe { GetConsoleMode(handle, &mut mode) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    Ok(mode)
}

fn set_console_mode(handle: HANDLE, mode: CONSOLE_MODE) -> io::Result<()> {
    // SAFETY: `handle` came from GetStdHandle; SetConsoleMode only reads `mode`.
    if unsafe { SetConsoleMode(handle, mode) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn restore(saved: &SavedConsole) {
    // SAFETY: each call takes plain values captured from the same console.
    unsafe {
        SetConsoleMode(saved.input, saved.input_mode);
        SetConsoleMode(saved.output, saved.output_mode);
        SetConsoleCP(saved.input_cp);
        SetConsoleOutputCP(saved.output_cp);
    }
}

/// Restore the console if the process is being torn down by the console.
unsafe extern "system" fn control_handler(event: u32) -> i32 {
    if matches!(
        event,
        CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT
    ) && let Ok(guard) = SAVED.lock()
        && let Some(saved) = guard.as_ref()
    {
        restore(saved);
    }
    // Let the default handler terminate the process.
    FALSE
}

pub(super) fn size() -> Option<(u16, u16)> {
    let output = std_handle(STD_OUTPUT_HANDLE).ok()?;
    // SAFETY: CONSOLE_SCREEN_BUFFER_INFO is plain data; all-zero is valid.
    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: `output` is a console handle and `info` a valid out pointer.
    if unsafe { GetConsoleScreenBufferInfo(output, &mut info) } == FALSE {
        return None;
    }
    let window = info.srWindow;
    let cols = i32::from(window.Right) - i32::from(window.Left) + 1;
    let rows = i32::from(window.Bottom) - i32::from(window.Top) + 1;
    match (u16::try_from(cols), u16::try_from(rows)) {
        (Ok(cols), Ok(rows)) if cols > 0 && rows > 0 => Some((cols, rows)),
        _ => None,
    }
}

pub(super) fn write_all(mut bytes: &[u8]) -> io::Result<()> {
    let output = std_handle(STD_OUTPUT_HANDLE)?;
    while !bytes.is_empty() {
        let chunk = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let mut written = 0u32;
        // SAFETY: `bytes` is valid for `chunk` bytes, `written` is a valid
        // out pointer, and the handle is opened for synchronous I/O, so no
        // OVERLAPPED is required.
        let ok = unsafe {
            WriteFile(
                output,
                bytes.as_ptr(),
                chunk,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == FALSE {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "console accepted no output",
            ));
        }
        let advanced = usize::try_from(written)
            .unwrap_or(bytes.len())
            .min(bytes.len());
        bytes = &bytes[advanced..];
    }
    Ok(())
}

pub(super) struct RawMode {
    saved: SavedConsole,
}

impl RawMode {
    pub(super) fn enter() -> Result<Self> {
        let not_console = |error: io::Error| {
            ConnectError::ActionRequired(format!(
                "nono-connect needs a Windows console with VT support (Windows Terminal or \
                 conhost on Windows 10 1809+); this terminal is not one ({error})"
            ))
        };
        let input = std_handle(STD_INPUT_HANDLE).map_err(not_console)?;
        let output = std_handle(STD_OUTPUT_HANDLE).map_err(not_console)?;
        let input_mode = console_mode(input).map_err(not_console)?;
        let output_mode = console_mode(output).map_err(not_console)?;
        // SAFETY: no preconditions; these read the console's code pages.
        let (input_cp, output_cp) = unsafe { (GetConsoleCP(), GetConsoleOutputCP()) };
        let saved = SavedConsole {
            input,
            output,
            input_mode,
            output_mode,
            input_cp,
            output_cp,
        };
        // Register for restoration before changing anything.
        if let Ok(mut guard) = SAVED.lock() {
            *guard = Some(saved);
        }
        // SAFETY: `control_handler` is a valid `extern "system"` handler that
        // lives for the whole program.
        unsafe { SetConsoleCtrlHandler(Some(control_handler), 1) };
        let guard = Self { saved };

        // From here on, `guard`'s Drop restores the console on any failure.
        let raw_input = (input_mode
            & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        set_console_mode(input, raw_input).map_err(not_console)?;
        let vt_output = output_mode
            | ENABLE_PROCESSED_OUTPUT
            | ENABLE_VIRTUAL_TERMINAL_PROCESSING
            | DISABLE_NEWLINE_AUTO_RETURN;
        set_console_mode(output, vt_output).map_err(not_console)?;
        // SAFETY: no pointer arguments; failures are checked.
        if unsafe { SetConsoleCP(CP_UTF8) } == FALSE
            || unsafe { SetConsoleOutputCP(CP_UTF8) } == FALSE
        {
            return Err(not_console(io::Error::last_os_error()));
        }
        Ok(guard)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        restore(&self.saved);
        if let Ok(mut guard) = SAVED.lock() {
            *guard = None;
        }
        // SAFETY: removes the handler registered in `enter`.
        unsafe { SetConsoleCtrlHandler(Some(control_handler), FALSE) };
    }
}

/// Reads VT input as UTF-16 with `ReadConsoleW` and re-encodes it as UTF-8.
///
/// `ReadFile` under CP 65001 mangles non-ASCII input on older builds, and
/// `std::io::Stdin` treats a trailing Ctrl-Z as end of file, which would end
/// the attachment instead of forwarding the key. A high surrogate at the end
/// of one read is carried to the next.
pub(super) struct InputReader {
    units: Vec<u16>,
    pending_high: Option<u16>,
}

impl InputReader {
    pub(super) fn new() -> Self {
        Self {
            units: vec![0; 4096],
            pending_high: None,
        }
    }

    pub(super) fn read(&mut self) -> io::Result<Vec<u8>> {
        let input = std_handle(STD_INPUT_HANDLE)?;
        loop {
            let capacity = u32::try_from(self.units.len()).unwrap_or(u32::MAX);
            let mut read = 0u32;
            // SAFETY: `units` is valid for `capacity` UTF-16 units, `read` is
            // a valid out pointer, and a null input control is permitted.
            let ok = unsafe {
                ReadConsoleW(
                    input,
                    self.units.as_mut_ptr().cast(),
                    capacity,
                    &mut read,
                    std::ptr::null(),
                )
            };
            if ok == FALSE {
                return Err(io::Error::last_os_error());
            }
            let read = usize::try_from(read).unwrap_or(0).min(self.units.len());
            if read == 0 {
                // Spurious wake-up (e.g. a focus/resize record): read again.
                continue;
            }
            let mut units = Vec::with_capacity(read + 1);
            units.extend(self.pending_high.take());
            units.extend_from_slice(&self.units[..read]);
            if let Some(&last) = units.last()
                && (0xD800..0xDC00).contains(&last)
            {
                self.pending_high = units.pop();
            }
            if units.is_empty() {
                continue;
            }
            let text: String = char::decode_utf16(units)
                .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect();
            return Ok(text.into_bytes());
        }
    }
}

pub(super) struct ResizeSource {
    interval: tokio::time::Interval,
}

impl ResizeSource {
    pub(super) fn new() -> Result<Self> {
        // Window-buffer-size events are only delivered through
        // ReadConsoleInput, which would compete with the VT byte reader, so
        // poll the window size instead.
        let mut interval = tokio::time::interval(RESIZE_POLL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Ok(Self { interval })
    }

    pub(super) async fn wait(&mut self) {
        self.interval.tick().await;
    }
}
