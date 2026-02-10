//! C FFI bindings for the nono capability-based sandboxing library.
//!
//! Provides a stable C ABI for any language with C FFI support (Go, Swift,
//! Ruby, Java, C#, Zig, etc.).
//!
//! # Memory ownership
//!
//! - Opaque pointers (`NonoCapabilitySet*`, `NonoQueryContext*`,
//!   `NonoSandboxState*`) are caller-owned. Free with the corresponding
//!   `_free()` function. All `_free()` functions are NULL-safe.
//!
//! - Returned `char*` strings are caller-owned. Free with
//!   `nono_string_free()`. NULL is safe to pass.
//!
//! - `nono_last_error()` returns a library-owned pointer valid until the
//!   next failing FFI call on the same thread. Do NOT free it.
//!
//! - Input `const char*` parameters are borrowed. The library copies what
//!   it needs.

pub mod capability_set;
pub mod fs_capability;
pub mod query;
pub mod sandbox;
pub mod state;
pub mod types;

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// Re-export all public FFI symbols so they appear in the cdylib.
pub use capability_set::*;
pub use fs_capability::*;
pub use query::*;
pub use sandbox::*;
pub use state::*;
pub use types::*;

// ---------------------------------------------------------------------------
// Thread-local error store
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Store an error message for the current thread.
pub(crate) fn set_last_error(msg: &str) {
    LAST_ERROR.with(|cell| {
        let cstr = match CString::new(msg) {
            Ok(s) => s,
            Err(nul_err) => {
                let pos = nul_err.nul_position();
                let mut bytes = nul_err.into_vec();
                bytes.truncate(pos);
                match CString::new(bytes) {
                    Ok(s) => s,
                    Err(_) => return,
                }
            }
        };
        *cell.borrow_mut() = Some(cstr);
    });
}

/// Map a `NonoError` to an error code and store the message.
pub(crate) fn map_error(e: &nono::NonoError) -> types::NonoErrorCode {
    use types::NonoErrorCode;
    set_last_error(&e.to_string());
    match e {
        nono::NonoError::PathNotFound(_) => NonoErrorCode::ErrPathNotFound,
        nono::NonoError::ExpectedDirectory(_) => NonoErrorCode::ErrExpectedDirectory,
        nono::NonoError::ExpectedFile(_) => NonoErrorCode::ErrExpectedFile,
        nono::NonoError::PathCanonicalization { .. } => NonoErrorCode::ErrPathCanonicalization,
        nono::NonoError::NoCapabilities => NonoErrorCode::ErrNoCapabilities,
        nono::NonoError::SandboxInit(_) => NonoErrorCode::ErrSandboxInit,
        nono::NonoError::UnsupportedPlatform(_) => NonoErrorCode::ErrUnsupportedPlatform,
        nono::NonoError::BlockedCommand { .. } => NonoErrorCode::ErrBlockedCommand,
        nono::NonoError::ConfigParse(_) => NonoErrorCode::ErrConfigParse,
        nono::NonoError::ProfileParse(_) => NonoErrorCode::ErrProfileParse,
        nono::NonoError::Io(_) | nono::NonoError::CommandExecution(_) => NonoErrorCode::ErrIo,
        _ => NonoErrorCode::ErrUnknown,
    }
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

/// Convert a Rust `String` to a caller-owned C string.
///
/// Returns `null_mut` if the string cannot be represented (should not happen
/// in practice since nono strings are valid UTF-8).
pub(crate) fn rust_string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cstr) => cstr.into_raw(),
        Err(nul_err) => {
            let pos = nul_err.nul_position();
            let mut bytes = nul_err.into_vec();
            bytes.truncate(pos);
            match CString::new(bytes) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }
}

/// Convert a C string pointer to a Rust `&str`.
///
/// Returns `None` if the pointer is null or the string is not valid UTF-8.
///
/// # Safety
///
/// The pointer must be null or point to a valid null-terminated C string
/// that remains valid for the lifetime `'a`.
pub(crate) unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees ptr is a valid null-terminated C string.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

// ---------------------------------------------------------------------------
// Public FFI: Error and string management
// ---------------------------------------------------------------------------

/// Get the last error message for the current thread.
///
/// Returns a pointer to a null-terminated UTF-8 string describing the most
/// recent error, or NULL if no error has occurred.
///
/// The returned pointer is valid until the next failing nono FFI call on
/// the same thread. Callers must NOT free this pointer.
#[no_mangle]
pub extern "C" fn nono_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        let borrow = cell.borrow();
        match borrow.as_ref() {
            Some(cstr) => cstr.as_ptr(),
            None => std::ptr::null(),
        }
    })
}

/// Clear the last error for the current thread.
#[no_mangle]
pub extern "C" fn nono_clear_error() {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Free a string previously returned by a nono FFI function.
///
/// NULL-safe (no-op on NULL). Only call this on strings whose documentation
/// says "Caller must free with `nono_string_free()`".
///
/// Do NOT call this on the pointer from `nono_last_error()`.
///
/// # Safety
///
/// `s` must be NULL or a pointer previously returned by a nono FFI function.
#[no_mangle]
pub unsafe extern "C" fn nono_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: The pointer was created by CString::into_raw() in this
        // library. The caller is required to only pass pointers from nono
        // FFI functions.
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

/// Get the nono library version string.
///
/// Caller must free the returned string with `nono_string_free()`.
#[no_mangle]
pub extern "C" fn nono_version() -> *mut c_char {
    rust_string_to_c(env!("CARGO_PKG_VERSION").to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_last_error_initially_null() {
        nono_clear_error();
        assert!(nono_last_error().is_null());
    }

    #[test]
    fn test_set_and_get_error() {
        set_last_error("test error message");
        let ptr = nono_last_error();
        assert!(!ptr.is_null());
        // SAFETY: ptr is valid, just set above.
        let msg = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or_default();
        assert_eq!(msg, "test error message");
        nono_clear_error();
        assert!(nono_last_error().is_null());
    }

    #[test]
    fn test_string_free_null_safe() {
        // SAFETY: deliberate NULL.
        unsafe { nono_string_free(std::ptr::null_mut()) };
    }

    #[test]
    fn test_version_not_null() {
        let v = nono_version();
        assert!(!v.is_null());
        // SAFETY: v was just returned by nono_version().
        let s = unsafe { CStr::from_ptr(v) }.to_str().unwrap_or_default();
        assert!(!s.is_empty());
        // SAFETY: v was returned by nono_version().
        unsafe { nono_string_free(v) };
    }

    #[test]
    fn test_rust_string_to_c_roundtrip() {
        let original = "hello nono".to_string();
        let c_ptr = rust_string_to_c(original);
        assert!(!c_ptr.is_null());
        // SAFETY: c_ptr was just created from a valid Rust string.
        let recovered = unsafe { CStr::from_ptr(c_ptr) }
            .to_str()
            .unwrap_or_default();
        assert_eq!(recovered, "hello nono");
        // SAFETY: c_ptr was created by rust_string_to_c.
        unsafe { nono_string_free(c_ptr) };
    }
}
