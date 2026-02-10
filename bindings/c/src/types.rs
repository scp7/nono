//! C-compatible types for the nono FFI layer.
//!
//! All types here use `#[repr(C)]` for stable ABI layout.

use std::os::raw::c_char;

/// Access mode for filesystem capabilities.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonoAccessMode {
    /// Read-only access
    Read = 0,
    /// Write-only access
    Write = 1,
    /// Read and write access
    ReadWrite = 2,
}

impl From<NonoAccessMode> for nono::AccessMode {
    fn from(mode: NonoAccessMode) -> Self {
        match mode {
            NonoAccessMode::Read => nono::AccessMode::Read,
            NonoAccessMode::Write => nono::AccessMode::Write,
            NonoAccessMode::ReadWrite => nono::AccessMode::ReadWrite,
        }
    }
}

impl From<nono::AccessMode> for NonoAccessMode {
    fn from(mode: nono::AccessMode) -> Self {
        match mode {
            nono::AccessMode::Read => NonoAccessMode::Read,
            nono::AccessMode::Write => NonoAccessMode::Write,
            nono::AccessMode::ReadWrite => NonoAccessMode::ReadWrite,
        }
    }
}

/// Tag for capability source discriminant.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonoCapabilitySourceTag {
    /// Added directly by the user
    User = 0,
    /// Resolved from a named policy group
    Group = 1,
    /// System-level path
    System = 2,
}

/// Status of a query result.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonoQueryStatus {
    Allowed = 0,
    Denied = 1,
}

/// Reason code for a query result.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonoQueryReason {
    /// Path is covered by a granted capability
    GrantedPath = 0,
    /// Network access is not blocked
    NetworkAllowed = 1,
    /// Path not covered by any capability
    PathNotGranted = 2,
    /// Path covered but with insufficient access level
    InsufficientAccess = 3,
    /// Network access is blocked
    NetworkBlocked = 4,
}

/// Result of a permission query.
///
/// String fields are nullable. Non-NULL string fields are caller-owned
/// and must be freed with `nono_string_free()`.
#[repr(C)]
pub struct NonoQueryResult {
    /// Whether the operation is allowed or denied.
    pub status: NonoQueryStatus,
    /// The specific reason.
    pub reason: NonoQueryReason,
    /// For `GrantedPath`: the path that grants access. NULL otherwise.
    pub granted_path: *mut c_char,
    /// For `GrantedPath`: the access mode string. NULL otherwise.
    pub access: *mut c_char,
    /// For `InsufficientAccess`: the granted access mode. NULL otherwise.
    pub granted: *mut c_char,
    /// For `InsufficientAccess`: the requested access mode. NULL otherwise.
    pub requested: *mut c_char,
}

/// Platform support information.
///
/// Returned by `nono_sandbox_support_info()`.
/// Caller must free string fields with `nono_string_free()`.
#[repr(C)]
pub struct NonoSupportInfo {
    /// Whether sandboxing is supported on this platform.
    pub is_supported: bool,
    /// Platform name. Caller must free with `nono_string_free()`.
    pub platform: *mut c_char,
    /// Detailed support information. Caller must free with `nono_string_free()`.
    pub details: *mut c_char,
}

/// Error codes returned by nono FFI functions.
///
/// Zero means success. Negative values indicate error categories.
/// Call `nono_last_error()` for the detailed error message.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonoErrorCode {
    /// Operation succeeded.
    Ok = 0,
    /// Path does not exist.
    ErrPathNotFound = -1,
    /// Expected a directory but got a file.
    ErrExpectedDirectory = -2,
    /// Expected a file but got a directory.
    ErrExpectedFile = -3,
    /// Path canonicalization failed.
    ErrPathCanonicalization = -4,
    /// No capabilities specified.
    ErrNoCapabilities = -5,
    /// Sandbox initialization failed.
    ErrSandboxInit = -6,
    /// Platform not supported.
    ErrUnsupportedPlatform = -7,
    /// Command is blocked.
    ErrBlockedCommand = -8,
    /// Configuration parse error.
    ErrConfigParse = -9,
    /// Profile parse error.
    ErrProfileParse = -10,
    /// I/O error.
    ErrIo = -11,
    /// Invalid argument (NULL pointer, invalid UTF-8).
    ErrInvalidArg = -12,
    /// Unknown or uncategorized error.
    ErrUnknown = -99,
}
