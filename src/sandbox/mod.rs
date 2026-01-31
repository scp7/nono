use crate::capability::CapabilitySet;
use crate::error::Result;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

/// Apply the sandbox with the given capabilities.
///
/// This function applies OS-level restrictions that cannot be undone.
/// After calling this, the current process (and all children) will
/// only be able to access resources granted by the capabilities.
pub fn apply(caps: &CapabilitySet) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::apply(caps)
    }

    #[cfg(target_os = "macos")]
    {
        macos::apply(caps)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(crate::error::NonoError::UnsupportedPlatform(
            std::env::consts::OS.to_string(),
        ))
    }
}

/// Check if sandboxing is supported on this platform
pub fn is_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::is_supported()
    }

    #[cfg(target_os = "macos")]
    {
        macos::is_supported()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Get information about sandbox support on this platform
pub fn support_info() -> String {
    #[cfg(target_os = "linux")]
    {
        linux::support_info()
    }

    #[cfg(target_os = "macos")]
    {
        macos::support_info()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        format!("Platform '{}' is not supported", std::env::consts::OS)
    }
}
