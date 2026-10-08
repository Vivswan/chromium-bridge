//! One module per OS so the unsafe FFI is quarantined there instead of cfg-gated through the policy modules;
//! `os` is the current platform's module.

#[cfg(target_os = "linux")]
pub(super) mod linux;
#[cfg(target_os = "macos")]
pub(super) mod macos;
#[cfg(any(windows, test))]
pub(super) mod windows;

#[cfg(target_os = "linux")]
pub(super) use linux as os;
#[cfg(target_os = "macos")]
pub(super) use macos as os;
#[cfg(windows)]
pub(super) use windows as os;
