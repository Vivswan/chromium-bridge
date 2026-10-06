//! Per-OS mechanisms behind the ipc policy modules, one module per OS so the unsafe FFI is not scattered
//! through the policy logic as cfg-gates; each module's own doc names its mechanisms. The `os` alias names the
//! current platform's identity mechanism, the one [`super::attest`] measures with.

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
