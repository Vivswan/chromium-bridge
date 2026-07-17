//! Per-OS mechanisms behind the ipc policy modules, one file per OS so the
//! platform-specific code (and its unsafe FFI) is not scattered through the
//! policy logic as cfg-gates:
//!
//! - [`linux`]: `/proc/<pid>/exe` SHA256 image identity + SO_PEERCRED peer
//!   credentials.
//! - [`macos`]: Security-framework code-signing identity (cdhash via the
//!   kernel audit token) + LOCAL_PEERPID peer credentials.
//! - [`windows`]: process handles (liveness/terminate) + BCrypt randomness.
//!   Windows has no image attestation (see SECURITY.md "Platform support").
//!
//! Selection is at compile time via cfg (there is exactly one implementation
//! per build, so a runtime trait object would add indirection for nothing).
//! The `os` alias names the current platform's identity mechanism where one
//! exists (Linux, macOS); [`super::attest`] is compiled only on those.

#[cfg(target_os = "linux")]
pub(super) mod linux;
#[cfg(target_os = "macos")]
pub(super) mod macos;
#[cfg(windows)]
pub(super) mod windows;

#[cfg(target_os = "linux")]
pub(super) use linux as os;
#[cfg(target_os = "macos")]
pub(super) use macos as os;
