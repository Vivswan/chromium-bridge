#![no_main]
//! Fuzz the native-messaging control-frame classifier: the router that decides
//! whether an extension-relayed frame is forwarded, handled locally, or
//! dropped. It transitively exercises the typed EnclaveControl / AdminControl
//! decodes, and the exhaustive match below makes a new disposition arm break
//! this target rather than silently escape fuzz coverage.
use libfuzzer_sys::fuzz_target;

use chromium_bridge_core::protocol::{classify_nm_frame, FrameDisposition};

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    match classify_nm_frame(&frame) {
        FrameDisposition::Forward
        | FrameDisposition::Challenge { .. }
        | FrameDisposition::RevokeHostKey
        | FrameDisposition::PresenceChallenge { .. }
        | FrameDisposition::ClientList
        | FrameDisposition::ClientRevoke { .. }
        | FrameDisposition::KillStatus
        | FrameDisposition::KillEngage
        | FrameDisposition::KillRelease
        | FrameDisposition::AuditEvent { .. }
        | FrameDisposition::Drop(_)
        | FrameDisposition::Malformed
        | FrameDisposition::MalformedPresence
        | FrameDisposition::MalformedAdmin(_) => {}
    }
});
