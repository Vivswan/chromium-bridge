//! The peer is identified by its kernel audit token, which names the running image and so closes both the
//! path re-open TOCTOU and the pid-reuse race. cdhash exists for ad-hoc signatures too, so unsigned dev and
//! CI builds are enforceable. Raw FFI remains only where `security-framework` has no binding:
//! ```text
//! LOCAL_PEERPID / LOCAL_PEERTOKEN   -> libc getsockopt (no crate binds the macOS peer options)
//! SecCodeCheckValidity              -> the crate's method demands a requirement; ours is the null "signature only"
//! SecCodeCopySigningInformation     -> unbound, with its two info keys
//! ```
#![expect(
    unsafe_code,
    reason = "audited FFI quarantine: the two peer socket options and the two Security.framework calls the security-framework crate does not bind, each behind a safe wrapper"
)]

use std::io;

use core_foundation::base::{CFType, OSStatus, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::ConcreteCFType;
use security_framework::base::Error as SecError;
use security_framework::os::macos::code_signing::{Flags, GuestAttributes, SecCode};
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::code_signing::{SecCSFlags, SecCodeCheckValidity, SecStaticCodeRef};

use super::super::identity::{ClientIdentity, HashDigest, SignerId};
use super::super::socket::BridgeStream;

pub(crate) const OWN_IDENTITY_ERROR: &str = "cannot compute own code-directory hash";

pub(crate) fn own_identity() -> io::Result<HashDigest> {
    let me = SecCode::for_self(Flags::NONE).map_err(|e| sec_err("SecCodeCopySelf", e))?;
    Ok(validated_identity(&me, "self")?.hash)
}

/// Identified by its kernel audit token.
///
/// ```text
/// ENOPROTOOPT (no LOCAL_PEERTOKEN on this system) -> the pid path: still running-image-validated, but it
///                                                     reopens the narrow pid-reuse race
/// any other audit-token failure                   -> fails closed, never a silent downgrade
/// ```
pub(crate) fn peer_identity(stream: &BridgeStream) -> io::Result<HashDigest> {
    use std::os::unix::io::AsRawFd;

    match peer_audit_token(stream.as_raw_fd()) {
        Ok(token) => {
            let token = CFData::from_buffer(&token);
            let mut guest = GuestAttributes::new();
            guest.set_audit_token(token.as_concrete_TypeRef());
            Ok(guest_identity(&guest, "peer")?.hash)
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => {
            pid_identity(super::super::peercred::peer_pid(stream)?)
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn pid_identity(pid: u32) -> io::Result<HashDigest> {
    Ok(pid_client_identity(pid)?.hash)
}

/// Identified by pid, not audit token, so the narrow pid-reuse race applies; the running signature is still
/// validated.
pub(crate) fn pid_client_identity(pid: u32) -> io::Result<ClientIdentity> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pid out of range"))?;
    let mut guest = GuestAttributes::new();
    guest.set_pid(pid);
    guest_identity(&guest, "pid")
}

/// macOS has no SO_PEERCRED; LOCAL_PEERPID yields the pid of the process that opened the peer end.
pub(crate) fn peer_pid(fd: libc::c_int) -> io::Result<u32> {
    let mut pid: libc::pid_t = 0;
    let expected_len = libc::socklen_t::try_from(std::mem::size_of::<libc::pid_t>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pid_t size exceeds socklen_t"))?;
    let mut len = expected_len;
    // SAFETY: `pid` and `len` are live locals sized for LOCAL_PEERPID; an
    // invalid fd is reported through rc, never a wild write.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::from_mut(&mut pid).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected peer-pid size from LOCAL_PEERPID",
        ));
    }
    u32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "peer pid out of range"))
}

// From <sys/un.h>: getsockopt level/name for the peer's audit token.
const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERTOKEN: libc::c_int = 0x006;

// audit_token_t from <bsm/audit.h> is `unsigned int val[8]`; it is opaque to
// us and travels as its 32 bytes.
const AUDIT_TOKEN_LEN: usize = 32;

fn peer_audit_token(fd: libc::c_int) -> io::Result<[u8; AUDIT_TOKEN_LEN]> {
    let mut token = [0u8; AUDIT_TOKEN_LEN];
    let expected_len = libc::socklen_t::try_from(token.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "audit-token size exceeds socklen_t",
        )
    })?;
    let mut len = expected_len;
    // SAFETY: `token` and `len` are live locals sized for an audit_token_t; an
    // invalid fd is reported through rc, never a wild write.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected audit-token size from LOCAL_PEERTOKEN",
        ));
    }
    Ok(token)
}

/// `host = None` asks the kernel's own guest table, not a hosting app's.
fn guest_identity(guest: &GuestAttributes, what: &str) -> io::Result<ClientIdentity> {
    let code = SecCode::copy_guest_with_attribues(None, guest, Flags::NONE)
        .map_err(|e| sec_err("SecCodeCopyGuestWithAttributes", e))?;
    validated_identity(&code, what)
}

/// The validity check is the running-image-bound step: the code pages must match the signature of the process
/// actually executing. Its null requirement means "the signature alone, no anchor", which the crate's
/// `check_validity` cannot express.
fn validated_identity(code: &SecCode, what: &str) -> io::Result<ClientIdentity> {
    // SAFETY: `code` is a live SecCode held by the caller for the whole call;
    // a null requirement is allowed by the API and imposes no requirement.
    let st = unsafe {
        SecCodeCheckValidity(
            code.as_concrete_TypeRef(),
            Flags::NONE.bits(),
            std::ptr::null_mut(),
        )
    };
    if st != errSecSuccess {
        return Err(osstatus_err(&format!("SecCodeCheckValidity ({what})"), st));
    }
    signing_identity(code)
}

/// `kSecCSSigningInformation` makes the dictionary carry the Team ID; `kSecCodeInfoUnique` (the cdhash) is
/// present regardless. An ad-hoc image has no Team ID, so `signer` is `None` and the allowlist anchors on the
/// hash.
fn signing_identity(code: &SecCode) -> io::Result<ClientIdentity> {
    let info = signing_information(code)?;
    // SAFETY: a Security.framework constant, initialized before any Rust code
    // runs and never released.
    let unique = unsafe { kSecCodeInfoUnique };
    let cdhash: CFData = info_value(&info, unique).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "code has no cdhash (unsigned?)",
        )
    })?;
    let hash = HashDigest::try_from(cdhash.bytes()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("code-directory hash: {e}"),
        )
    })?;

    // SAFETY: a Security.framework constant, initialized before any Rust code
    // runs and never released.
    let team = unsafe { kSecCodeInfoTeamIdentifier };
    let signer =
        info_value::<CFString>(&info, team).and_then(|s| SignerId::try_from(s.to_string()).ok());

    Ok(ClientIdentity { hash, signer })
}

const SIGNING_INFORMATION_FLAGS: SecCSFlags = 0x2; // kSecCSSigningInformation

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
}

/// The signing-information dictionary of a dynamic `SecCode`, read directly
/// off it: SecCode.h accepts a `SecCodeRef` wherever a `SecStaticCodeRef` is
/// expected, so no static-code hop is needed.
fn signing_information(code: &SecCode) -> io::Result<CFDictionary<CFString, CFType>> {
    let mut info: CFDictionaryRef = std::ptr::null();
    // SAFETY: `code` is a live SecCode held by the caller; `info` is a live
    // local the +1 reference is written into.
    let st = unsafe {
        SecCodeCopySigningInformation(
            code.as_concrete_TypeRef().cast(),
            SIGNING_INFORMATION_FLAGS,
            &mut info,
        )
    };
    if st != errSecSuccess {
        return Err(osstatus_err("SecCodeCopySigningInformation", st));
    }
    if info.is_null() {
        return Err(io::Error::other(
            "SecCodeCopySigningInformation returned a null dictionary",
        ));
    }
    // SAFETY: a success status with the non-null `info` checked above is a +1
    // reference, which the wrapper releases exactly once on drop.
    Ok(unsafe { CFDictionary::wrap_under_create_rule(info) })
}

fn info_value<T: ConcreteCFType>(
    info: &CFDictionary<CFString, CFType>,
    key: CFStringRef,
) -> Option<T> {
    // SAFETY: `key` is a Security.framework constant string that is never
    // released; the get rule retains it for this wrapper's lifetime only.
    let key = unsafe { CFString::wrap_under_get_rule(key) };
    info.find(&key).and_then(|value| value.downcast::<T>())
}

fn sec_err(context: &str, e: SecError) -> io::Error {
    let message = e.message().map(|m| format!(": {m}")).unwrap_or_default();
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{context} failed (OSStatus {}{message})", e.code()),
    )
}

fn osstatus_err(context: &str, status: OSStatus) -> io::Error {
    sec_err(context, SecError::from_code(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_cdhash_equals_what_codesign_reports_for_the_running_image() {
        // External fact: `kSecCodeInfoUnique` read off the DYNAMIC SecCode is the image's cdhash, the value
        // Apple's codesign prints for the executable on disk; a read of another field would drift silently.
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new("codesign")
            .arg("-dvvv")
            .arg(&exe)
            .output()
            .expect("codesign runs on every macOS");
        // codesign writes its report to stderr.
        let report = String::from_utf8_lossy(&out.stderr);
        let reported = report
            .lines()
            .find_map(|l| l.strip_prefix("CDHash="))
            .unwrap_or_else(|| panic!("codesign reports a CDHash:\n{report}"));
        assert_eq!(own_identity().unwrap().as_str(), reported);
    }

    #[test]
    fn a_pid_identity_carries_the_same_hash_as_the_audit_token_path() {
        // External fact: the kernel resolves the audit-token and pid guests of one process to the same image,
        // so the ENOPROTOOPT fallback attests the same value; the token is read directly, so a fallback
        // cannot make both sides the pid path.
        use std::os::unix::io::AsRawFd;

        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let token = peer_audit_token(a.as_raw_fd()).expect("LOCAL_PEERTOKEN is supported here");
        let token = CFData::from_buffer(&token);
        let mut guest = GuestAttributes::new();
        guest.set_audit_token(token.as_concrete_TypeRef());
        let by_token = guest_identity(&guest, "peer").unwrap();
        let by_pid = pid_client_identity(std::process::id()).unwrap();
        assert_eq!(by_pid, by_token);
        assert_eq!(by_pid.hash, own_identity().unwrap());
    }
}
