//! macOS mechanisms: running-image-bound peer attestation via the Security
//! framework - identify the peer by its kernel audit token, validate its
//! dynamic code signature, and read its code-directory hash (cdhash) - plus
//! peer credentials via `LOCAL_PEERPID`. Unlike re-opening a path, the audit
//! token names the running image, so this closes both the path re-open TOCTOU
//! and the pid-reuse race. cdhash works for ad-hoc-signed builds (it is the
//! hash of the code pages), so it is enforceable on unsigned dev and CI
//! binaries too; Team-ID / designated-requirement pinning is the follow-up for
//! when a real signing identity lands. All FFI is hand-declared to avoid
//! adding crates (keeps cargo-deny clean). See ADR-0020.
// Quarantined unsafe: Security.framework and libc FFI (audit-token peer
// identity, code-signature validation). unsafe_code is denied workspace-wide;
// this module is one of the audited exceptions.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;

use super::super::socket::BridgeStream;

/// Error message for an unmeasurable self identity, used by
/// [`super::super::attest`].
pub(crate) const OWN_IDENTITY_ERROR: &str = "cannot compute own code-directory hash";

/// This process's own executable identity: the cdhash of its running image.
pub(crate) fn own_identity() -> io::Result<String> {
    own_cdhash()
}

/// The peer's running-image identity, measured the same way as
/// [`own_identity`].
pub(crate) fn peer_identity(stream: &BridgeStream) -> io::Result<String> {
    peer_cdhash(stream)
}

/// The running-image identity of an arbitrary process named by pid. Carries
/// the pid-reuse race documented on [`super::super::peercred::peer_pid`].
pub(crate) fn pid_identity(pid: u32) -> io::Result<String> {
    pid_cdhash(pid)
}

/// The full client identity of an arbitrary process named by pid: its running
/// image's `cdhash` plus its signing Team ID when the image is Team-ID signed.
/// Used to attest the harness (parent) for the trusted-client allowlist. Like
/// [`pid_identity`] this identifies the guest by pid (not audit token), so it
/// carries the narrow pid-reuse race recorded in ADR-0020; the running
/// signature is still validated via `SecCodeCheckValidity`.
pub(crate) fn pid_client_identity(pid: u32) -> io::Result<super::super::ClientIdentity> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pid out of range"))?;
    let num = unsafe {
        CFNumberCreate(
            kCFAllocatorDefault,
            KCF_NUMBER_SINT32,
            (&pid as *const libc::pid_t).cast(),
        )
    };
    if num.is_null() {
        return Err(io::Error::other("CFNumberCreate for pid failed"));
    }
    let num = Cf(num);
    guest_client_identity(GuestKey::Pid, &num)
}

/// The PID of the peer of a connected Unix-domain socket. macOS has no
/// SO_PEERCRED pid; LOCAL_PEERPID on the AF_UNIX socket yields the pid of the
/// process that opened the peer end.
pub(crate) fn peer_pid(fd: libc::c_int) -> io::Result<u32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::pid_t>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected peer-pid size from LOCAL_PEERPID",
        ));
    }
    u32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "peer pid out of range"))
}

type CFTypeRef = *const c_void;
type CFAllocatorRef = *const c_void;
type CFDataRef = *const c_void;
type CFStringRef = *const c_void;
type CFNumberRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFIndex = isize;
type OSStatus = i32;
type SecCSFlags = u32;
type SecCodeRef = *mut c_void;
type SecStaticCodeRef = *mut c_void;

const DEFAULT_FLAGS: SecCSFlags = 0; // kSecCSDefaultFlags
const SIGNING_INFORMATION_FLAGS: SecCSFlags = 0x2; // kSecCSSigningInformation
const ERR_SEC_SUCCESS: OSStatus = 0;
const KCF_NUMBER_SINT32: CFIndex = 3; // kCFNumberSInt32Type
const KCF_STRING_ENCODING_UTF8: u32 = 0x0800_0100; // kCFStringEncodingUTF8

// From <sys/un.h>: getsockopt level/name for the peer's audit token.
const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERTOKEN: libc::c_int = 0x006;

// audit_token_t from <bsm/audit.h> is `unsigned int val[8]`, layout-identical
// to `[u32; 8]`; we treat it as opaque bytes and never read the fields.
const AUDIT_TOKEN_LEN: usize = 8;

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFAllocatorDefault: CFAllocatorRef;
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
    fn CFRelease(cf: CFTypeRef);
    fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
    fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    fn CFDataGetLength(data: CFDataRef) -> CFIndex;
    fn CFNumberCreate(
        allocator: CFAllocatorRef,
        the_type: CFIndex,
        value_ptr: *const c_void,
    ) -> CFNumberRef;
    fn CFDictionaryCreate(
        allocator: CFAllocatorRef,
        keys: *const *const c_void,
        values: *const *const c_void,
        num_values: CFIndex,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFDictionaryRef;
    fn CFDictionaryGetValue(dict: CFDictionaryRef, key: *const c_void) -> *const c_void;
    fn CFStringGetCString(
        the_string: CFStringRef,
        buffer: *mut std::os::raw::c_char,
        buffer_size: CFIndex,
        encoding: u32,
    ) -> u8;
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecGuestAttributeAudit: CFStringRef;
    static kSecGuestAttributePid: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    fn SecCodeCopySelf(flags: SecCSFlags, self_out: *mut SecCodeRef) -> OSStatus;
    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: SecCSFlags,
        guest: *mut SecCodeRef,
    ) -> OSStatus;
    fn SecCodeCopyStaticCode(
        code: SecCodeRef,
        flags: SecCSFlags,
        static_out: *mut SecStaticCodeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(
        code: SecCodeRef,
        flags: SecCSFlags,
        requirement: *const c_void,
    ) -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
}

/// Owns a +1 Core Foundation reference and releases it on drop, so every early
/// return on the error paths below still balances its retain. Invariant: the
/// wrapped pointer is a live CF object the caller owns (+1, null-checked at
/// every construction site), which is what lets [`guest_cdhash`] and
/// [`guest_client_identity`] accept `&Cf` from safe code.
struct Cf(CFTypeRef);

impl Drop for Cf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

enum GuestKey {
    Audit,
    Pid,
}

fn osstatus_err(context: &str, status: OSStatus) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{context} failed (OSStatus {status})"),
    )
}

/// The cdhash of THIS process's running image.
fn own_cdhash() -> io::Result<String> {
    let mut me: SecCodeRef = std::ptr::null_mut();
    let st = unsafe { SecCodeCopySelf(DEFAULT_FLAGS, &mut me) };
    if st != ERR_SEC_SUCCESS {
        return Err(osstatus_err("SecCodeCopySelf", st));
    }
    if me.is_null() {
        return Err(io::Error::other("SecCodeCopySelf returned null on success"));
    }
    let _me = Cf(me as CFTypeRef);
    validate_and_cdhash(me, "self")
}

/// The cdhash of the process on the other end of `stream`, identified by its
/// kernel audit token so the measurement binds to the running image (closing
/// the path re-open TOCTOU and the pid-reuse race). We fall back to
/// identifying by pid ONLY when the kernel reports the audit-token option
/// itself is unsupported (`ENOPROTOOPT`, older systems without
/// `LOCAL_PEERTOKEN`); the pid path is still running-image-validated by
/// `SecCodeCheckValidity` but reopens the narrow pid-reuse race (ADR-0020).
/// Any OTHER audit-token failure (short read, permission error) fails closed
/// rather than silently downgrading.
fn peer_cdhash(stream: &BridgeStream) -> io::Result<String> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    match peer_audit_token(fd) {
        Ok(token) => peer_cdhash_via_audit(&token),
        Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => {
            pid_cdhash(super::super::peercred::peer_pid(stream)?)
        }
        Err(e) => Err(e),
    }
}

fn peer_audit_token(fd: libc::c_int) -> io::Result<[u32; AUDIT_TOKEN_LEN]> {
    let mut token = [0u32; AUDIT_TOKEN_LEN];
    let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
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
    if len as usize != std::mem::size_of_val(&token) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected audit-token size from LOCAL_PEERTOKEN",
        ));
    }
    Ok(token)
}

fn peer_cdhash_via_audit(token: &[u32; AUDIT_TOKEN_LEN]) -> io::Result<String> {
    let bytes = unsafe {
        std::slice::from_raw_parts(token.as_ptr().cast::<u8>(), std::mem::size_of_val(token))
    };
    let data = unsafe { CFDataCreate(kCFAllocatorDefault, bytes.as_ptr(), bytes.len() as CFIndex) };
    if data.is_null() {
        return Err(io::Error::other("CFDataCreate for audit token failed"));
    }
    let data = Cf(data);
    guest_cdhash(GuestKey::Audit, &data)
}

/// The cdhash of the running image of the process named by `pid`,
/// validated by `SecCodeCheckValidity`. Also the audit-token fallback for
/// [`peer_cdhash`], and the pid-keyed identity behind
/// [`super::super::attest::attest_pid`]; identifying by pid (rather than
/// audit token) reopens the narrow pid-reuse race recorded in ADR-0020.
fn pid_cdhash(pid: u32) -> io::Result<String> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pid out of range"))?;
    let num = unsafe {
        CFNumberCreate(
            kCFAllocatorDefault,
            KCF_NUMBER_SINT32,
            (&pid as *const libc::pid_t).cast(),
        )
    };
    if num.is_null() {
        return Err(io::Error::other("CFNumberCreate for pid failed"));
    }
    let num = Cf(num);
    guest_cdhash(GuestKey::Pid, &num)
}

/// Build the one-entry guest-attribute dictionary, copy the peer's SecCode,
/// validate its running signature, and return its cdhash. Taking `&Cf` (not a
/// raw `CFTypeRef`) makes the caller's ownership guard carry the live-object
/// invariant that `CFDictionaryCreate`'s retaining callbacks rely on.
fn guest_cdhash(key: GuestKey, value: &Cf) -> io::Result<String> {
    let key_ref = unsafe {
        match key {
            GuestKey::Audit => kSecGuestAttributeAudit,
            GuestKey::Pid => kSecGuestAttributePid,
        }
    };
    let keys: [*const c_void; 1] = [key_ref];
    let values: [*const c_void; 1] = [value.0];
    let attrs = unsafe {
        CFDictionaryCreate(
            kCFAllocatorDefault,
            keys.as_ptr(),
            values.as_ptr(),
            1,
            std::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks),
            std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
        )
    };
    if attrs.is_null() {
        return Err(io::Error::other(
            "CFDictionaryCreate for guest attributes failed",
        ));
    }
    let _attrs = Cf(attrs);

    let mut guest: SecCodeRef = std::ptr::null_mut();
    let st = unsafe {
        SecCodeCopyGuestWithAttributes(std::ptr::null_mut(), attrs, DEFAULT_FLAGS, &mut guest)
    };
    if st != ERR_SEC_SUCCESS {
        return Err(osstatus_err("SecCodeCopyGuestWithAttributes", st));
    }
    if guest.is_null() {
        return Err(io::Error::other(
            "SecCodeCopyGuestWithAttributes returned null on success",
        ));
    }
    let _guest = Cf(guest as CFTypeRef);

    validate_and_cdhash(guest, "peer")
}

/// Like [`guest_cdhash`], but returns the guest's full client identity
/// (cdhash + Team ID). Builds the same one-entry guest-attribute dictionary,
/// copies and validates the peer's `SecCode`, and reads both signing fields.
fn guest_client_identity(key: GuestKey, value: &Cf) -> io::Result<super::super::ClientIdentity> {
    let key_ref = unsafe {
        match key {
            GuestKey::Audit => kSecGuestAttributeAudit,
            GuestKey::Pid => kSecGuestAttributePid,
        }
    };
    let keys: [*const c_void; 1] = [key_ref];
    let values: [*const c_void; 1] = [value.0];
    let attrs = unsafe {
        CFDictionaryCreate(
            kCFAllocatorDefault,
            keys.as_ptr(),
            values.as_ptr(),
            1,
            std::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks),
            std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
        )
    };
    if attrs.is_null() {
        return Err(io::Error::other(
            "CFDictionaryCreate for guest attributes failed",
        ));
    }
    let _attrs = Cf(attrs);

    let mut guest: SecCodeRef = std::ptr::null_mut();
    let st = unsafe {
        SecCodeCopyGuestWithAttributes(std::ptr::null_mut(), attrs, DEFAULT_FLAGS, &mut guest)
    };
    if st != ERR_SEC_SUCCESS {
        return Err(osstatus_err("SecCodeCopyGuestWithAttributes", st));
    }
    if guest.is_null() {
        return Err(io::Error::other(
            "SecCodeCopyGuestWithAttributes returned null on success",
        ));
    }
    let _guest = Cf(guest as CFTypeRef);

    let st = unsafe { SecCodeCheckValidity(guest, DEFAULT_FLAGS, std::ptr::null()) };
    if st != ERR_SEC_SUCCESS {
        return Err(osstatus_err("SecCodeCheckValidity (harness)", st));
    }
    signing_identity_of_code(guest)
}

/// Validate a dynamic `SecCode`'s running signature, then return its cdhash.
/// The validity check is the running-image-bound step: it verifies the code
/// pages match the signature of the process actually executing.
fn validate_and_cdhash(code: SecCodeRef, what: &str) -> io::Result<String> {
    let st = unsafe { SecCodeCheckValidity(code, DEFAULT_FLAGS, std::ptr::null()) };
    if st != ERR_SEC_SUCCESS {
        return Err(osstatus_err(&format!("SecCodeCheckValidity ({what})"), st));
    }
    cdhash_of_code(code)
}

fn cdhash_of_code(code: SecCodeRef) -> io::Result<String> {
    let mut static_code: SecStaticCodeRef = std::ptr::null_mut();
    let st = unsafe { SecCodeCopyStaticCode(code, DEFAULT_FLAGS, &mut static_code) };
    if st != ERR_SEC_SUCCESS {
        return Err(osstatus_err("SecCodeCopyStaticCode", st));
    }
    if static_code.is_null() {
        return Err(io::Error::other(
            "SecCodeCopyStaticCode returned null on success",
        ));
    }
    let _static = Cf(static_code as CFTypeRef);

    let mut info: CFDictionaryRef = std::ptr::null();
    let st = unsafe { SecCodeCopySigningInformation(static_code, DEFAULT_FLAGS, &mut info) };
    if st != ERR_SEC_SUCCESS {
        return Err(osstatus_err("SecCodeCopySigningInformation", st));
    }
    if info.is_null() {
        return Err(io::Error::other(
            "SecCodeCopySigningInformation returned null on success",
        ));
    }
    let _info = Cf(info);

    // Borrowed reference (Get-rule): do not release.
    let cdhash = unsafe { CFDictionaryGetValue(info, kSecCodeInfoUnique) } as CFDataRef;
    if cdhash.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "code has no cdhash (unsigned?)",
        ));
    }
    let len = unsafe { CFDataGetLength(cdhash) };
    let ptr = unsafe { CFDataGetBytePtr(cdhash) };
    if len <= 0 || ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "code-directory hash is empty",
        ));
    }
    // SAFETY: ptr/len come from the CFData owned by the `_info` guard above,
    // and were just checked non-null/positive; the borrow must not outlive
    // `_info`, so the slice is hex-encoded before this function returns.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    Ok(super::super::rand::hex_encode(bytes))
}

/// Read a validated `SecCode`'s full signing identity: its `cdhash` (required)
/// and its Team ID (optional). Uses `kSecCSSigningInformation` so the signing
/// dictionary carries the Team ID; `kSecCodeInfoUnique` (the cdhash) is present
/// regardless. An unsigned / ad-hoc image has no Team ID, so `team_id` is
/// `None` and the allowlist must anchor it on the hash instead.
fn signing_identity_of_code(code: SecCodeRef) -> io::Result<super::super::ClientIdentity> {
    let mut static_code: SecStaticCodeRef = std::ptr::null_mut();
    let st = unsafe { SecCodeCopyStaticCode(code, DEFAULT_FLAGS, &mut static_code) };
    if st != ERR_SEC_SUCCESS {
        return Err(osstatus_err("SecCodeCopyStaticCode", st));
    }
    if static_code.is_null() {
        return Err(io::Error::other(
            "SecCodeCopyStaticCode returned null on success",
        ));
    }
    let _static = Cf(static_code as CFTypeRef);

    let mut info: CFDictionaryRef = std::ptr::null();
    let st =
        unsafe { SecCodeCopySigningInformation(static_code, SIGNING_INFORMATION_FLAGS, &mut info) };
    if st != ERR_SEC_SUCCESS {
        return Err(osstatus_err("SecCodeCopySigningInformation", st));
    }
    if info.is_null() {
        return Err(io::Error::other(
            "SecCodeCopySigningInformation returned null on success",
        ));
    }
    let _info = Cf(info);

    // cdhash (borrowed Get-rule references; do not release).
    let cdhash = unsafe { CFDictionaryGetValue(info, kSecCodeInfoUnique) } as CFDataRef;
    if cdhash.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "code has no cdhash (unsigned?)",
        ));
    }
    let len = unsafe { CFDataGetLength(cdhash) };
    let ptr = unsafe { CFDataGetBytePtr(cdhash) };
    if len <= 0 || ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "code-directory hash is empty",
        ));
    }
    // SAFETY: ptr/len come from the CFData owned by the `_info` guard above,
    // and were just checked non-null/positive; the borrow must not outlive
    // `_info`, so the slice is consumed by hex_encode within this expression.
    let hash =
        super::super::rand::hex_encode(unsafe { std::slice::from_raw_parts(ptr, len as usize) });

    // Team ID is optional: ad-hoc / unsigned images simply lack it.
    let team_ref = unsafe { CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier) } as CFStringRef;
    let team_id = cfstring_to_string(team_ref).filter(|s| !s.is_empty());

    Ok(super::super::ClientIdentity { hash, team_id })
}

/// Copy a `CFString` into an owned Rust `String` (UTF-8), or `None` if the
/// reference is null or the copy fails. A fixed 256-byte buffer is ample for a
/// 10-character Team ID; a value that would not fit is treated as absent rather
/// than truncated.
fn cfstring_to_string(s: CFStringRef) -> Option<String> {
    if s.is_null() {
        return None;
    }
    let mut buf = [0i8; 256];
    let ok = unsafe {
        CFStringGetCString(
            s,
            buf.as_mut_ptr(),
            buf.len() as CFIndex,
            KCF_STRING_ENCODING_UTF8,
        )
    };
    if ok == 0 {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    cstr.to_str().ok().map(str::to_string)
}
