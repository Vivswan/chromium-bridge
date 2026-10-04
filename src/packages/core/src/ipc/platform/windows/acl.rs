//! The pipe's security descriptor: the current user's SID, rendered to the SDDL
//! text of [`super::user_only_sddl`] and parsed back by Windows into a
//! descriptor the pipe instances are created with. Admission to the pipe is
//! then kernel-enforced at `CreateFileW`, before any byte reaches the broker.
#![expect(
    unsafe_code,
    reason = "audited FFI quarantine: the token, SID, and SDDL calls, each behind a safe wrapper"
)]

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, HandleOrNull, OwnedHandle};
use std::ptr;

use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{user_only_sddl, SidString};

/// A security descriptor admitting the current user alone, kept alive for as
/// long as the pipe listener that hands it to `CreateNamedPipeW`.
pub(crate) struct UserOnlyDescriptor {
    #[expect(
        dead_code,
        reason = "held for the LocalFree its Drop performs; `attributes` points into it"
    )]
    descriptor: LocalAllocated<c_void>,
    attributes: SECURITY_ATTRIBUTES,
}

impl UserOnlyDescriptor {
    pub(crate) fn for_current_user() -> io::Result<UserOnlyDescriptor> {
        let sddl = wide(&user_only_sddl(&current_user_sid()?));
        let mut raw: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl` is a live NUL-terminated buffer; `raw` is a live local
        // the call writes a LocalAlloc'd descriptor into, freed once by
        // LocalAllocated's Drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = LocalAllocated(raw);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| io::Error::other("SECURITY_ATTRIBUTES size exceeds u32"))?,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        Ok(UserOnlyDescriptor {
            descriptor,
            attributes,
        })
    }

    /// The attributes to pass to `CreateNamedPipeW`; they point into `self`.
    pub(crate) fn attributes(&self) -> *const SECURITY_ATTRIBUTES {
        &self.attributes
    }
}

// SAFETY: the descriptor allocation is owned by this value alone and the
// attributes point at nothing else, so moving it to the accept thread moves
// the only reference.
unsafe impl Send for UserOnlyDescriptor {}

/// The current user's SID, read off this process's own token.
fn current_user_sid() -> io::Result<SidString> {
    let token = own_token()?;
    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 is the documented size query;
    // `needed` is a live local for the reported size.
    let _ = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    let len =
        usize::try_from(needed).map_err(|_| io::Error::other("TokenUser size exceeds usize"))?;
    if len < std::mem::size_of::<TOKEN_USER>() {
        return Err(io::Error::other("TokenUser size query reported no user"));
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` is a live allocation of exactly the `needed` bytes the
    // query reported; `needed` receives the written size.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful TokenUser query places a TOKEN_USER at the start of
    // `buf`, which the length check above proves is large enough to hold one.
    let user: TOKEN_USER = unsafe { ptr::read_unaligned(buf.as_ptr().cast()) };
    let mut text: PWSTR = ptr::null_mut();
    // SAFETY: `user.Sid` points into the live `buf`; `text` receives a
    // LocalAlloc'd string freed once by LocalAllocated's Drop.
    let ok = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let text = LocalAllocated(text);
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated string, live
    // until `text` drops.
    let sid = unsafe { from_wide_nul(text.0) };
    SidString::try_from(sid).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// This process's own token, opened for query only.
fn own_token() -> io::Result<OwnedHandle> {
    // SAFETY: GetCurrentProcess takes nothing and returns a pseudo-handle that
    // is never closed.
    let me = unsafe { GetCurrentProcess() };
    let mut raw = ptr::null_mut();
    // SAFETY: `me` is the live pseudo-handle; `raw` is a live local the token
    // handle is written into.
    let ok = unsafe { OpenProcessToken(me, TOKEN_QUERY, &mut raw) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful OpenProcessToken wrote a handle this process now
    // owns, which the wrapper closes exactly once on drop.
    let handle = unsafe { HandleOrNull::from_raw_handle(raw) };
    OwnedHandle::try_from(handle).map_err(|_| io::Error::last_os_error())
}

/// Memory a Win32 call allocated with `LocalAlloc` on our behalf, freed exactly
/// once on drop.
struct LocalAllocated<T>(*mut T);

impl<T> Drop for LocalAllocated<T> {
    fn drop(&mut self) {
        let block: HLOCAL = self.0.cast();
        // SAFETY: the pointer came from a LocalAlloc-ing API and is freed once,
        // here.
        unsafe { LocalFree(block) };
    }
}

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The string at a NUL-terminated UTF-16 pointer.
///
/// # Safety
/// `p` must point at a NUL-terminated UTF-16 string that stays live for the
/// duration of the call.
unsafe fn from_wide_nul(p: *const u16) -> String {
    let mut len = 0usize;
    // SAFETY: the caller guarantees a NUL terminator, and `len` advances only
    // while the unit read was not that terminator, so every read is in bounds.
    while unsafe { *p.wrapping_add(len) } != 0 {
        len = len.saturating_add(1);
    }
    // SAFETY: the loop above read `len` live units before the terminator.
    let units = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(units)
}
