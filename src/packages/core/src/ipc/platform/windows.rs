//! Windows mechanisms: process handles for liveness/terminate and BCrypt for
//! OS randomness. Windows has no executable-image attestation (see
//! SECURITY.md "Platform support"); the bridge falls back to secret-only
//! authentication there.
#![expect(
    unsafe_code,
    reason = "audited FFI quarantine: process-handle and BCrypt calls, each behind a safe wrapper"
)]

use std::io;

pub mod windows_process {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit_handle: i32, process_id: u32) -> Handle;
        fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> i32;
        fn TerminateProcess(process: Handle, exit_code: u32) -> i32;
        fn CloseHandle(object: Handle) -> i32;
    }

    pub fn is_alive(pid: u32) -> bool {
        // SAFETY: OpenProcess takes plain integers and reports failure as a
        // null handle, checked below.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut exit_code = 0;
        // SAFETY: `handle` is non-null and still open; `exit_code` is a live
        // local for the write.
        let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) } != 0;
        // SAFETY: `handle` was opened above and is closed exactly once, here.
        unsafe { CloseHandle(handle) };
        ok && exit_code == STILL_ACTIVE
    }

    pub fn terminate(pid: u32) {
        // SAFETY: OpenProcess takes plain integers and reports failure as a
        // null handle, checked below.
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() {
            return;
        }
        // SAFETY: `handle` is non-null and was opened with PROCESS_TERMINATE.
        let _ = unsafe { TerminateProcess(handle, 0) };
        // SAFETY: `handle` was opened above and is closed exactly once, here.
        unsafe { CloseHandle(handle) };
    }
}

pub(crate) fn fill_os_random(buf: &mut [u8]) -> io::Result<()> {
    // BCryptGenRandom takes a u32 length; a silent `as` cast would under-fill
    // any buffer past 4 GiB while still returning Ok, so refuse instead.
    let len = u32::try_from(buf.len())
        .map_err(|_| io::Error::other("buffer too large for BCryptGenRandom"))?;
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG lets BCryptGenRandom use the system
    // RNG without opening and managing an algorithm-provider handle.
    // SAFETY: `buf` is a live exclusive slice and `len` is exactly its length,
    // so the write stays in bounds; the null algorithm handle is what the
    // system-preferred-RNG flag requires.
    let status =
        unsafe { BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), len, 0x0000_0002) };
    if status >= 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "BCryptGenRandom failed (NTSTATUS {status:#010x})"
        )))
    }
}

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut std::ffi::c_void,
        buffer: *mut u8,
        buffer_len: u32,
        flags: u32,
    ) -> i32;
}
