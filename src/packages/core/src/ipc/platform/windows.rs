//! Windows mechanisms: process handles for liveness/terminate. Windows has
//! no executable-image attestation (see SECURITY.md "Platform support"); the
//! bridge falls back to secret-only authentication there.
#![expect(
    unsafe_code,
    reason = "audited FFI quarantine: process-handle calls, each behind a safe wrapper"
)]

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
