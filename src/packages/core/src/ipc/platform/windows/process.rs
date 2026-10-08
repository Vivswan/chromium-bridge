#![expect(
    unsafe_code,
    reason = "audited FFI quarantine: process-handle calls, each behind a safe wrapper"
)]

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, HandleOrNull, OwnedHandle};
use std::path::PathBuf;

use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// `GetExitCodeProcess` reports this code for a process that has not exited.
const STILL_ACTIVE: u32 = 259;

/// Windows allows paths up to this many UTF-16 units.
const PATH_CAPACITY: usize = 32_768;

struct Process(OwnedHandle);

impl Process {
    fn open(pid: u32) -> io::Result<Process> {
        // SAFETY: OpenProcess takes plain integers; failure is a null handle,
        // which HandleOrNull models.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        // SAFETY: `raw` is null or a handle this process now owns, closed
        // exactly once by the wrapper's drop.
        let handle = unsafe { HandleOrNull::from_raw_handle(raw) };
        OwnedHandle::try_from(handle)
            .map(Process)
            .map_err(|_| io::Error::last_os_error())
    }

    fn is_alive(&self) -> io::Result<bool> {
        let mut code = 0u32;
        // SAFETY: the handle is open for query; `code` is a live local for the
        // write.
        let ok = unsafe { GetExitCodeProcess(self.0.as_raw_handle(), &mut code) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(code == STILL_ACTIVE)
    }

    fn image_path(&self) -> io::Result<PathBuf> {
        let mut buf = vec![0u16; PATH_CAPACITY];
        let mut len =
            u32::try_from(buf.len()).map_err(|_| io::Error::other("path capacity exceeds u32"))?;
        // SAFETY: `buf` holds `len` units and `len` is a live local the call
        // updates to the written length.
        let ok = unsafe {
            QueryFullProcessImageNameW(
                self.0.as_raw_handle(),
                PROCESS_NAME_WIN32,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let written =
            usize::try_from(len).map_err(|_| io::Error::other("path length exceeds usize"))?;
        let units = buf
            .get(..written)
            .ok_or_else(|| io::Error::other("image path longer than its buffer"))?;
        // The path is kept as the exact UTF-16 the kernel returned: a lossy
        // conversion would map an unpaired surrogate to U+FFFD and could name
        // a different file than the one the process runs.
        Ok(PathBuf::from(OsString::from_wide(units)))
    }
}

pub(crate) fn is_alive(pid: u32) -> bool {
    Process::open(pid)
        .and_then(|process| process.is_alive())
        .unwrap_or(false)
}

pub(crate) fn image_path(pid: u32) -> io::Result<PathBuf> {
    Process::open(pid)?.image_path()
}
