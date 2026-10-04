//! Process handles: the image path a pid is running (the input to the identity
//! measurement), liveness, and the parent pid Windows recorded at creation.
#![expect(
    unsafe_code,
    reason = "audited FFI quarantine: process-handle and snapshot calls, each behind a safe wrapper"
)]

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, HandleOrInvalid, HandleOrNull, OwnedHandle};
use std::path::PathBuf;

use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// `GetExitCodeProcess` reports this code for a process that has not exited.
const STILL_ACTIVE: u32 = 259;

/// Windows allows paths up to this many UTF-16 units.
const PATH_CAPACITY: usize = 32_768;

/// A process opened for queries only (no terminate, no memory access).
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

/// Whether a process with the given pid is alive.
pub(crate) fn is_alive(pid: u32) -> bool {
    Process::open(pid)
        .and_then(|process| process.is_alive())
        .unwrap_or(false)
}

/// The on-disk path of the image a pid is running.
pub(crate) fn image_path(pid: u32) -> io::Result<PathBuf> {
    Process::open(pid)?.image_path()
}

/// The pid Windows recorded as this process's parent. Read from a process
/// snapshot: Windows keeps the creator's pid on the process object but exposes
/// it to user mode only this way. The parent may since have exited and its pid
/// been reused, the race [`super::super::super::peercred::peer_pid`] records;
/// and a launcher can name any process it can open as the parent
/// (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), the residual the threat model
/// carries for harness admission on Windows.
pub(crate) fn parent_pid() -> io::Result<u32> {
    let me = std::process::id();
    // SAFETY: a process snapshot takes plain integers; failure is
    // INVALID_HANDLE_VALUE, which HandleOrInvalid models.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    // SAFETY: `raw` is INVALID_HANDLE_VALUE or a handle this process now owns,
    // closed exactly once by the wrapper's drop.
    let snapshot = unsafe { HandleOrInvalid::from_raw_handle(raw) };
    let snapshot = OwnedHandle::try_from(snapshot).map_err(|_| io::Error::last_os_error())?;
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>())
            .map_err(|_| io::Error::other("PROCESSENTRY32W size exceeds u32"))?,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };
    // SAFETY: `snapshot` is an open process snapshot and `entry` a live local
    // with dwSize set, as Process32FirstW requires.
    let mut ok = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
    while ok != 0 {
        if entry.th32ProcessID == me {
            return Ok(entry.th32ParentProcessID);
        }
        // SAFETY: same snapshot and entry as the first call; the loop ends on
        // the first failing return.
        ok = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "own process missing from the process snapshot",
    ))
}
