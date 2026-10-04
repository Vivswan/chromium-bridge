//! The bridge transport on Windows: a named pipe in the local namespace, one
//! instance per connection, every instance created with the user-only
//! descriptor and the first with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a name
//! another process already holds fails the bind instead of being shared.
//!
//! All I/O is overlapped, which is what lets a read carry a deadline and lets
//! `shutdown` from another thread wake a blocked reader: the two things the
//! broker's attach phase needs that a synchronous pipe handle cannot do. Clones
//! share one handle and one timeout, as clones of a socket share its options;
//! each clone owns the event its own operations signal.
#![expect(
    unsafe_code,
    reason = "audited FFI quarantine: the named-pipe, overlapped I/O, and event calls, each behind a safe wrapper"
)]

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::windows::io::{AsRawHandle, HandleOrInvalid, HandleOrNull, OwnedHandle};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, ERROR_SEM_TIMEOUT, GENERIC_READ, GENERIC_WRITE,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileType, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_FLAG_OVERLAPPED, FILE_TYPE_PIPE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED, OVERLAPPED_0};

use super::acl::{wide, UserOnlyDescriptor};
use super::PipeName;

/// Kernel buffer hint per direction; the bridge frames are small NDJSON lines.
const PIPE_BUFFER: u32 = 64 * 1024;

/// The server end: creates instances and hands each connected one out.
pub struct PipeListener {
    name: Vec<u16>,
    descriptor: UserOnlyDescriptor,
    /// The instance waiting for the next client, created ahead of `accept` so
    /// the name stays claimed between connections.
    pending: Mutex<Option<OwnedHandle>>,
}

impl PipeListener {
    /// Claim `name` with a first instance: fails when any process already holds
    /// an instance of it, so a squatted name is refused rather than joined.
    pub fn bind(name: &PipeName) -> io::Result<PipeListener> {
        let listener = PipeListener {
            name: wide(name.as_str()),
            descriptor: UserOnlyDescriptor::for_current_user()?,
            pending: Mutex::new(None),
        };
        let first = listener.create_instance(true)?;
        *listener
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(first);
        Ok(listener)
    }

    fn create_instance(&self, first: bool) -> io::Result<OwnedHandle> {
        let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        // SAFETY: `name` is a live NUL-terminated buffer and the attributes
        // point into `self.descriptor`, live for `self`; failure is
        // INVALID_HANDLE_VALUE, which HandleOrInvalid models.
        let raw = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER,
                PIPE_BUFFER,
                0,
                self.descriptor.attributes(),
            )
        };
        // SAFETY: `raw` is INVALID_HANDLE_VALUE or a handle this process now
        // owns, closed exactly once by the wrapper's drop.
        let handle = unsafe { HandleOrInvalid::from_raw_handle(raw) };
        OwnedHandle::try_from(handle).map_err(|_| io::Error::last_os_error())
    }

    /// Block until a client connects and hand the connected instance out. The
    /// second element stands where a socket listener returns the peer
    /// address; a pipe has none.
    pub fn accept(&self) -> io::Result<(PipeStream, ())> {
        let taken = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let mut instance = match taken {
            Some(instance) => instance,
            None => self.create_instance(false)?,
        };
        loop {
            match wait_for_client(&instance) {
                Ok(()) => {
                    self.listen_again();
                    let shared = Arc::new(Shared::new(instance, PipeEnd::Server));
                    return Ok((PipeStream::new(shared)?, ()));
                }
                // The client came and went before we listened (a reachability
                // probe does exactly that): the instance is spent, not the
                // listener.
                Err(err) if error_code(&err) == Some(ERROR_NO_DATA) => {
                    instance = self.create_instance(false)?;
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Create the next instance before the connected one is handed out, so a
    /// client arriving between two `accept` calls finds the name listening
    /// instead of absent (`CreateFileW` would fail with no instance to wait
    /// for). A failure here only costs that early arrival; the next `accept`
    /// creates its own instance and reports the error if it persists.
    fn listen_again(&self) {
        match self.create_instance(false) {
            Ok(next) => {
                *self.pending.lock().unwrap_or_else(PoisonError::into_inner) = Some(next);
            }
            Err(e) => log_warn!("ipc", "could not pre-create the next pipe instance: {e}"),
        }
    }
}

/// The pid of the process that created this process's stdin pipe: the harness
/// that spawned the server. Every spawner (CreatePipe, libuv, Rust's own
/// Command) opens both ends of a child's stdio pipe itself before handing one
/// across, so the kernel's client and server pids agree and name the creator;
/// anything else (a console or file on stdin, a pipe end passed on from
/// another process) fails closed.
pub(crate) fn stdin_pipe_creator() -> io::Result<u32> {
    let stdin = io::stdin().as_raw_handle();
    // SAFETY: the handle is this process's live stdin; the call only reads
    // its type.
    if unsafe { GetFileType(stdin) } != FILE_TYPE_PIPE {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "stdin is not a pipe; the harness cannot be attested",
        ));
    }
    let mut client = 0u32;
    // SAFETY: `stdin` is an open pipe handle; `client` is a live local for the
    // write.
    if unsafe { GetNamedPipeClientProcessId(stdin, &mut client) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut server = 0u32;
    // SAFETY: as above, for the server end's pid.
    if unsafe { GetNamedPipeServerProcessId(stdin, &mut server) } == 0 {
        return Err(io::Error::last_os_error());
    }
    super::pipe_creator(client, server, std::process::id())
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))
}

/// Wait for a client to open `instance`.
fn wait_for_client(instance: &OwnedHandle) -> io::Result<()> {
    let event = Event::new()?;
    let mut overlapped = event.overlapped();
    // SAFETY: `instance` is an open overlapped instance and `overlapped` a
    // live local that outlives the operation: this function returns only
    // after `finish` confirms the connect completed.
    let issued = unsafe { ConnectNamedPipe(instance.as_raw_handle(), &mut overlapped) };
    if issued != 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match error_code(&err) {
        // The client opened the instance before we waited on it.
        Some(ERROR_PIPE_CONNECTED) => Ok(()),
        Some(ERROR_IO_PENDING) => {
            let waited = event.wait(None);
            finish(instance.as_raw_handle(), &overlapped)?;
            waited.map(|_| ())
        }
        _ => Err(err),
    }
}

/// Which end of the pipe a stream holds; it selects whose pid the kernel is
/// asked for and whether `shutdown` can disconnect the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipeEnd {
    Server,
    Client,
}

struct Shared {
    handle: OwnedHandle,
    end: PipeEnd,
    read_timeout: Mutex<Option<Duration>>,
    closed: AtomicBool,
}

impl Shared {
    fn new(handle: OwnedHandle, end: PipeEnd) -> Shared {
        Shared {
            handle,
            end,
            read_timeout: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }
}

/// One end of a connected pipe. `Read`/`Write` as a socket; `try_clone`,
/// `set_read_timeout`, and `shutdown` with the semantics the rest of the crate
/// relies on from `UnixStream`.
pub struct PipeStream {
    shared: Arc<Shared>,
    event: Event,
}

impl PipeStream {
    fn new(shared: Arc<Shared>) -> io::Result<PipeStream> {
        Ok(PipeStream {
            shared,
            event: Event::new()?,
        })
    }

    /// Open the pipe at `name`, waiting up to `timeout` for a free instance
    /// while the server is between `accept`s. The open asks for identification
    /// only, so a server impersonating this client (the squatter case) gets no
    /// more than its identity.
    pub fn connect(name: &PipeName, timeout: Duration) -> io::Result<PipeStream> {
        let name = wide(name.as_str());
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "connect timeout too large")
        })?;
        loop {
            // SAFETY: `name` is a live NUL-terminated buffer; failure is
            // INVALID_HANDLE_VALUE, which HandleOrInvalid models.
            let raw = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    ptr::null_mut(),
                )
            };
            // SAFETY: `raw` is INVALID_HANDLE_VALUE or a handle this process
            // now owns, closed exactly once by the wrapper's drop.
            let handle = unsafe { HandleOrInvalid::from_raw_handle(raw) };
            match OwnedHandle::try_from(handle) {
                Ok(handle) => {
                    return PipeStream::new(Arc::new(Shared::new(handle, PipeEnd::Client)))
                }
                Err(_) => {
                    let err = io::Error::last_os_error();
                    if error_code(&err) != Some(ERROR_PIPE_BUSY) {
                        return Err(err);
                    }
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no free pipe instance",
                ));
            }
            // SAFETY: `name` is a live NUL-terminated buffer; the call only waits.
            let ok = unsafe { WaitNamedPipeW(name.as_ptr(), millis(remaining)) };
            if ok == 0 {
                let err = io::Error::last_os_error();
                if error_code(&err) != Some(ERROR_SEM_TIMEOUT) {
                    return Err(err);
                }
            }
        }
    }

    /// Another handle onto the same connection, sharing its timeout and
    /// shutdown state.
    pub fn try_clone(&self) -> io::Result<PipeStream> {
        PipeStream::new(Arc::clone(&self.shared))
    }

    /// Bound every read on this connection, as `set_read_timeout` on a socket.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot set a 0 duration timeout",
            ));
        }
        *self
            .shared
            .read_timeout
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = timeout;
        Ok(())
    }

    /// End the connection from any clone: the peer reads EOF, and a reader of
    /// this connection blocked on another thread wakes with EOF.
    pub fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        self.shared.closed.store(true, Ordering::Release);
        let handle = self.shared.handle.as_raw_handle();
        if self.shared.end == PipeEnd::Server {
            // SAFETY: the handle is an open server instance; disconnecting it
            // closes the client's end.
            let _ = unsafe { DisconnectNamedPipe(handle) };
        }
        // SAFETY: cancels every operation this process has pending on the
        // handle; each issuer is blocked in `finish` and observes the
        // cancellation there.
        let _ = unsafe { CancelIoEx(handle, ptr::null()) };
        Ok(())
    }

    /// The pid the kernel recorded for the other end when it connected.
    pub fn peer_pid(&self) -> io::Result<u32> {
        let handle = self.shared.handle.as_raw_handle();
        let mut pid = 0u32;
        let ok = match self.shared.end {
            // SAFETY: the handle is an open server instance; `pid` is a live
            // local for the write.
            PipeEnd::Server => unsafe { GetNamedPipeClientProcessId(handle, &mut pid) },
            // SAFETY: the handle is an open client end; `pid` is a live local
            // for the write.
            PipeEnd::Client => unsafe { GetNamedPipeServerProcessId(handle, &mut pid) },
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }

    fn closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed() {
            return Ok(0);
        }
        let handle = self.shared.handle.as_raw_handle();
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut overlapped = self.event.overlapped();
        // SAFETY: `handle` is open; `buf` and `overlapped` outlive the read,
        // because this function returns only after `finish` confirms the read
        // completed or its cancellation took effect.
        let issued = unsafe {
            ReadFile(
                handle,
                buf.as_mut_ptr(),
                len,
                ptr::null_mut(),
                &mut overlapped,
            )
        };
        if issued != 0 {
            // Completed at once (bytes were already buffered): the result is
            // ready, and the event is not relied on to have been signaled.
            return self.read_outcome(finish(handle, &overlapped), false);
        }
        let err = io::Error::last_os_error();
        if error_code(&err) != Some(ERROR_IO_PENDING) {
            return self.read_outcome(Err(err), false);
        }
        let timeout = *self
            .shared
            .read_timeout
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let waited = self.event.wait(timeout);
        let completed = matches!(waited, Ok(Waited::Signaled));
        if !completed {
            // SAFETY: cancels the one read issued above; `overlapped` is its
            // live record.
            let _ = unsafe { CancelIoEx(handle, &overlapped) };
        }
        let finished = finish(handle, &overlapped);
        waited?;
        self.read_outcome(finished, !completed)
    }
}

impl PipeStream {
    /// Fold a finished read into socket semantics: a peer gone is EOF, a
    /// cancelled read is a timeout or (after `shutdown`) EOF.
    fn read_outcome(&self, finished: io::Result<usize>, timed_out: bool) -> io::Result<usize> {
        let err = match finished {
            Ok(n) => return Ok(n),
            Err(err) => err,
        };
        match error_code(&err) {
            Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA) => Ok(0),
            Some(ERROR_OPERATION_ABORTED) if timed_out => {
                Err(io::Error::new(io::ErrorKind::TimedOut, "read timed out"))
            }
            Some(ERROR_OPERATION_ABORTED) if self.closed() => Ok(0),
            _ => Err(err),
        }
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let handle = self.shared.handle.as_raw_handle();
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut overlapped = self.event.overlapped();
        // SAFETY: `handle` is open; `buf` and `overlapped` outlive the write,
        // because `finish` below returns only once it has completed.
        let issued =
            unsafe { WriteFile(handle, buf.as_ptr(), len, ptr::null_mut(), &mut overlapped) };
        if issued == 0 {
            let err = io::Error::last_os_error();
            if error_code(&err) != Some(ERROR_IO_PENDING) {
                return Err(err);
            }
        }
        finish(handle, &overlapped)
    }

    /// Pipe writes land in the kernel buffer on completion; there is nothing
    /// user-space holds back. (`FlushFileBuffers` would instead block until the
    /// peer has read everything.)
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Wait for the operation recorded in `overlapped` to complete or be cancelled
/// and return its byte count. Every issued operation goes through here before
/// its buffers go out of scope.
fn finish(handle: *mut std::ffi::c_void, overlapped: &OVERLAPPED) -> io::Result<usize> {
    let mut transferred = 0u32;
    // SAFETY: `overlapped` is the live record of an operation issued on
    // `handle`; with the wait flag set the call returns only once that
    // operation has completed or been cancelled.
    let ok = unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, 1) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(transferred).map_err(|_| io::Error::other("transfer count exceeds usize"))
}

/// A manual-reset event one stream's operations signal on completion.
struct Event(OwnedHandle);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Waited {
    Signaled,
    TimedOut,
}

impl Event {
    fn new() -> io::Result<Event> {
        // SAFETY: no attributes, manual reset, unsignaled, unnamed; failure is
        // a null handle, which HandleOrNull models.
        let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        // SAFETY: `raw` is null or a handle this process now owns, closed
        // exactly once by the wrapper's drop.
        let handle = unsafe { HandleOrNull::from_raw_handle(raw) };
        OwnedHandle::try_from(handle)
            .map(Event)
            .map_err(|_| io::Error::last_os_error())
    }

    fn overlapped(&self) -> OVERLAPPED {
        OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            Anonymous: OVERLAPPED_0 {
                Pointer: ptr::null_mut(),
            },
            hEvent: self.0.as_raw_handle(),
        }
    }

    fn wait(&self, timeout: Option<Duration>) -> io::Result<Waited> {
        let ms = timeout.map_or(INFINITE, millis);
        // SAFETY: the event handle is open; the call only waits on it.
        match unsafe { WaitForSingleObject(self.0.as_raw_handle(), ms) } {
            WAIT_OBJECT_0 => Ok(Waited::Signaled),
            WAIT_TIMEOUT => Ok(Waited::TimedOut),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            other => Err(io::Error::other(format!(
                "unexpected wait result {other:#x}"
            ))),
        }
    }
}

/// A duration as Win32 milliseconds: at least one (zero would poll), and below
/// `INFINITE`.
fn millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis())
        .unwrap_or(INFINITE.saturating_sub(1))
        .clamp(1, INFINITE.saturating_sub(1))
}

fn error_code(err: &io::Error) -> Option<u32> {
    err.raw_os_error().and_then(|code| u32::try_from(code).ok())
}

#[cfg(test)]
mod tests {
    use std::io::BufRead;

    use super::*;

    fn unique_name(tag: &str) -> PipeName {
        PipeName::for_broker(
            &std::env::temp_dir().join(format!("chromium-bridge-pipe-test-{tag}")),
            std::process::id(),
        )
    }

    fn pair(listener: &PipeListener, name: &PipeName) -> (PipeStream, PipeStream) {
        let name = name.clone();
        let client = std::thread::spawn(move || PipeStream::connect(&name, Duration::from_secs(5)));
        let (server, ()) = listener.accept().unwrap();
        (server, client.join().unwrap().unwrap())
    }

    #[test]
    fn a_claimed_name_refuses_a_second_listener_and_both_ends_see_the_local_peer() {
        // External facts the bridge rests on: FILE_FLAG_FIRST_PIPE_INSTANCE
        // fails a second bind of a held name (so a squatter cannot join ours),
        // and the kernel reports the pid on each end of a connected pipe
        // (the input to attestation). Both ends here are this process.
        let name = unique_name("claim");
        let listener = PipeListener::bind(&name).unwrap();
        assert!(
            PipeListener::bind(&name).is_err(),
            "a held name must not bind twice"
        );

        let (mut server, mut client) = pair(&listener, &name);
        assert_eq!(server.peer_pid().unwrap(), std::process::id());
        assert_eq!(client.peer_pid().unwrap(), std::process::id());
        super::super::super::super::attest::attest_peer(&server).unwrap();
        super::super::super::super::attest::attest_peer(&client).unwrap();

        client.write_all(b"ping\n").unwrap();
        let mut line = String::new();
        io::BufReader::new(server.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "ping\n");
        server.write_all(b"pong\n").unwrap();
        let mut reply = [0u8; 5];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong\n");
    }

    /// Set in the child this test spawns of itself; the parent role is the
    /// test run without it.
    const STDIN_PEER_CHILD: &str = "CHROMIUM_BRIDGE_TEST_STDIN_PEER_CHILD";

    #[test]
    fn the_stdin_pipe_creator_is_the_process_that_spawned_us() {
        // External fact the harness measurement rests on: a child's stdin pipe,
        // created by its spawner (here Rust's Command), reports the spawner's
        // pid on both ends, even though the child only inherited one end; and
        // GetNamedPipe{Client,Server}ProcessId answer for an anonymous pipe.
        // The test re-runs itself as that child, which also attests its
        // harness end to end: the spawner is this same binary, so the measured
        // hash must equal the child's own identity.
        if std::env::var_os(STDIN_PEER_CHILD).is_some() {
            use super::super::super::super::attest::{attest_parent, ensure_own_identity};

            println!("stdin-pipe-creator={}", stdin_pipe_creator().unwrap());
            let harness = attest_parent().unwrap();
            assert_eq!(harness.hash.as_str(), ensure_own_identity().unwrap());
            println!("attest-parent=own-image");
            return;
        }
        let me = std::env::current_exe().unwrap();
        let output = std::process::Command::new(me)
            .args([
                "--exact",
                "ipc::platform::windows::pipe::tests::the_stdin_pipe_creator_is_the_process_that_spawned_us",
                "--nocapture",
            ])
            .env(STDIN_PEER_CHILD, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        // libtest prefixes the first child line with "test <name> ... " when it
        // runs single-threaded, so the markers are searched within a line.
        let reported = stdout
            .lines()
            .find_map(|line| line.split_once("stdin-pipe-creator="))
            .unwrap_or_else(|| panic!("child reports the creator pid:\n{stdout}"))
            .1
            .trim();
        assert_eq!(reported, std::process::id().to_string());
        assert!(
            stdout.contains("attest-parent=own-image"),
            "child attests its harness:\n{stdout}"
        );
        assert!(output.status.success(), "child test run passes");
    }

    #[test]
    fn a_client_arriving_between_accepts_finds_the_name_listening() {
        // External fact: CreateFileW on a pipe name with no instance fails at
        // once (ERROR_FILE_NOT_FOUND) and WaitNamedPipeW has nothing to wait
        // for, so the listener must hold a fresh instance before it hands the
        // connected one out. The connect below runs with no accept pending.
        let name = unique_name("between-accepts");
        let listener = PipeListener::bind(&name).unwrap();
        let (_server, _client) = pair(&listener, &name);
        PipeStream::connect(&name, Duration::from_millis(500))
            .expect("a listening instance exists between accepts");
    }

    #[test]
    fn a_read_deadline_fires_and_shutdown_wakes_a_blocked_reader() {
        // The broker bounds its attach phase with set_read_timeout and ends
        // connections with shutdown from another thread; neither exists on a
        // synchronous pipe handle, so both are pinned here against the
        // overlapped implementation.
        let name = unique_name("deadline");
        let listener = PipeListener::bind(&name).unwrap();
        let (mut server, mut client) = pair(&listener, &name);

        server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let started = Instant::now();
        let mut buf = [0u8; 8];
        let err = server.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline must fire promptly"
        );

        // Data arriving within the deadline is delivered, not lost to it.
        let writer = std::thread::spawn({
            let mut client = client.try_clone().unwrap();
            move || {
                std::thread::sleep(Duration::from_millis(20));
                client.write_all(b"late").unwrap();
            }
        });
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let n = server.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"late");
        writer.join().unwrap();

        server.set_read_timeout(None).unwrap();
        let reader = std::thread::spawn({
            let mut server = server.try_clone().unwrap();
            move || {
                let mut buf = [0u8; 8];
                server.read(&mut buf)
            }
        });
        std::thread::sleep(Duration::from_millis(50));
        server.shutdown(Shutdown::Both).unwrap();
        assert_eq!(
            reader.join().unwrap().unwrap(),
            0,
            "the blocked reader wakes with EOF"
        );
        assert_eq!(client.read(&mut buf).unwrap(), 0, "the peer reads EOF");
    }
}
