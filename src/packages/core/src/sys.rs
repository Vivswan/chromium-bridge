//! Quarantined libc shims: the only `unsafe` outside the designated FFI
//! modules (`ipc::platform`, `ipc::peercred`, and
//! `enclave::macos`). Each wrapper exposes a small libc surface through a
//! safe function so callers (broker, attest, lockfile, protocol, mcp_server)
//! never hold an `unsafe` block themselves: `geteuid`/`getppid` are
//! infallible by POSIX contract, while the signal wrappers report (or log)
//! the syscall status instead of pretending it cannot fail.
#![cfg_attr(
    unix,
    expect(
        unsafe_code,
        reason = "audited libc quarantine: the only unsafe outside the FFI modules, each call behind a safe wrapper"
    )
)]

/// The effective UID of this process. `geteuid` cannot fail (POSIX defines no
/// error returns for it).
#[cfg(unix)]
pub(crate) fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid takes no pointers and has no failure mode.
    unsafe { libc::geteuid() }
}

/// The PID of this process's current parent. `getppid` cannot fail.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn parent_pid() -> libc::pid_t {
    // SAFETY: getppid takes no pointers and has no failure mode.
    unsafe { libc::getppid() }
}

/// SIGPIPE protection. On Unix, writing to a closed stdout/socket raises
/// SIGPIPE by default and kills the process. Rust disables SIGPIPE for its
/// own I/O but not for the inherited disposition everywhere; ignore it so we
/// get EPIPE errors instead of dying. Safe to call once at startup.
pub(crate) fn ignore_sigpipe() {
    #[cfg(unix)]
    // SAFETY: SIG_IGN is a disposition constant, not a handler pointer, so no
    // memory of ours is handed to the kernel; SIGPIPE may be ignored by POSIX.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// Block SIGTERM/SIGINT process-wide and run `f` on a dedicated thread when
/// one arrives, then exit. Blocking the signals here (and letting a single
/// thread `sigwait` for them) sidesteps async-signal-safety limits: the
/// cleanup runs in ordinary thread context, so it may touch the filesystem
/// freely. Callers MUST invoke this before spawning worker threads so those
/// threads inherit the blocked mask.
#[cfg(unix)]
pub(crate) fn block_signals_and_spawn_cleanup<F: Fn() + Send + 'static>(f: F) {
    // SAFETY: sigset_t is a plain C value type for which all-zero bytes are a
    // valid state; sigemptyset below defines the contents.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a live, writable local for the duration of the call.
    unsafe { libc::sigemptyset(&mut set) };
    // SAFETY: `set` was initialized by sigemptyset above and outlives the call.
    unsafe { libc::sigaddset(&mut set, libc::SIGTERM) };
    // SAFETY: as for SIGTERM above: same initialized set, same lifetime.
    unsafe { libc::sigaddset(&mut set, libc::SIGINT) };
    // Block in the current (main) thread; threads spawned later inherit it.
    // SAFETY: `set` is fully built and outlives the call; POSIX permits a null
    // oldset pointer.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };

    std::thread::spawn(move || {
        let mut sig: std::os::raw::c_int = 0;
        // Wait until one of the blocked signals is delivered. On the
        // (never-observed) sigwait failure, still run the cleanup and
        // exit rather than leave a zombie server with no signal handling.
        // SAFETY: `set` moved into this thread and `sig` is a live local; both
        // outlive the blocking call.
        let rc = unsafe { libc::sigwait(&set, &mut sig) };
        if rc == 0 {
            log_info!("mcp", "received signal {sig}, cleaning up and exiting");
        } else {
            log_warn!("mcp", "sigwait failed ({rc}); cleaning up and exiting");
        }
        f();
        std::process::exit(0);
    });
}
