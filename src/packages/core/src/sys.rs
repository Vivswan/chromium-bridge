//! Quarantined libc shims: the only `unsafe` outside the designated FFI
//! modules (`ipc::platform`, `ipc::peercred`, and `enclave::macos`). Each
//! wrapper exposes a small libc surface through a safe function so callers
//! (broker, attest, lockfile, protocol) never hold an `unsafe` block
//! themselves: `geteuid`/`getppid` are infallible by POSIX contract, and
//! ignoring SIGPIPE cannot fail for that signal. The signal-cleanup thread
//! below holds no unsafe at all; signal-hook owns the handler.
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

/// Run `f` on a dedicated thread when SIGTERM or SIGINT arrives, then exit.
/// signal-hook's handler only writes to a self-pipe; the thread wakes from
/// the iterator and runs the cleanup in ordinary thread context, free of
/// async-signal-safety limits, so it may touch the filesystem. If the
/// handler cannot be registered, the server keeps running without signal
/// cleanup and says so: a signal then takes the default disposition and the
/// next server start clears the stale lock.
#[cfg(unix)]
pub(crate) fn spawn_signal_cleanup<F: Fn() + Send + 'static>(f: F) {
    use signal_hook::consts::signal::{SIGINT, SIGTERM};

    let mut signals = match signal_hook::iterator::Signals::new([SIGTERM, SIGINT]) {
        Ok(signals) => signals,
        Err(e) => {
            log_warn!(
                "mcp",
                "could not register the SIGTERM/SIGINT handler ({e}); a signal will exit without cleanup"
            );
            return;
        }
    };
    std::thread::spawn(move || {
        // `forever` yields only once a registered signal has arrived; the
        // iterator ends only if the handle is closed, which nothing does.
        match signals.forever().next() {
            Some(sig) => log_info!("mcp", "received signal {sig}, cleaning up and exiting"),
            None => log_warn!("mcp", "signal stream closed; cleaning up and exiting"),
        }
        f();
        std::process::exit(0);
    });
}
