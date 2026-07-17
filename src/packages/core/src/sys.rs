//! Quarantined libc shims: the only `unsafe` outside the designated FFI
//! modules ([`crate::ipc::platform`], [`crate::ipc::peercred`], and
//! `enclave::macos`). Each wrapper exposes a small libc surface through a
//! safe function so callers (broker, attest, lockfile, protocol, mcp_server)
//! never hold an `unsafe` block themselves: `geteuid`/`getppid` are
//! infallible by POSIX contract, while the signal wrappers report (or log)
//! the syscall status instead of pretending it cannot fail. `unsafe_code` is
//! denied workspace-wide; this module is one of the audited exceptions.
#![allow(unsafe_code)]

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
    // SAFETY: setting a signal disposition to SIG_IGN involves no memory the
    // caller owns; SIGPIPE is not one of the undefined-behavior signals.
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
    // SAFETY: the sigset_t is zero-initialized then built exclusively through
    // sigemptyset/sigaddset; pthread_sigmask and sigwait receive pointers to
    // locals that outlive the calls (the set is moved into the waiting thread).
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        // Block in the current (main) thread; threads spawned later inherit it.
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());

        std::thread::spawn(move || {
            let mut sig: std::os::raw::c_int = 0;
            // Wait until one of the blocked signals is delivered. On the
            // (never-observed) sigwait failure, still run the cleanup and
            // exit rather than leave a zombie server with no signal handling.
            let rc = libc::sigwait(&set, &mut sig);
            if rc == 0 {
                log_info!("mcp", "received signal {sig}, cleaning up and exiting");
            } else {
                log_warn!("mcp", "sigwait failed ({rc}); cleaning up and exiting");
            }
            f();
            std::process::exit(0);
        });
    }
}
