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
/// async-signal-safety limits, so it may touch the filesystem. The two
/// signals are unblocked on the calling thread after the handler is in
/// place: a parent that blocked them before exec hands its mask down, and a
/// blocked signal would stay pending forever instead of reaching the
/// handler. Later threads inherit the unblocked mask.
#[cfg(unix)]
pub(crate) fn spawn_signal_cleanup<F: Fn() + Send + 'static>(f: F) -> std::io::Result<()> {
    use nix::sys::signal::{SigSet, Signal};
    use signal_hook::consts::signal::{SIGINT, SIGTERM};

    let mut signals = signal_hook::iterator::Signals::new([SIGTERM, SIGINT])?;
    let mut unblock = SigSet::empty();
    unblock.add(Signal::SIGTERM);
    unblock.add(Signal::SIGINT);
    unblock.thread_unblock()?;
    std::thread::spawn(move || {
        match signals.forever().next() {
            Some(sig) => log_info!("mcp", "received signal {sig}, cleaning up and exiting"),
            None => log_warn!("mcp", "signal stream closed; cleaning up and exiting"),
        }
        f();
        std::process::exit(0);
    });
    Ok(())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use nix::sys::signal::{kill, SigSet, Signal};
    use nix::unistd::Pid;

    use super::spawn_signal_cleanup;

    /// The child half of the test below: the test binary re-invoked with
    /// this variable set to a scratch directory installs the cleanup, reports
    /// readiness, and waits to be signalled.
    const CHILD_ENV: &str = "CHROMIUM_BRIDGE_TEST_SIGNAL_CHILD";
    const TEST_NAME: &str = "sys::tests::signal_cleanup_runs_even_when_the_signal_arrives_blocked";

    /// Kills and reaps the child on every exit path of the test, a failed
    /// assertion included, so a failing run never leaves a sleeping child
    /// behind.
    struct Reaped(Child);

    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn wait_for(path: &Path, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn child_role(dir: &Path) {
        let marker = dir.join("cleaned");
        spawn_signal_cleanup(move || {
            std::fs::write(&marker, b"").expect("write the cleanup marker");
        })
        .expect("install the signal cleanup");
        std::fs::write(dir.join("ready"), b"").expect("write the ready marker");
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// A signal that arrives blocked, because the parent blocked it before
    /// exec and the mask was inherited, must still run the cleanup and exit
    /// 0; without the unblock after registration the server sat forever with
    /// the signal pending and the lock on disk. The child is spawned with
    /// the mask already blocked (pre_exec runs after std clears the mask).
    /// Four cases: SIGTERM and SIGINT, each with the mask blocked and clear.
    #[test]
    fn signal_cleanup_runs_even_when_the_signal_arrives_blocked() {
        if let Some(dir) = std::env::var_os(CHILD_ENV) {
            child_role(Path::new(&dir));
        }
        let exe = std::env::current_exe().expect("test binary path");
        for (signal, blocked) in [
            (Signal::SIGTERM, false),
            (Signal::SIGTERM, true),
            (Signal::SIGINT, false),
            (Signal::SIGINT, true),
        ] {
            let case = format!("{signal:?} blocked={blocked}");
            let dir = tempfile::tempdir().expect("scratch dir");
            let mut cmd = Command::new(&exe);
            cmd.args([TEST_NAME, "--exact", "--test-threads=1", "--nocapture"])
                .env(CHILD_ENV, dir.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if blocked {
                // SAFETY: the closure runs in the forked child before exec
                // and only calls pthread_sigmask, which is async-signal-safe
                // and allocates nothing.
                unsafe {
                    cmd.pre_exec(move || {
                        let mut set = SigSet::empty();
                        set.add(signal);
                        set.thread_block()?;
                        Ok(())
                    });
                }
            }
            let mut child = Reaped(cmd.spawn().expect("spawn the child"));
            assert!(
                wait_for(&dir.path().join("ready"), Duration::from_secs(10)),
                "{case}: child never reported ready"
            );
            kill(
                Pid::from_raw(i32::try_from(child.0.id()).expect("pid fits")),
                signal,
            )
            .expect("signal the child");
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = child.0.try_wait().expect("poll the child") {
                    break status;
                }
                assert!(
                    Instant::now() <= deadline,
                    "{case}: child hung with the signal pending"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(status.success(), "{case}: exit status {status}");
            assert!(
                dir.path().join("cleaned").exists(),
                "{case}: cleanup did not run before exit"
            );
        }
    }
}
