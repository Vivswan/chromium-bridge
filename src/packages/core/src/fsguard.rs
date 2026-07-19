//! The crate's one private-file idiom: every file or directory that lives in
//! a user-private location (the 0700 runtime directory, the wrapper install
//! dir) is created and opened through these helpers, so the symlink/TOCTOU
//! reasoning is written - and audited - exactly once.
//!
//! ## The threat, once
//!
//! These paths sit in directories a same-user process can write to before we
//! do. Two classic games are closed here:
//!
//! - **Pre-planted symlink**: a symlink at our path would make us write
//!   through to (or chmod) an arbitrary file. Opens pass `O_NOFOLLOW`, so a
//!   symlink at the final component fails the open instead of being followed;
//!   exclusive creates (`create_new`) refuse any pre-existing entry, symlink
//!   included; directory creation refuses a symlink at the leaf.
//! - **Pre-planted loose file**: `OpenOptions::mode` applies only when the
//!   open CREATES the file, so a pre-planted 0644 file would keep its
//!   group/other bits. After a non-exclusive open the mode is re-asserted on
//!   the open handle (no path re-traversal, so no TOCTOU window); a file
//!   whose mode cannot be asserted fails the open, and every caller already
//!   fails closed on a failed open.
//!
//! What is deliberately NOT here: the atomic-write choreography (temp file +
//! rename) stays at its two call sites (`ipc::write_private_atomic`,
//! `registration::write_atomic`) - they share only the create step, and
//! `registration`'s outputs are deliberately world-readable (0644/0755
//! wrappers and manifests the browser must read), the opposite contract.
//!
//! On non-Unix targets the mode and `O_NOFOLLOW` hardening compiles to plain
//! opens: Windows has no Unix modes, and the same-user boundary is not
//! enforced there (see SECURITY.md "Platform support").

use std::fs;
use std::io;
use std::path::Path;

/// Open `path` for appending, creating it 0600 if absent. Refuses a symlink
/// at the final component; re-asserts owner-only permissions on the handle.
pub(crate) fn open_private_append(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.append(true).create(true);
    open_private(opts, path)
}

/// Open `path` read+write, creating it 0600 if absent. Same hardening as
/// [`open_private_append`]. For lock and mutex files whose content is
/// irrelevant but whose mode and identity are not.
pub(crate) fn open_private_rw(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true).write(true).create(true);
    open_private(opts, path)
}

fn open_private(opts: fs::OpenOptions, path: &Path) -> io::Result<fs::File> {
    #[cfg(unix)]
    let opts = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = opts;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
        opts
    };
    let f = opts.open(path)?;
    // The mode above applies only on create; re-assert it on the open handle
    // so a pre-planted looser file cannot keep group/other bits. Propagated:
    // a file we cannot tighten (e.g. planted by a more-privileged writer) is
    // refused like any other failed open, never written through.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

/// Exclusively create `path` for writing, 0600 from the first instant.
/// `create_new` (O_EXCL) fails on ANY pre-existing entry - a planted file or
/// symlink is refused, never adopted or followed - so no re-assert is needed:
/// the file cannot exist with a mode we did not give it.
///
/// Unix-only: its sole caller (`ipc::write_private_atomic`) takes a plain
/// create+truncate open on Windows, where there are no Unix modes to pin.
#[cfg(unix)]
pub(crate) fn create_private_excl(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    opts.open(path)
}

/// Force owner-only (0600) permissions on an existing filesystem object that
/// cannot be opened as a file - the Unix-domain socket a listener just bound.
#[cfg(unix)]
pub(crate) fn set_private_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

/// Create `dir` (and parents) and force owner-only (0700) permissions on it.
/// Refuses a symlink at the leaf: our private namespace must not be
/// redirectable elsewhere. Applies to an existing directory too, so a
/// pre-planted looser directory is tightened, not inherited.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    if fs::symlink_metadata(dir)?.file_type().is_symlink() {
        return Err(io::Error::other(
            "is a symlink; refusing to use it as a private directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A scratch directory unique to one test, so parallel tests never
    /// collide. Cleared at the start of each run, so a previous run's
    /// leftovers never leak in; left behind afterwards (temp dir).
    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "chromium-bridge-fsguard-test-{}-{test}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn open_private_refuses_a_preplanted_symlink() {
        for (name, open) in [
            (
                "append",
                open_private_append as fn(&Path) -> io::Result<fs::File>,
            ),
            ("rw", open_private_rw as fn(&Path) -> io::Result<fs::File>),
        ] {
            let dir = scratch(&format!("symlink-{name}"));
            let target = dir.join("target");
            let link = dir.join("guarded");
            fs::write(&target, b"").unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(open(&link).is_err(), "{name}: symlink must not be opened");
            assert_eq!(
                fs::read(&target).unwrap(),
                b"",
                "{name}: the symlink target must stay untouched"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn open_private_creates_0600_and_tightens_a_preplanted_loose_file() {
        use std::os::unix::fs::PermissionsExt;
        for (name, open) in [
            (
                "append",
                open_private_append as fn(&Path) -> io::Result<fs::File>,
            ),
            ("rw", open_private_rw as fn(&Path) -> io::Result<fs::File>),
        ] {
            let dir = scratch(&format!("mode-{name}"));
            // Fresh create: 0600 from the open itself.
            let fresh = dir.join("fresh");
            open(&fresh).unwrap();
            assert_eq!(mode_of(&fresh), 0o600, "{name}: fresh create");
            // Pre-planted loose file: the re-assert strips group/other bits.
            let planted = dir.join("planted");
            fs::write(&planted, b"planted").unwrap();
            fs::set_permissions(&planted, fs::Permissions::from_mode(0o644)).unwrap();
            open(&planted).unwrap();
            assert_eq!(
                mode_of(&planted) & 0o077,
                0,
                "{name}: mode {:o} leaks group/other bits",
                mode_of(&planted)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn create_private_excl_is_0600_and_refuses_any_preexisting_entry() {
        let dir = scratch("excl");
        let fresh = dir.join("fresh");
        create_private_excl(&fresh).unwrap();
        assert_eq!(mode_of(&fresh), 0o600);
        // An existing file is refused, never truncated or adopted.
        assert!(create_private_excl(&fresh).is_err());
        // A dangling symlink is refused too (O_EXCL treats it as existing),
        // so the create can never land at the link's target.
        let link = dir.join("link");
        std::os::unix::fs::symlink(dir.join("nowhere"), &link).unwrap();
        assert!(create_private_excl(&link).is_err());
        assert!(!dir.join("nowhere").exists());
    }

    #[cfg(unix)]
    #[test]
    fn set_private_mode_strips_group_and_other_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("chmod");
        let path = dir.join("loose");
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        set_private_mode(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn ensure_private_dir_creates_refuses_symlink_and_tightens() {
        let root = scratch("dir");
        // Fresh create (with parents) is owner-only.
        let fresh = root.join("a/b");
        ensure_private_dir(&fresh).unwrap();
        #[cfg(unix)]
        assert_eq!(mode_of(&fresh), 0o700);
        // Idempotent on an existing dir, and a loosened one is re-tightened.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fresh, fs::Permissions::from_mode(0o755)).unwrap();
            ensure_private_dir(&fresh).unwrap();
            assert_eq!(mode_of(&fresh), 0o700);
        }
        // A symlink at the leaf is refused, even one pointing at a real dir.
        #[cfg(unix)]
        {
            let real = root.join("real");
            fs::create_dir_all(&real).unwrap();
            let link = root.join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert!(ensure_private_dir(&link).is_err());
        }
    }
}
