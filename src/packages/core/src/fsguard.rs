//! The crate's one private-file idiom: every open, read, and atomic replacement of a file in a user-private
//! location (the 0700 runtime directory, the wrapper install dir) goes through these helpers, so the
//! symlink/TOCTOU reasoning lives once. These paths sit in directories a same-user process can write to before
//! we do.
//!
//! ```text
//! pre-planted symlink     -> opens pass `O_NOFOLLOW`; dirs refuse a symlink leaf
//! pre-planted loose file  -> `OpenOptions::mode` applies only on create, so the mode is re-asserted on the open handle
//!                            (no path re-traversal); a file that cannot be tightened fails the open
//! pre-planted huge file   -> `read_capped` stops at the cap + 1 and refuses, never slurping it
//! replacement             -> `write_private_atomic` lands an exclusive 0600 temp file by rename, so a planted entry is
//!                            neither adopted nor followed and its looser mode never carries over
//! ```
//!
//! Reads take plain opens that follow a symlink at the final component: a same-user symlink only redirects a read
//! to something that user could already read. `registration::write_atomic` is the one replacement outside this
//! module, because its outputs are deliberately world-readable wrappers and manifests the browser must read. On
//! non-Unix targets the hardening compiles to plain opens: no Unix modes, and the same-user boundary is not
//! enforced there (SECURITY.md "Platform support").

use std::fs;
use std::io::{self, Read, Write};
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
    // A file we cannot tighten (planted by a more-privileged writer) is refused, never written through.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
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

/// Read a small private file in full, bounded by `max` bytes. `Ok(None)` when the file does not exist;
/// `InvalidData` when it exceeds the cap, after reading at most `max + 1` bytes. Every record in the runtime
/// directory is a few KB at most, so anything larger is not ours (a same-user process planted it) and is
/// refused instead of slurped into memory.
pub(crate) fn read_capped(path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    // max + 1 bytes, so an over-cap file is distinguishable from one of exactly max bytes.
    let cap = u64::try_from(max)
        .ok()
        .and_then(|c| c.checked_add(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "size cap out of range"))?;
    let mut bytes = Vec::new();
    f.take(cap).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is larger than its {max}-byte cap; refusing a file that cannot be ours",
                path.display()
            ),
        ));
    }
    Ok(Some(bytes))
}

/// Write `bytes` to `path` atomically: a same-directory temp file created exclusively (0600 on Unix) under
/// a fresh random name, renamed over the destination. Not fsynced, for every private record alike: readers
/// see the old file or the new one, never a partial write, and nothing is promised across a system crash.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("target path has no parent directory"))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.persist(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("chromium-bridge-fsguard-test-")
            .tempdir()
            .unwrap()
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
            let tmp = scratch();
            let dir = tmp.path();
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
            let tmp = scratch();
            let dir = tmp.path();
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
    fn set_private_mode_strips_group_and_other_bits() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = scratch();
        let dir = tmp.path();
        let path = dir.join("loose");
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        set_private_mode(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn ensure_private_dir_creates_refuses_symlink_and_tightens() {
        let tmp = scratch();
        let root = tmp.path();
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

    #[test]
    fn read_capped_refuses_an_oversized_file_and_passes_a_small_one() {
        let tmp = scratch();
        let dir = tmp.path();
        let path = dir.join("record.json");
        assert!(read_capped(&path, 16).unwrap().is_none(), "absent is None");
        fs::write(&path, vec![b'x'; 17]).unwrap();
        assert_eq!(
            read_capped(&path, 16).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::write(&path, b"{\"pid\":1}").unwrap();
        assert_eq!(read_capped(&path, 16).unwrap().unwrap(), b"{\"pid\":1}");
    }

    /// tempfile creates the temp file owner-only and rename replaces the destination inode: two external
    /// facts every secret-bearing record relies on, neither enforced by the compiler.
    #[cfg(unix)]
    #[test]
    fn write_private_atomic_is_owner_only_and_replaces_a_planted_loose_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = scratch();
        let dir = tmp.path();
        let path = dir.join("record.json");
        // A world-readable file planted at the destination is replaced, never written through
        // (which would keep its 0644 mode on the secret).
        fs::write(&path, b"planted").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_private_atomic(&path, b"{\"secret\":\"s\"}").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{\"secret\":\"s\"}");
        // Group/other bits only: the umask may strip owner bits too.
        assert_eq!(
            mode_of(&path) & 0o077,
            0,
            "mode {:o} leaks group/other bits",
            mode_of(&path)
        );
        let leftovers: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "record.json")
            .collect();
        assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");
    }
}
