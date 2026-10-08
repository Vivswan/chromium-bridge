//! Files and directories the engine creates: atomic replacement that never writes through an existing entry,
//! and the modes a machine-wide registration needs so every account's browser can reach what it points at.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The directories missing for `dir` to exist, outermost first, once its existing ancestor passed the
/// reachability rule. Directories that already exist are not ours to loosen: one that other accounts
/// cannot traverse (a root-made 0700 `/etc/opt/chrome`) is refused here, before anything is created,
/// since a manifest under it would read healthy and be unreachable for every other account.
pub(super) fn plan_traversable_dirs(dir: &Path, root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut cursor = dir;
    while !cursor.as_os_str().is_empty() && fs::symlink_metadata(cursor).is_err() {
        missing.push(cursor.to_path_buf());
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => break,
        }
    }
    traversable_by_every_account(cursor, root).map_err(std::io::Error::other)?;
    missing.reverse();
    Ok(missing)
}

/// Make the planned directories, each 0755 whatever the umask (a maintainer script may run under 077),
/// since other accounts' browsers read what sits under them.
pub(super) fn create_traversable_dirs(planned: &[PathBuf]) -> Result<(), String> {
    for path in planned {
        let could_not = |e: std::io::Error| format!("could not create {}: {e}", path.display());
        fs::create_dir(path).map_err(could_not)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(could_not)?;
        }
    }
    Ok(())
}

/// Whether every account can launch `exe`: the file readable and executable by others, and each
/// directory from it up to (not including) `root` traversable by them. A machine-wide registration that
/// points into one account's home (`sudo ~/.local/lib/genkan/genkan doctor --fix
/// --system`) reads healthy and fails for everyone else at launch, so it is refused before any write.
/// `root` is the directory whose reachability is the caller's premise: `/` for a real install, the
/// fixture root in tests. Windows ACLs are not inspected (residual: the .msi installs per user).
pub(super) fn launchable_by_every_account(exe: &Path, root: &Path) -> Result<(), String> {
    if unix_mode(exe)? & 0o005 != 0o005 {
        return Err(format!(
            "{} is not readable and executable by other accounts, so a machine-wide registration \
             would fail for them; install the binary under /usr/local/bin, or drop --system",
            exe.display()
        ));
    }
    match exe.parent() {
        Some(dir) => traversable_by_every_account(dir, root),
        None => Ok(()),
    }
}

/// Whether other accounts can traverse `dir` and every directory above it, up to (not including) `root`.
fn traversable_by_every_account(dir: &Path, root: &Path) -> Result<(), String> {
    for dir in dir.ancestors().take_while(|d| *d != root) {
        if unix_mode(dir)? & 0o001 == 0 {
            return Err(format!(
                "{} is not traversable by other accounts, so their browsers cannot reach what sits \
                 under it; fix its mode, or drop --system",
                dir.display()
            ));
        }
    }
    Ok(())
}

/// The Unix permission bits of `path`; off Unix every bit reads set, so the reachability checks pass
/// (Windows ACLs are not inspected: a residual, the .msi installs per user).
fn unix_mode(path: &Path) -> Result<u32, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .map_err(|e| format!("cannot inspect {}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(0o777)
    }
}

/// Write `bytes` to `path` atomically: a uniquely named temp file is created
/// exclusively beside it (so a planted entry is never adopted or followed),
/// given its mode, fsynced, and renamed over the destination; the directory
/// is then fsynced so the entry survives a crash. The final path is replaced,
/// never written through: rename replaces even a symlink at the final
/// component without following it. On any failure the temp file is removed.
pub(super) fn write_atomic(path: &Path, bytes: &[u8], executable: bool) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("target path has no parent directory"))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    // Directories cannot be fsynced on Windows.
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}
