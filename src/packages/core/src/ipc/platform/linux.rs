//! Linux mechanisms: image identity as the SHA256 of `/proc/<pid>/exe` (the
//! kernel's magic symlink to the executable inode), and peer credentials via
//! `SO_PEERCRED`.
// Quarantined unsafe: SO_PEERCRED getsockopt FFI. unsafe_code is denied
// workspace-wide; this module is one of the audited exceptions.
#![allow(unsafe_code)]

use std::io::{self, Read};
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use super::super::socket::BridgeStream;

/// Error message for an unmeasurable self identity, used by
/// [`super::super::attest`].
pub(crate) const OWN_IDENTITY_ERROR: &str = "cannot hash own executable";

/// This process's own executable identity: the SHA256 of its on-disk image.
pub(crate) fn own_identity() -> io::Result<String> {
    exe_hash_of_pid(std::process::id())
}

/// The peer's running-image identity, measured the same way as
/// [`own_identity`].
pub(crate) fn peer_identity(stream: &BridgeStream) -> io::Result<String> {
    exe_hash_of_pid(super::super::peercred::peer_pid(stream)?)
}

/// The running-image identity of an arbitrary process named by pid. Carries
/// the pid-reuse race documented on [`super::super::peercred::peer_pid`].
pub(crate) fn pid_identity(pid: u32) -> io::Result<String> {
    exe_hash_of_pid(pid)
}

/// The full client identity of an arbitrary process named by pid: its image
/// hash plus its signing Team ID. Linux code signing is not part of the base
/// system, so there is no Team ID to read here and the anchor is always the
/// hash; `team_id` is therefore always `None`. Carries the same pid-reuse race
/// as [`pid_identity`].
pub(crate) fn pid_client_identity(pid: u32) -> io::Result<super::super::ClientIdentity> {
    Ok(super::super::ClientIdentity {
        hash: exe_hash_of_pid(pid)?,
        team_id: None,
    })
}

/// SHA256 (lowercase hex) of a running process's on-disk executable, named by
/// pid. We hash `/proc/<pid>/exe`, the kernel's magic symlink to the actual
/// executable inode: it follows to the real backing file even if the path was
/// later replaced, so once the pid is resolved the digest reflects the running
/// image (the pid-resolution race is noted on
/// [`super::super::peercred::peer_pid`]). macOS does not use this: it attests
/// the running image directly through the Security framework (see
/// [`super::macos`]), which is bound to the running image and needs no path
/// re-open.
fn exe_hash_of_pid(pid: u32) -> io::Result<String> {
    hash_file(&PathBuf::from(format!("/proc/{pid}/exe")))
}

/// Stream a file through SHA256 and return the lowercase hex digest.
fn hash_file(path: &std::path::Path) -> io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        // read() never returns more than buf.len(); a broken Read impl that
        // did would corrupt the identity hash, so refuse it instead.
        let chunk = buf.get(..n).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "read returned an impossible length",
            )
        })?;
        hasher.update(chunk);
    }
    Ok(super::super::rand::hex_encode(hasher.finalize().as_slice()))
}

/// Peer credentials of a connected Unix-domain socket via `SO_PEERCRED`.
pub(crate) fn peer_uid(fd: libc::c_int) -> io::Result<u32> {
    Ok(peer_ucred(fd)?.uid)
}

pub(crate) fn peer_pid(fd: libc::c_int) -> io::Result<u32> {
    let pid = peer_ucred(fd)?.pid;
    u32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "peer pid out of range"))
}

fn peer_ucred(fd: libc::c_int) -> io::Result<libc::ucred> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected peer-credential size from SO_PEERCRED",
        ));
    }
    Ok(unsafe { cred.assume_init() })
}
