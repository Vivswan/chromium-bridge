#![expect(
    unsafe_code,
    reason = "audited FFI quarantine: the SO_PEERCRED getsockopt call, behind a safe wrapper"
)]

use std::io;
use std::path::PathBuf;

use super::super::identity::{ClientIdentity, HashDigest};
use super::super::socket::BridgeStream;

pub(crate) const OWN_IDENTITY_ERROR: &str = "cannot hash own executable";

pub(crate) fn own_identity() -> io::Result<HashDigest> {
    pid_identity(std::process::id())
}

pub(crate) fn peer_identity(stream: &BridgeStream) -> io::Result<HashDigest> {
    pid_identity(super::super::peercred::peer_pid(stream)?)
}

/// Linux code signing is not part of the base system, so the anchor is the hash and `signer` is always
/// `None`.
pub(crate) fn pid_client_identity(pid: u32) -> io::Result<ClientIdentity> {
    Ok(ClientIdentity {
        hash: pid_identity(pid)?,
        signer: None,
    })
}

/// `/proc/<pid>/exe` is the kernel's magic symlink to the executable inode, so it follows to the real backing
/// file even after the path was replaced. The pid-resolution race is noted on
/// [`super::super::peercred::peer_pid`].
pub(crate) fn pid_identity(pid: u32) -> io::Result<HashDigest> {
    HashDigest::of_file(&PathBuf::from(format!("/proc/{pid}/exe")))
}

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
    let expected_len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ucred size exceeds socklen_t"))?;
    let mut len = expected_len;
    // SAFETY: cred/len are live stack locals sized and typed for SO_PEERCRED;
    // an invalid fd yields an error return (EBADF), never a wild write.
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
    if len != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected peer-credential size from SO_PEERCRED",
        ));
    }
    // SAFETY: rc == 0 with the returned len still the full size of ucred
    // (checked above) proves the kernel wrote the whole struct, which is what
    // licenses assume_init. Do not drop that length check as redundant.
    Ok(unsafe { cred.assume_init() })
}
