//! The Authenticode publisher of an image file: `WinVerifyTrust` verifies the
//! embedded signature against the machine's trust store, and the leaf
//! certificate's subject names the publisher, the Windows analog of a macOS
//! Team ID. A catalog-signed image (most of Windows itself) has no embedded
//! signature and anchors by hash alone.
#![expect(
    unsafe_code,
    reason = "audited FFI quarantine: WinVerifyTrust and the signer-chain helpers, each behind a safe wrapper"
)]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Security::Cryptography::{
    CertNameToStrW, CERT_NAME_STR_REVERSE_FLAG, CERT_X500_NAME_STR, CRYPT_INTEGER_BLOB,
    X509_ASN_ENCODING,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

use super::super::super::identity::TeamId;
use super::{publisher_anchor, TrustStatus};

/// The publisher anchor of the image at `image`, `None` when the image is
/// unsigned or its chain is not trusted. Runs where a harness is measured
/// (server startup, `pair-client --this-parent`), not on the bridge accept
/// path, which hashes the image alone. Revocation is not checked
/// (`WTD_REVOKE_NONE`); the threat model's residual list owns why.
pub(crate) fn publisher_of(image: &Path) -> io::Result<Option<TeamId>> {
    let session = TrustSession::verify(image)?;
    let status = TrustStatus::from_hresult(session.status);
    let subject = match status {
        TrustStatus::Trusted => Some(session.signer_subject()?),
        TrustStatus::Untrusted(code) => {
            log_warn!(
                "ipc",
                "image {} is signed but its chain is not trusted (HRESULT {code:#x}); anchoring by hash alone",
                image.display()
            );
            None
        }
        TrustStatus::Unsigned | TrustStatus::Tampered => None,
    };
    publisher_anchor(status, subject)
}

/// One `WinVerifyTrust` verification with its provider state held open, so the
/// signer chain can be read, and closed exactly once on drop. The file record
/// and path are boxed because the data struct points at them.
struct TrustSession {
    data: WINTRUST_DATA,
    status: i32,
    _file: Box<WINTRUST_FILE_INFO>,
    _path: Vec<u16>,
}

impl TrustSession {
    fn verify(image: &Path) -> io::Result<TrustSession> {
        let path: Vec<u16> = image
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut file = Box::new(WINTRUST_FILE_INFO {
            cbStruct: size_u32::<WINTRUST_FILE_INFO>()?,
            pcwszFilePath: path.as_ptr(),
            hFile: ptr::null_mut(),
            pgKnownSubject: ptr::null_mut(),
        });
        let data = WINTRUST_DATA {
            cbStruct: size_u32::<WINTRUST_DATA>()?,
            pPolicyCallbackData: ptr::null_mut(),
            pSIPClientData: ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: ptr::from_mut(&mut *file),
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: ptr::null_mut(),
            pwszURLReference: ptr::null_mut(),
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            dwUIContext: 0,
            pSignatureSettings: ptr::null_mut(),
        };
        let mut session = TrustSession {
            data,
            status: 0,
            _file: file,
            _path: path,
        };
        session.status = session.call();
        Ok(session)
    }

    /// Run the verification action for the current `dwStateAction`.
    fn call(&mut self) -> i32 {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: `data` and the file record and path it points at are live
        // fields of `self`, laid out as WinTrust documents; UI is off, so no
        // window handle is needed.
        unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                ptr::from_mut(&mut self.data).cast(),
            )
        }
    }

    /// The X.500 subject of the leaf (signing) certificate, the same string
    /// Windows's own publisher rules key on.
    fn signer_subject(&self) -> io::Result<String> {
        // SAFETY: hWVTStateData belongs to this open session; the helper returns
        // a pointer owned by that state, null when there is none.
        let provider = unsafe { WTHelperProvDataFromStateData(self.data.hWVTStateData) };
        if provider.is_null() {
            return Err(io::Error::other("WinVerifyTrust kept no provider data"));
        }
        // SAFETY: `provider` is live for the session; index 0 is the primary
        // signer, null when absent.
        let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
        if signer.is_null() {
            return Err(io::Error::other("trusted signature without a signer"));
        }
        // SAFETY: `signer` is live for the session; index 0 is the leaf
        // certificate, null when absent.
        let cert = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
        if cert.is_null() {
            return Err(io::Error::other("signer without a leaf certificate"));
        }
        // SAFETY: a non-null provider certificate is fully initialized for the
        // session's lifetime.
        let context = unsafe { (*cert).pCert };
        if context.is_null() {
            return Err(io::Error::other("leaf certificate without a context"));
        }
        // SAFETY: a live CERT_CONTEXT carries its decoded CERT_INFO.
        let info = unsafe { (*context).pCertInfo };
        if info.is_null() {
            return Err(io::Error::other("certificate context without decoded info"));
        }
        // SAFETY: `info` is live for the session; Subject is its encoded name.
        let subject: *const CRYPT_INTEGER_BLOB = unsafe { ptr::addr_of!((*info).Subject) };
        name_to_string(subject)
    }
}

impl Drop for TrustSession {
    fn drop(&mut self) {
        self.data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = self.call();
    }
}

/// `CertNameToStrW` over an encoded name, in the X.500 form with the common
/// name first (`CN=..., O=..., L=..., S=..., C=...`).
fn name_to_string(name: *const CRYPT_INTEGER_BLOB) -> io::Result<String> {
    let form = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
    // SAFETY: `name` points at a live encoded name; a null output with zero
    // size is the documented size query.
    let needed = unsafe { CertNameToStrW(X509_ASN_ENCODING, name, form, ptr::null_mut(), 0) };
    let capacity =
        usize::try_from(needed).map_err(|_| io::Error::other("name length exceeds usize"))?;
    let mut buf = vec![0u16; capacity];
    // SAFETY: `buf` holds exactly the `needed` units the size query reported;
    // the name is unchanged since.
    let written =
        unsafe { CertNameToStrW(X509_ASN_ENCODING, name, form, buf.as_mut_ptr(), needed) };
    // The count includes the terminating NUL.
    let text_len = usize::try_from(written)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| io::Error::other("signer subject could not be rendered"))?;
    let units = buf
        .get(..text_len)
        .ok_or_else(|| io::Error::other("signer subject longer than its buffer"))?;
    Ok(String::from_utf16_lossy(units))
}

fn size_u32<T>() -> io::Result<u32> {
    u32::try_from(std::mem::size_of::<T>()).map_err(|_| io::Error::other("struct size exceeds u32"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unsigned_image_earns_no_publisher() {
        // External fact: WinVerifyTrust answers TRUST_E_NOSIGNATURE for a PE
        // with no embedded signature, which the anchor folds to None. The test
        // binary cargo builds is such an image, so this also pins that the
        // whole call sequence (session, verdict, close) runs without error.
        let me = std::env::current_exe().unwrap();
        assert_eq!(publisher_of(&me).unwrap(), None);
    }
}
