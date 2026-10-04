//! The bridge's identity constants: the values that make this deployment of
//! chromium-bridge recognizably itself across every process boundary. This
//! module is the canonical source; the TypeScript side receives
//! them through the generated `src/packages/shared/src/identity.gen.ts` (`moon
//! run gen`), the registration engine consumes them directly, `moon run
//! check-gen` proves the generated copy fresh, and `scripts/check-extension-id.ts`
//! verifies the built extension manifest and that this file stays the only
//! definition site.

/// The native-messaging host id: what the extension passes to
/// `connectNative`, what the host manifest declares as `name`, and the host
/// manifest's filename stem (`<id>.json`). Chrome allows only dot-separated
/// segments of `[a-z0-9_]`.
pub const NATIVE_HOST_ID: &str = "com.vivswan.chromium_bridge.host";

/// The extension's pinned manifest `key`: the base64 DER public key the
/// extension build injects into its manifest, from which Chrome derives the
/// extension ID (sha256 of the DER bytes, first 16 bytes, hex mapped onto
/// a-p). The derivation itself lives in the generator
/// (`scripts/gen-ops.ts`); the host manifest pins the derived id in
/// `allowed_origins`, so a build without this key is rejected by Chrome.
pub const EXTENSION_MANIFEST_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuE+qrxaJ5pXhQu4k+ecB0cvAXk1bKdCNjwV49Nepgj4j6aj4EGb6LS8rnnnkpPN3Ixh/tFFS4CU/vDa2ZBZS8pUOcLTOUjii6/MyIDNCCs4D6fg/746ko0ISBWEOynVGBFRaA9YYFm3F6K1Damnw3uZnr2nnTAvnDAoBvHyCVry1phyY7XCVFSQ6R7S2vZHUTBgJhd2dEGI7+OqKbPXgnFLVwITbDk8A8Z4S3lZlbVQidwtUZuhe9cPt3Jgxj+ytxcoftmR1zssj3QJ2NAhuk/NDmlyrJ4CL9tk1/ludMdJbd6pcPmHcV3EDm7btheksLERX6+5/N+vL+46VOg4PLQIDAQAB";

/// The extension ID Chrome derives from [`EXTENSION_MANIFEST_KEY`] (sha256
/// of the DER key bytes, first 16 bytes, hex mapped onto a-p). Pinned as a
/// constant because the host manifest's `allowed_origins` and the
/// registration/doctor surfaces need it without a crypto round-trip; the
/// derivation is recomputed and asserted against this literal by
/// `scripts/gen-ops.ts` (`moon run gen`, held fresh by `moon run check-gen`),
/// so this value cannot drift from the key.
pub const PINNED_EXTENSION_ID: &str = "mkjjlmjbcljpcfkfadfmhblmmddkdihf";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_id_satisfies_chromes_charset() {
        // Dot-separated segments of [a-z0-9_]: no empty segments, no
        // leading/trailing dots (Chrome rejects the manifest otherwise).
        assert!(!NATIVE_HOST_ID.is_empty());
        for segment in NATIVE_HOST_ID.split('.') {
            assert!(
                !segment.is_empty()
                    && segment
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "segment {segment:?} violates Chrome's host-id charset"
            );
        }
    }
}
