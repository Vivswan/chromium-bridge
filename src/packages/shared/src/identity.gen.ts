// GENERATED from the Rust core (src/packages/core/src/identity.rs) by
// scripts/gen-ops.ts - DO NOT EDIT. Run `moon run gen`.
//
// The bridge's identity constants. PINNED_EXTENSION_ID is DERIVED from
// EXTENSION_MANIFEST_KEY (Chrome's own id derivation), so it cannot drift
// from the generated manifest. scripts/check-extension-id.ts verifies the
// built manifest against the same values.

// The extension ID Chrome derives from the manifest `key`. The native-
// messaging host manifest pins this in `allowed_origins`, so a build without
// the pinned key is rejected by the host.
export const PINNED_EXTENSION_ID = "mkjjlmjbcljpcfkfadfmhblmmddkdihf";

// The extension's pinned manifest `key` (base64 DER public key).
// src/apps/extension/wxt.config.ts injects it into the generated manifest.
export const EXTENSION_MANIFEST_KEY =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuE+qrxaJ5pXhQu4k+ecB0cvAXk1bKdCNjwV49Nepgj4j6aj4EGb6LS8rnnnkpPN3Ixh/tFFS4CU/vDa2ZBZS8pUOcLTOUjii6/MyIDNCCs4D6fg/746ko0ISBWEOynVGBFRaA9YYFm3F6K1Damnw3uZnr2nnTAvnDAoBvHyCVry1phyY7XCVFSQ6R7S2vZHUTBgJhd2dEGI7+OqKbPXgnFLVwITbDk8A8Z4S3lZlbVQidwtUZuhe9cPt3Jgxj+ytxcoftmR1zssj3QJ2NAhuk/NDmlyrJ4CL9tk1/ludMdJbd6pcPmHcV3EDm7btheksLERX6+5/N+vL+46VOg4PLQIDAQAB";

// The native-messaging host id: what the extension passes to connectNative,
// what the Rust host expects, and the host manifest's name/filename stem.
export const NATIVE_HOST_ID = "com.vivswan.chromium_bridge.host";
