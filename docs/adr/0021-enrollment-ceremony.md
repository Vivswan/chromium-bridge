# ADR-0021: Enrollment ceremony with a Secure Enclave key

- Status: Accepted
- Date: 2026-07-16
- Extends: [ADR-0019](0019-authenticated-ipc.md) (authenticated socket),
  [ADR-0020](0020-kernel-attested-peer-identity.md) (kernel-attested peers)

## Context

ADR-0019 and ADR-0020 authenticate the socket leg between the MCP server and
the native host. Two gaps remain on the other legs, both called out in the
threat model:

1. **Silent first pairing.** Nothing binds the extension to a specific host
   install, or the bridge to a specific enrollment act by the user. The first
   time the extension talks to a host, it has no way to know whether the human
   ever approved this pairing. A malicious `claude mcp add` (or any process
   that can write an MCP client config) could stand up the whole chain without
   the user noticing.
2. **Manifest substitution.** The native-messaging manifest is user-writable,
   so a same-user attacker can point the browser at a different host binary,
   which then drives the extension without touching the authenticated socket.

The zero-trust principle in AGENTS.md sets the bar: driving the browser must
require proof of identity, not presence on the machine, and the target is a
Codex-level guarantee that another program the user runs cannot use the bridge
silently.

## Decision

Add a one-time, user-present **enrollment ceremony**, on by default, performed
at MCP-client setup time (`claude mcp add`, then `browser-bridge pair`):

1. **The host mints a P-256 signing key inside the Secure Enclave**
   (`browser-bridge pair`). The private key is not extractable, and its
   keychain ACL requires **user presence** (Touch ID or the login password)
   for every signing operation. The key is stored under the stable label
   `com.browser-bridge.enclave.signing.v1` so the short-lived, Chrome-spawned
   host process can find the key the `pair` CLI created. Lookup fails closed
   unless exactly one key exists under the label and it carries the Secure
   Enclave token id; a planted software key, or duplicate labels, yield
   `key_invalid` rather than a signature.
2. **`pair` completes only with a key it minted itself, in that run.** Any
   same-user process can plant a key under our label, including an Enclave
   key minted *without* a presence ACL, and public API cannot read an ACL
   back to tell the difference. The only key whose ACL `pair` can vouch for
   is the one it just created. So if any key already exists, plain `pair`
   refuses and directs the user to `pair --reset`, which deletes everything
   under the label and mints fresh. `pair` then performs a presence-gated
   self-test signature; the Touch ID prompt is the ceremony, and declining it
   rolls the key back and leaves the machine unenrolled. On success, `pair`
   prints the public key (base64) and its SHA-256 fingerprint for the user to
   compare against the extension's enrollment screen, and records
   `{enrolled, granularity}` in a 0600 `config.json` next to the lock file.
   The config carries policy only; key material lives exclusively in the
   Enclave.
3. **The extension pins the public key** and verifies challenge proofs against
   it. Three native-messaging control frames carry the exchange
   (`src/protocol.rs`): `enclave_challenge {nonce, context?}` from the
   extension, answered by `enclave_proof {sig, key_id, pubkey}` or
   `enclave_error {reason}`. The signature covers
   `"browser-bridge-enclave-v1" || 0x00 || nonce || 0x00 || context`, ECDSA
   P-256 with SHA-256, delivered as the raw 64-byte `r||s` form WebCrypto
   verifies directly. The host converts Security.framework's DER output to
   that form itself. The host keeps no replay state, so nonce freshness is a
   normative extension-side requirement: nonces come from a cryptographic
   RNG, are single-use, and a proof is accepted only for the exact nonce the
   extension just issued (the full contract is documented on
   `EnclaveControl`).
4. **The native host answers control frames locally.** A filter in the
   stdin-to-socket pump (`src/native_host.rs`) recognizes the three control
   `type` tags, signs and replies without forwarding, and drops stray
   proof/error frames. Every other frame forwards byte for byte, so the
   protocol is backward compatible: an extension that never sends a challenge
   sees no change.
5. **Fail closed when not enrolled.** A challenge on an unenrolled machine
   gets `enclave_error {reason: "not_enrolled"}`; the pinning extension then
   refuses to treat the bridge as trusted. Re-pinning requires a new `pair`,
   which requires presence. `browser-bridge revoke` deletes the key, after
   which no proof can be produced anywhere.

## Why these choices

- **A Secure Enclave key, not a file secret.** Every file a host process can
  read, any same-user process can read (that is the lock-file lesson from
  ADR-0020). The Enclave private key cannot be read by anyone; it can only be
  *used*, and every use raises a presence prompt. So the thing the extension
  pins is bound to this machine's hardware and to a human at the keyboard,
  not to file permissions.
- **The vetted `security-framework` crate, not hand-rolled FFI.** The crate
  (MIT/Apache-2.0, passes `cargo deny`) wraps key generation, ACLs, keychain
  search, and signing with RAII reference counting. The bespoke-FFI route was
  taken in ADR-0020 only because the crate does not wrap `SecCode`; it does
  wrap everything this feature needs. One constraint the crate imposes:
  permanence is derived from setting a keychain location, and Enclave keys
  must live in the data-protection keychain, which macOS only grants to
  binaries codesigned with an application identifier. An ad-hoc dev build can
  generate and use software keys (the test suite does) but cannot store an
  Enclave key; `pair` reports this error explicitly rather than degrading.
- **DER to raw `r||s` conversion in the host.** `SecKeyCreateSignature`
  returns an X9.62 DER `ECDSA-Sig-Value`; WebCrypto's `verify` takes the
  fixed-width IEEE P1363 form. Converting on the host keeps the extension's
  crypto surface to one `crypto.subtle.verify` call. The parser is strict DER
  and rejects anything Security.framework could not have emitted, including
  long-form lengths, which cannot occur in a P-256 signature.
- **NUL-separated, domain-prefixed challenge messages.** The domain prefix
  stops cross-protocol replay of a proof; the NUL separators make the
  encoding injective, so no `(nonce, context)` pair collides with another.
  Both fields are length-bounded and validated before the keychain is
  touched, so malformed input cannot raise a presence prompt.
- **Revocation is not presence-gated, on purpose.** The keychain cannot bind
  `SecItemDelete` to the key's usage ACL, and an attacker who wanted the key
  gone could delete it directly anyway. Deletion only ever reduces capability:
  the extension's pin fails closed. Gating it would add a prompt without
  adding a guarantee.
- **`config.json` is informational.** The enforced decisions are the keychain
  ACL and the extension's pin. A same-user process that edits the config
  changes what `enclave-status` prints, nothing more. Claiming otherwise would
  be the kind of assumed (not mechanized) boundary AGENTS.md forbids.

## What this does and does not close

This change ships the host half only. None of the "closed" items below is
enforced until the extension-side pin (a separate task consuming this frame
contract) lands; until then the host answers challenges and ordinary bridge
traffic is unchanged. With both halves deployed:

- **Silent first pairing is closed.** Enrollment cannot complete without a
  Touch ID approval the user physically gives, and the fingerprint
  comparison between the `pair` terminal output and the extension UI defeats
  a man-in-the-middle host standing between them. A malicious
  `claude mcp add` gets `not_enrolled` and a pinning extension that refuses
  to proceed.
- **Silent re-pinning is closed.** Replacing the key requires another
  presence-gated `pair --reset`.
- **The first-pin race (threat model D1) is closed.** There is no
  trust-on-first-use window in which an attacker can seed the pin: the pin
  is created by the user-present ceremony itself, and `pair` never blesses a
  key it did not mint in that run, so a pre-planted key cannot inherit the
  ceremony's endorsement.

Not closed, stated plainly:

- **Post-enrollment same-user substitution.** MV3 kills the extension's
  service worker after a few idle minutes, and Chrome kills the native host
  with it, so a fresh host process spawns on every reconnect, roughly every
  five minutes in practice. Verifying presence per reconnect would mean a
  Touch ID prompt every five minutes, which no one would ship or keep
  enabled. Any per-reconnect verification therefore has to be silent, and a
  silent key, of any construction, can be exercised by any same-user process,
  because the Enclave gates *presence*, not *which process asked* (a
  same-user process can look up the key by label and request a signature; the
  prompt is the only barrier, and a silent path has no prompt). So after
  enrollment, a same-user attacker who re-executes our binary, or swaps the
  native-messaging manifest, is not distinguishable at reconnect time. The
  opt-in per-action presence tier (tracked separately, task #12) is the
  mechanism that would close this; this ADR does not claim it.
- **The MCP-client leg.** The stdio leg binds "a human authorized this
  machine's enrollment", not "a human authorized this tool call" or even
  "this specific client binary". A trusted-but-hijacked MCP client is
  unaffected by enrollment.
- **Non-macOS platforms.** Every entry point fails closed with
  `unsupported_platform`. Linux (TPM) and Windows (Hello) equivalents are
  possible but not designed here.

## Consequences

- New CLI surface: `pair`, `pair --reset`, `revoke`, `enclave-status`.
- New dependency, macOS-gated: `security-framework` v3 (plus its `-sys` crate
  for two ACL flag constants). `cargo deny` stays green.
- The native host is no longer a pure byte pump: it owns the three control
  frame types. The filter is a pure function (`classify_nm_frame`) with unit
  tests, and the e2e suite drives the real host with control frames, using
  only challenges that fail validation before keychain access so the suite
  never prompts.
- While a presence prompt is outstanding, the stdin-to-socket pump is
  blocked, so extension-to-server traffic waits until the user answers
  (server-to-extension still flows). Accepted: challenges occur only during
  the user-present ceremony, not in steady state.
- The Touch ID path itself cannot run in CI. The manual script is
  [docs/security/enrollment-manual-test.md](../security/enrollment-manual-test.md);
  release builds must be codesigned for the data-protection keychain before
  `pair` can succeed.
- The extension side (pin storage, WebCrypto verification, enrollment UI)
  consumes the frame contract in `src/protocol.rs` and is tracked as its own
  task; until it lands, the host answers challenges but nothing enforces the
  pin.

## Implementation pointers

- `src/enclave.rs`: key mint/lookup/sign/revoke, challenge message
  construction, DER conversion, `HostConfig`, and the CLI runners.
- `src/protocol.rs`: `EnclaveControl`, `classify_nm_frame`, and the frame
  contract documentation the extension consumes.
- `src/native_host.rs`: the control-frame filter in the stdin-to-socket pump.
- `tests/e2e.py::test_enclave_control_frames`: the real-process routing test.
