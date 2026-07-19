# Security Policy

chromium-bridge drives a **real, logged-in browser** on the user's machine.
It can read page content, cookies (including httpOnly), and web storage, and
can execute JavaScript in pages. This document covers how to report issues,
the security model in summary, and the review bar for security-relevant
changes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's **[Report a vulnerability](https://github.com/Vivswan/chromium-bridge/security/advisories/new)**
(Security -> Advisories) on this repository. Include:

- what an attacker can do (impact) and the trust boundary crossed,
- reproduction steps or a proof of concept,
- affected version / commit.

Expect an acknowledgement within a few days. Because this is a small project,
please allow reasonable time for a fix before any public disclosure.

## Scope

In scope: the Rust binary in all its roles (MCP server/broker, native host,
the registration engine, the enrollment and presence ceremonies, the kill
switch, the audit trail), the bridge socket and its authentication, harness
admission and the trusted-client allowlist, the revocation epoch, the MV3
extension (background/content/confirmation window), the site allowlist and
confirmation model, masking, and the desktop app's write paths into the core.

Examples of in-scope issues: bypassing the site allowlist or a confirmation
prompt; exfiltrating cookies/storage/page content past the mask; a page
influencing the extension into acting on a non-approved origin; the bridge
socket accepting an unauthenticated or unattested peer; a harness served
despite an enrolled allowlist that does not match it; releasing the kill
switch without user presence; forging an Enclave presence verdict; privilege
escalation via the native messaging host.

Out of scope: anything requiring a pre-compromised machine, or a malicious
MCP client the user themselves paired (a paired client is trusted by design;
see the [threat model](docs/security/threat-model.md)).

## The security model (summary)

See [docs/security/](docs/security/) for the full picture:

- [threat-model.md](docs/security/threat-model.md): actors, assets, what's
  trusted vs not, residual risks.
- [trust-boundaries.md](docs/security/trust-boundaries.md): the
  process/protocol boundaries and how each is enforced.
- [tool-risk-matrix.md](docs/security/tool-risk-matrix.md): every tool's
  blast radius and protections.

The design record for the current model is the ADR set
[0019](docs/adr/0019-authenticated-ipc.md),
[0020](docs/adr/0020-kernel-attested-peer-identity.md),
[0021](docs/adr/0021-enrollment-ceremony.md), and
[0023](docs/adr/0023-workspace-monorepo-tauri-app.md) through
[0031](docs/adr/0031-touch-id-confirmations-and-presence-grants.md).

Key invariants:

- **stdout is protocol.** The binary never prints diagnostics there; only
  framed/NDJSON messages (a stray write corrupts the stream).
- **Read-only credential access.** Cookies/storage can be read (masked),
  never written. There is no `cookie_set`/`storage_set` by design.
- **Approve-per-origin + confirm high-risk.** Page ops need an allowlisted
  origin; submit/link clicks, key presses, selects, tab close, uploads, and
  `page_eval` confirm on an extension-owned window the page cannot reach.
  On an enrolled Mac, `page_eval` and `page_upload` approval is a Secure
  Enclave user-presence signature (Touch ID or the login password,
  [ADR-0031](docs/adr/0031-touch-id-confirmations-and-presence-grants.md)).
  Every confirmation gate is on by default; each is a documented setting,
  and relaxing one is an explicit, informed choice (see the defaults table
  below).
- **Bridge auth.** No bridge connection is served until it passes, in order:
  the kernel peer-UID check, mutual kernel-attested executable identity, an
  HMAC-SHA256 challenge-response over a per-run secret (0600 lock file), and
  a mandatory role-declaring attach frame
  ([ADR-0019](docs/adr/0019-authenticated-ipc.md),
  [ADR-0020](docs/adr/0020-kernel-attested-peer-identity.md),
  [ADR-0024](docs/adr/0024-multi-client-attested-pairing-and-broker.md)).
- **Harness admission.** Once the trusted-client allowlist exists, no MCP
  client is served unless its attested code identity matches an entry;
  authorization keys on the attested anchor, never a self-asserted name
  ([ADR-0024](docs/adr/0024-multi-client-attested-pairing-and-broker.md)).
- **Any-side revocation.** A monotonic epoch is re-read at every enforcement
  point; revoking from any surface drops live connections and refuses
  re-attach, fail-closed ([ADR-0025](docs/adr/0025-any-side-revocation-epoch.md)).
- **Fail-closed kill switch.** One latch halts everything from any trusted
  surface; release demands proof of user presence and refuses on an
  unreadable record ([ADR-0030](docs/adr/0030-global-kill-switch-and-audit.md)).
- **Log-after-decide audit.** Security decisions (admissions, refusals,
  confirmations, revocations, kill transitions, tool calls) are recorded to
  stderr and a durable 0600 `audit.log`. The trail is best-effort by design:
  recording can never gate or fail a decision, and a failed write drops the
  record visibly (a `dropped` counter) rather than blocking.

## Platform support

The strong bridge guarantees hold on macOS and Linux only. There the broker
and the native hosts talk over a Unix-domain socket with no listening port,
created 0600 inside a 0700 per-user directory. The server rejects any peer
whose UID differs from its own, and both ends kernel-attest that the other
side is running this exact binary (Linux: SHA256 of `/proc/<pid>/exe`;
macOS: the running image's code-directory hash) before the HMAC handshake.

Windows support is best-effort. None of those mechanisms is compiled in: the
bridge is a loopback TCP socket that any process on the machine can reach,
the only gate is the HMAC challenge-response over the per-run secret in the
lock file, and harness admission is unenforced (there is no attestation to
key it on). The lock file gets no explicit restrictive mode on Windows, so
the secret's confidentiality rests on the default permissions of the
per-user runtime directory (normally `%LOCALAPPDATA%\chromium-bridge`,
falling back to the temp directory when `LOCALAPPDATA` and `USERPROFILE` are
unset). The non-abuse goal stated in the threat model (another program you
are running must not be able to drive the bridge silently) does not hold on
Windows: any same-user process that reads the lock file can authenticate.
The server logs a prominent warning at startup on Windows. Treat the bridge
accordingly there; the full scoping is in the
[threat model](docs/security/threat-model.md) and
[trust boundaries](docs/security/trust-boundaries.md) docs. The Touch ID
presence gates are macOS-only by nature; other platforms use the documented
interactive fail-closed floors ([ADR-0031](docs/adr/0031-touch-id-confirmations-and-presence-grants.md)).

## page_eval and confirmation defaults (fail-safe)

`page_eval` runs arbitrary JavaScript in a real, logged-in page, so its
defaults are set to fail safe (ADR-0008, updated by ADR-0027/0031):

- **Every `page_eval` call reconfirms.** The confirmation (showing the full
  code, target URL, and tab title) is shown on every call; on an enrolled
  Mac it is a Touch ID prompt. `page_eval` is deliberately excluded from the
  same-origin grace window, so there is no silent-eval window: one approval
  never covers a later, different payload.
- **The grace window is click-only.** `confirmGraceMs` (default 60000 ms)
  lets a repeated same-origin click/submit skip re-prompting within the
  window. It does not apply to `page_eval`. Those clicks are lower-risk and
  observable in the UI.

These defaults are user-configurable knobs, not removed gates. A power user
can still relax them, and doing so is an explicit, informed choice:

| Setting | Default | Relaxing it means | Residual risk you accept |
|---------|---------|-------------------|--------------------------|
| `confirmPageEval` | `true` | `false` = `page_eval` runs with no prompt | Arbitrary JS executes silently on approved origins |
| `pageEvalEnabled` | `true` | `false` = `page_eval` refused entirely | (hardening, not a relaxation) |
| `touchIdConfirm` | `true` | `false` = enrolled Macs fall back to the extension-window confirmation for `page_eval`/`page_upload` | The verdict is a window click the extension trusts, not a hardware tap |
| `confirmHighRiskClick` | `true` | `false` = submit/link clicks, key presses, and selects run with no prompt | A prompt-injected model can act on approved origins silently |
| `confirmTabClose` | `true` | `false` = `tab_close` runs with no prompt | Silent data loss in a closed tab |
| `confirmGraceMs` | `60000` | Larger = longer click/submit silence window; `0` = every click reconfirms | A same-origin click/submit within the window is silent (never eval) |

The options page shows an explicit warning on the `confirmPageEval` toggle.
The site allowlist (per-origin) and the global kill switch remain in force
regardless of these settings.

## Masking is heuristic and best-effort

Cookie, storage, page-text, and `page_eval`-result masking (applied at the
service-worker egress, once for both page backends) is a **heuristic,
best-effort** filter, not a guarantee. It targets common secret shapes
(JWTs, long hex, long digit runs, opaque base64url tokens of >=32 chars
containing both a letter and a digit, and `bearer`/`key=` assignments) and
redacts sensitive-looking key names. The token rule keys off length plus the
presence of a letter and a digit, not a true entropy measure, so it can both
over-mask (a long mixed letter+digit identifier that is not secret) and
under-mask. It will miss secrets that do not match these shapes: short
tokens, secrets below the length thresholds, all-letter or all-digit tokens,
tokens broken up by characters outside the matched set (whitespace, `.`,
`/`, `+`, `=`), or application-specific formats. Masking reduces accidental
leakage into the model context and logs; it is not a substitute for treating
any `page_eval` result or storage dump as potentially sensitive. Masking can
be disabled per surface (`evalMask`), which removes this filter entirely;
`storage_get` masking is not user-toggleable.

## Release artifact integrity

Release binaries are built by GitHub Actions from the tagged commit
(`.github/workflows/release.yml`) with a deterministic build
(`scripts/build-repro.sh`: pinned toolchain, path remapping,
`SOURCE_DATE_EPOCH`, `--locked`), so the binary's hash can be re-derived
from the tag. Byte-identical rebuilds are verified across clean builds and
checkout paths on the same machine; matching a published hash from another
machine requires the same rustup toolchain and platform SDK, and independent
cross-machine rebuilds have not been demonstrated yet. Each release
publishes the archive's SHA-256, a separate SHA-256 of the binary inside it
(`<name>.binary.sha256`), and a build provenance attestation covering both.

Verification is yours to run, before you execute anything from an archive:

```sh
shasum -a 256 -c chromium-bridge-<tag>-<platform>-<arch>.tar.gz.sha256
gh attestation verify chromium-bridge-<tag>-<platform>-<arch>.tar.gz --repo Vivswan/chromium-bridge
# after extraction, the bare binary can be verified on its own:
gh attestation verify chromium-bridge --repo Vivswan/chromium-bridge
shasum -a 256 -c chromium-bridge-<tag>-<platform>-<arch>.binary.sha256
```

Verifying the whole archive also covers the bundled `extension/dist`.
Registration (`doctor --fix`, or the app) points browsers at the binary as
it sits on disk; it downloads nothing and adds no verification step of its
own, so verify first, then register. You can also skip the release pipeline
entirely: the binary builds reproducibly, so install the exact toolchain
pinned in `rust-toolchain.toml` via [rustup](https://rustup.rs) (a Homebrew
or distro rustc embeds different standard-library paths and will not match),
on the same platform the release targets, then:

```sh
git checkout <tag>
./scripts/build-repro.sh
shasum -a 256 target/release/chromium-bridge   # compare with the release's .binary.sha256
```

Known gaps, stated plainly:

- Reproducibility is verified across clean rebuilds and checkout paths on
  one machine so far; the archives themselves are not bit-reproducible (tar
  and gzip embed metadata), which is why the release publishes the binary's
  hash separately.
- Binaries are not yet Apple-notarized for standalone distribution, and the
  Windows exe is not Authenticode-signed. macOS verification today is the
  SHA-256 and attestation above rather than a notarization check. The
  desktop app bundle is codesigned with its entitlement chain verified at
  build time ([ADR-0026](docs/adr/0026-tauri-signing-and-entitlement-chain.md));
  once a distribution signing identity lands, released binaries will no
  longer be byte-identical to local rebuilds and verification will move to
  comparing cdhashes.
- A hostile process already running as the same user during install is out
  of scope here; that boundary is enforced at runtime by the bridge's peer
  attestation and harness admission, not at install time.

## Identifiers (rebrand, 2026-07)

The project renamed from the upstream `browser-bridge` to `chromium-bridge`
([ADR-0023](docs/adr/0023-workspace-monorepo-tauri-app.md)). The
security-relevant identifiers are now:

- native-messaging host id: `com.vivswan.chromium_bridge.host` (also the
  manifest filename stem and the extension's `connectNative` argument;
  `scripts/check-extension-id.ts` asserts all copies agree),
- enclave keychain label: `com.vivswan.chromium-bridge.enclave.signing.v1`,
- enclave challenge domain: `chromium-bridge-enclave-v1` (host and extension
  changed together; no enrolled key predated the rename, so there was no key
  migration),
- the extension id `mkjjlmjbcljpcfkfadfmhblmmddkdihf` is derived from the
  manifest `key` and did not change.

An install registered under the old host id stops working until
re-registered; that is a naming change, not a security regression.

Upgrading from a pre-rebrand install: the current tooling (`doctor --fix`,
`uninstall`, `revoke`) only touches new-labeled artifacts, so it will not
clean up an old `com.browser_bridge.host.json` manifest, the old
`browser-bridge` runtime directory, or an Enclave key under the old
`com.browser-bridge.enclave.signing.v1` label. Those leftovers grant no
capability (the challenge domains differ, an old pin fails closed, and the
new host reports `not_enrolled`), but to remove them run the old release's
uninstaller and `browser-bridge revoke` with the old binary before switching
over.

## Lock poisoning policy (std::sync::Mutex)

The core is built with panics aborting the process, but library code cannot
assume it (tests and future embeddings unwind), so every
`Mutex::lock().unwrap_or_else(...)` recover site is a policy decision, not
noise. The rule:

- **Refuse on authorization paths.** Where poisoned state could admit,
  serve, or free capacity for a peer, treat the poison as untrustworthy
  state and refuse (the broker's attach path, its revocation registry, and
  the kill switch's reach all do this; see `broker.rs`).
- **Recover on cleanup and egress paths.** Where refusing would leak a slot
  or wedge a shutdown, recover the inner value and proceed (the broker's
  release and shutdown paths).
- The two writer-leg recover sites in `native_host.rs` (the stdout frame
  writer in `write_control_reply` and the socket-to-stdout pump) are
  deliberate members of the second class: the mutex serializes frame writes
  to stdout, the guarded `BufWriter` carries no security state, and refusing
  to write would silently wedge the browser leg. They predate this note and
  are inventoried here for completeness.

A new `Mutex` in the core must pick a side explicitly and say why at the
recover site.

## Security-relevant changes (review bar)

A change is **security-relevant**, and must carry the
[security-change](.github/ISSUE_TEMPLATE/security-change.yml) checklist,
update the [tool risk matrix](docs/security/tool-risk-matrix.md), and (if it
moves a trust boundary) the [threat model](docs/security/threat-model.md),
if it:

- adds/broadens a Chrome permission or host permission,
- adds a way to read new sensitive data, or any write capability,
- changes confirmation, allowlist, masking, or presence-gate logic,
- changes the bridge authentication, harness admission, the trusted-client
  allowlist, the revocation epoch, the kill switch, the lock file, or the
  run secret,
- changes the enrollment ceremony, the Enclave key policy, or the audit
  trail's failure behavior,
- adds outbound network/IPC, or widens `page_eval`.

Such PRs should add a **negative** security test (proving the boundary
holds), in addition to the positive one. Extra review care applies to the
security-critical surfaces listed in [AGENTS.md](AGENTS.md):
`src/packages/core/src/ipc/`, `protocol.rs`, `broker.rs`, `allowlist.rs`,
`revocation.rs`, `kill.rs`, `presence/`, `enclave/`, the extension's
allowlist/eval/confirmation code, and `wxt.config.ts`.

## Supported versions

Pre-1.0: only the latest release is supported. Security fixes ship in a new
patch/minor release.
