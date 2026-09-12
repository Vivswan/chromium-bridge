# Security policy

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/Vivswan/chromium-bridge/security/advisories/new) ("Report a vulnerability"). If that page is unavailable, contact [@Vivswan](https://github.com/Vivswan) directly instead.

A useful report includes:

- what an attacker can do (impact), and where trust is broken,
- reproduction steps or a proof of concept,
- the affected version or commit.

What to expect, and what we ask:

- an acknowledgement within a few days,
- a fix in the next release once the report is confirmed,
- reasonable time for that fix before any public disclosure,
- no real credentials in the report; redact everything that looks like a key.

## Supported versions

Only the latest release is supported.

chromium-bridge drives a **real, logged-in browser** on the user's machine. It can read page content, cookies (including httpOnly), and web storage, and can execute JavaScript in pages.

## Scope

In scope:

- the Rust binary in all its roles: MCP server/broker, native host, the registration engine, the enrollment and presence ceremonies, the kill switch, the audit trail,
- the bridge socket and its authentication,
- harness admission and the trusted-client allowlist,
- the revocation epoch,
- the MV3 extension (background/content/confirmation window),
- the site allowlist and confirmation model,
- masking,
- the desktop app's write paths into the core.

Examples of in-scope issues:

- bypassing the site allowlist or a confirmation prompt,
- exfiltrating cookies/storage/page content past the mask,
- a page influencing the extension into acting on a non-approved origin,
- the bridge socket accepting an unauthenticated or unattested peer,
- a harness served despite an enrolled allowlist that does not match it,
- releasing the kill switch without user presence,
- forging an Enclave presence verdict,
- privilege escalation via the native messaging host.

Out of scope:

- anything requiring a pre-compromised machine,
- a malicious MCP client the user themselves paired (a paired client is trusted by design; see the [threat model](../docs/security/threat-model.md)).

## The security model (summary)

See [docs/security/](../docs/security/) for the full picture:

- [threat-model.md](../docs/security/threat-model.md): actors, assets, what's trusted vs not, residual risks.
- [trust-boundaries.md](../docs/security/trust-boundaries.md): the process/protocol boundaries and how each is enforced.
- [tool-risk-matrix.md](../docs/security/tool-risk-matrix.md): every tool's blast radius and protections.

The design record for the current model is the ADR set [0019](../docs/adr/0019-authenticated-ipc.md), [0020](../docs/adr/0020-kernel-attested-peer-identity.md), [0021](../docs/adr/0021-enrollment-ceremony.md), and [0023](../docs/adr/0023-workspace-monorepo-tauri-app.md) through [0031](../docs/adr/0031-touch-id-confirmations-and-presence-grants.md).

Key invariants:

- **stdout is protocol.** The binary never prints diagnostics there; only framed/NDJSON messages (a stray write corrupts the stream).
- **Read-only credential access.** Cookies/storage can be read (masked), never written. There is no `cookie_set`/`storage_set` by design.
- **Approve-per-origin.** Page ops need an allowlisted origin.
- **Confirm high-risk.** Submit/link clicks, key presses, selects, tab close, uploads, and `page_eval` confirm on an extension-owned window the page cannot reach. On an enrolled Mac, `page_eval` and `page_upload` approval is a Secure Enclave user-presence signature (Touch ID or the login password, [ADR-0031](../docs/adr/0031-touch-id-confirmations-and-presence-grants.md)).
- **Gates are on by default.** Each is a documented setting, and relaxing one is an explicit, informed choice (see the defaults table below).
- **Bridge auth.** No bridge connection is served until it passes the four gates below, in order ([ADR-0019](../docs/adr/0019-authenticated-ipc.md), [ADR-0020](../docs/adr/0020-kernel-attested-peer-identity.md), [ADR-0024](../docs/adr/0024-multi-client-attested-pairing-and-broker.md)).
- **Harness admission.** Once the trusted-client allowlist exists, no MCP client is served unless its attested code identity matches an entry; authorization keys on the attested anchor, never a self-asserted name ([ADR-0024](../docs/adr/0024-multi-client-attested-pairing-and-broker.md)).
- **Any-side revocation.** A monotonic epoch is re-read at every enforcement point; revoking from any surface drops live connections and refuses re-attach, fail-closed ([ADR-0025](../docs/adr/0025-any-side-revocation-epoch.md)).
- **Fail-closed kill switch.** One latch halts everything from any trusted surface; release demands proof of user presence and refuses on an unreadable record ([ADR-0030](../docs/adr/0030-global-kill-switch-and-audit.md)).
- **Log-after-decide audit.** Security decisions (admissions, refusals, confirmations, revocations, kill transitions, tool calls) are recorded to stderr and a durable 0600 `audit.log`. Recording can never gate or fail a decision; a failed write drops the record visibly (a `dropped` counter) rather than blocking.

The bridge auth gates, in order:

1. the kernel peer-UID check,
2. mutual kernel-attested executable identity,
3. an HMAC-SHA256 challenge-response over a per-run secret (0600 lock file),
4. a mandatory role-declaring attach frame.

## Platform support

The strong bridge guarantees hold on macOS and Linux only. Windows support is best-effort.

| Mechanism | macOS and Linux | Windows |
|-----------|-----------------|---------|
| Transport | Unix-domain socket, no listening port, created 0600 inside a 0700 per-user directory | Loopback TCP socket any process on the machine can reach |
| Peer-UID check | The server rejects any peer whose UID differs from its own | Not compiled in |
| Executable attestation | Both ends kernel-attest that the other side is running this exact binary, before the HMAC handshake (Linux: SHA256 of `/proc/<pid>/exe`; macOS: the running image's code-directory hash) | Not compiled in |
| HMAC challenge-response | One gate of four | The only gate |
| Harness admission | Enforced on the attested identity | Unenforced (there is no attestation to key it on) |
| Lock file (the per-run secret) | 0600 | No explicit restrictive mode; confidentiality rests on the default permissions of the per-user runtime directory |

What that means on Windows:

- The runtime directory is normally `%LOCALAPPDATA%\chromium-bridge`, falling back to the temp directory when `LOCALAPPDATA` and `USERPROFILE` are unset.
- The non-abuse goal stated in the threat model (another program you are running must not be able to drive the bridge silently) does not hold: any same-user process that reads the lock file can authenticate.
- The server logs a prominent warning at startup. Treat the bridge accordingly there.
- The full scoping is in the [threat model](../docs/security/threat-model.md) and [trust boundaries](../docs/security/trust-boundaries.md) docs.

The Touch ID presence gates are macOS-only by nature; other platforms use the documented interactive fail-closed floors ([ADR-0031](../docs/adr/0031-touch-id-confirmations-and-presence-grants.md)).

## page_eval and confirmation defaults (fail-safe)

`page_eval` runs arbitrary JavaScript in a real, logged-in page, so its defaults are set to fail safe (ADR-0008, updated by ADR-0027/0031):

- **Every `page_eval` call reconfirms.** The confirmation shows the full code, target URL, and tab title; on an enrolled Mac it is a Touch ID prompt.
- **No silent-eval window.** `page_eval` is deliberately excluded from the same-origin grace window, so one approval never covers a later, different payload.
- **The grace window is click-only.** `confirmGraceMs` (default 60000 ms) lets a repeated same-origin click/submit skip re-prompting within the window. Those clicks are lower-risk and observable in the UI.

These are host-owned POLICY defaults (ADR-0032): the table shows the signed policy contract's deny baseline, which governs once a host policy applies. A power user can still relax a field, and doing so is an explicit, informed choice:

| Setting | Default | Relaxing it means | Residual risk you accept |
|---------|---------|-------------------|--------------------------|
| `confirmPageEval` | `true` | `false` = `page_eval` runs with no prompt | Arbitrary JS executes silently on approved origins |
| `pageEvalEnabled` | `false` | `true` = `page_eval` can run at all (each call still confirms per the rows above) | The arbitrary-JS surface opens on approved origins |
| `touchIdConfirm` | `true` | `false` = enrolled Macs fall back to the extension-window confirmation for `page_eval`/`page_upload` | The verdict is a window click the extension trusts, not a hardware tap |
| `confirmHighRiskClick` | `true` | `false` = high-risk clicks (submit/link) run with no prompt; `page_press` and `page_select` still confirm on every call regardless | A prompt-injected model can click submit/links on approved origins silently |
| `confirmTabClose` | `true` | `false` = `tab_close` runs with no prompt | Silent data loss in a closed tab |
| `confirmGraceMs` | `60000` | Larger = longer click/submit silence window; `0` = every click reconfirms | A same-origin click/submit within the window is silent (never eval) |

How relaxing works:

- **Two write surfaces, one cost.** The desktop app's Security view shows a confirmation dialog naming each relaxed field, then signs the policy document with Touch ID. The CLI's `chromium-bridge policy` grant path raises the same Touch ID user-presence prompt through its enclave signature.
- **Never silent.** The extension's options page no longer carries these toggles.
- **Always in force.** The site allowlist (per-origin) and the global kill switch apply regardless of the policy.

The `pageEvalEnabled` baseline is a deliberate flip. The pre-migration local setting defaulted to `true`, and still does on a pre-cutover install: the extension keeps enforcing its legacy settings until a first policy applies (indefinitely on non-macOS). The host-owned baseline denies it until an explicit grant.

## Masking is heuristic and best-effort

Cookie, storage, page-text, and `page_eval`-result masking is a **heuristic, best-effort** filter, not a guarantee. It is applied at the service-worker egress, once for both page backends; the rules live in `src/apps/extension/src/lib/shared/masking.ts`.

What it targets:

| Shape | Rule |
|-------|------|
| JWTs | three base64url segments, the first starting with `ey` |
| Long hex | 32 or more hex characters |
| Long digit runs | 12 or more digits |
| Opaque tokens | 32 or more base64url characters containing both a letter and a digit |
| Assignments | `bearer`/`key=` style values |
| Key names | sensitive-looking keys are redacted |

What it misses:

- short tokens, and secrets below the length thresholds,
- all-letter or all-digit tokens,
- tokens broken up by characters outside the matched set (whitespace, `.`, `/`, `+`, `=`),
- application-specific formats.

The token rule keys off length plus the presence of a letter and a digit, not a true entropy measure. It can over-mask (a long mixed letter+digit identifier that is not secret) as well as under-mask.

Masking reduces accidental leakage into the model context and logs. It is not a substitute for treating any `page_eval` result or storage dump as potentially sensitive.

- `evalMask` disables masking for `page_eval` results entirely.
- `storage_get` masking is not user-toggleable.

## Release artifact integrity

Release binaries are built by GitHub Actions from the tagged commit, with a deterministic build, so the binary's hash can be re-derived from the tag. The pipeline is the repo-owned `.github/workflows/update-release.yml` hook, called by the managed ci.yml between the fleet's release and publish legs; the build recipe is `scripts/build-repro.ts` (pinned toolchain, path remapping, `SOURCE_DATE_EPOCH`, `--locked`). Pipeline mechanics: [docs/release.md](../docs/release.md).

Each release publishes:

| Asset | Integrity data |
|-------|----------------|
| `chromium-bridge-<tag>-<platform>-<arch>.tar.gz` | its SHA-256, a separate SHA-256 of the binary inside it (`<name>.binary.sha256`), a build provenance attestation covering both, and that attestation's Sigstore bundle as `chromium-bridge-<tag>-<platform>-<arch>.attestation.jsonl` |
| the extension zip, the `.dmg`, the CycloneDX SBOM | their own attestations and `<asset>.attestation.jsonl` bundles, verifiable the same way |
| the whole release | `attestation.json`: one Sigstore bundle whose single attestation lists every asset as a subject, written by the managed publish stage before the draft flips live |

Verification is yours to run, before you execute anything from an archive:

```sh
shasum -a 256 -c chromium-bridge-<tag>-<platform>-<arch>.tar.gz.sha256
gh attestation verify chromium-bridge-<tag>-<platform>-<arch>.tar.gz --repo Vivswan/chromium-bridge
# after extraction, the bare binary can be verified on its own:
gh attestation verify chromium-bridge --repo Vivswan/chromium-bridge
shasum -a 256 -c chromium-bridge-<tag>-<platform>-<arch>.binary.sha256
```

Offline variants of the `gh attestation verify` calls:

- `--bundle chromium-bridge-<tag>-<platform>-<arch>.attestation.jsonl` reads the attestation from the downloaded release asset instead of GitHub's attestations API. The one bundle covers the archive and the bare binary alike; verification picks the entry matching the asset's digest.
- `gh attestation verify <asset> -R Vivswan/chromium-bridge --bundle attestation.json` works for any downloaded asset, through the release-level bundle.

Verifying the whole archive also covers the bundled `extension/dist`. Registration (`doctor --fix`, or the app) points browsers at the binary as it sits on disk; it downloads nothing and adds no verification step of its own. Verify first, then register.

Building it yourself skips the release pipeline entirely:

1. Install the exact toolchain pinned in `rust-toolchain.toml` via [rustup](https://rustup.rs). A Homebrew or distro rustc embeds different standard-library paths and will not match.
2. Install [bun](https://bun.sh) to run the build script.
3. Build on the same platform the release targets:

```sh
git checkout <tag>
bun scripts/build-repro.ts
shasum -a 256 target/release/chromium-bridge   # compare with the release's .binary.sha256
```

Known gaps, stated plainly:

- **Reproducibility is one-machine so far.** Byte-identical rebuilds are verified across clean builds and checkout paths on the same machine. Matching a published hash from another machine requires the same rustup toolchain and platform SDK, and independent cross-machine rebuilds have not been demonstrated yet.
- **Archives are not bit-reproducible.** tar and gzip embed metadata, which is why the release publishes the binary's hash separately.
- **No notarization or Authenticode yet.** Binaries are not Apple-notarized for standalone distribution, and the Windows exe is not Authenticode-signed; macOS verification today is the SHA-256 and attestation above. The desktop app bundle is codesigned with its entitlement chain verified at build time ([ADR-0026](../docs/adr/0026-tauri-signing-and-entitlement-chain.md)).
- **Signing will change the check.** Once a distribution signing identity lands, released binaries will no longer be byte-identical to local rebuilds and verification will move to comparing cdhashes.
- **Install-time hostility is out of scope.** A hostile process already running as the same user during install is handled at runtime by the bridge's peer attestation and harness admission, not at install time.

### Dependency supply chain (ADR-0035)

Dependency review is fully automated; there is no manual per-crate audit step ([ADR-0035](../docs/adr/0035-automated-supply-chain-review.md)).

| Layer | Runs | Catches |
|-------|------|---------|
| cargo-deny + cargo-audit | inside the all-green gate on every PR and push, and again in the weekly security.yml sweep | RUSTSEC advisories, the license allow-list and banned sources in `deny.toml` |
| GitHub's dependency-review action | on every PR, through the managed ci.yml's fleet-delivered job | dependencies with known advisories in the PR diff |
| Dependabot | continuously, over cargo, bun, and GitHub Actions | alerts and bump PRs |

Boundaries of that stack:

- The dependency-review action only has a diff to review on pull_request events; direct pushes stay covered by cargo-deny + cargo-audit in the same gate plus the weekly sweep.
- License enforcement is cargo-deny's alone; the reason the action does not mirror the allow-list is in ADR-0035.
- The weekly sweep exists so advisories disclosed between pushes still surface.

What this asserts is "no unwaived known advisory and an allowed license", not "a human audited this code". The RUSTSEC exceptions reviewed into `deny.toml`'s ignore list stay waived. The residual risk (a novel malicious crate or undiscovered flaw with no published advisory) is recorded in ADR-0035.

### CI supply chain under the fleet template (ADR-0033)

CI configuration is fleet-managed ([ADR-0033](../docs/adr/0033-adopt-repo-platform-fleet-template.md)):

- The managed ci.yml is a skeleton that calls the fleet's reusable workflows and actions at `@build`, the fleet repository's green-gated delivery branch, which moves on every green commit there.
- Third-party actions are pinned to commit SHAs on both sides.

The moving `@build` ref is a real, accepted widening of the CI supply chain:

- A compromise of the fleet repository executes in this repository's CI, in jobs holding security-events, pages, id-token, contents, and pull-requests write.
- The acceptance rests on a trust assumption, not a technical boundary: the fleet repository stays under the same owner's control.
- The rest of the accepted residuals live in ADR-0033.

## Identifiers (rebrand, 2026-07)

The project renamed from the upstream `browser-bridge` to `chromium-bridge` ([ADR-0023](../docs/adr/0023-workspace-monorepo-tauri-app.md)). The security-relevant identifiers are now:

| Identifier | Value | Note |
|------------|-------|------|
| native-messaging host id | `com.vivswan.chromium_bridge.host` | also the manifest filename stem and the extension's `connectNative` argument; `scripts/check-extension-id.ts` asserts all copies agree |
| enclave keychain label | `com.vivswan.chromium-bridge.enclave.signing.v1` | |
| enclave challenge domain | `chromium-bridge-enclave-v1` | host and extension changed together; no enrolled key predated the rename, so there was no key migration |
| extension id | `mkjjlmjbcljpcfkfadfmhblmmddkdihf` | derived from the manifest `key`; did not change |

An install registered under the old host id stops working until re-registered; that is a naming change, not a security regression.

Upgrading from a pre-rebrand install leaves artifacts the current tooling (`doctor --fix`, `uninstall`, `revoke`) does not touch:

- an old `com.browser_bridge.host.json` manifest,
- the old `browser-bridge` runtime directory,
- an Enclave key under the old `com.browser-bridge.enclave.signing.v1` label.

Those leftovers grant no capability: the challenge domains differ, an old pin fails closed, and the new host reports `not_enrolled`. To remove them, run the old release's uninstaller and `browser-bridge revoke` with the old binary before switching over.

## Lock poisoning policy (std::sync::Mutex)

The core is built with panics aborting the process, but library code cannot assume it (tests and future embeddings unwind). Every `Mutex::lock().unwrap_or_else(...)` recover site is therefore a policy decision, not noise. The rule:

- **Refuse on authorization paths.** Where poisoned state could admit, serve, or free capacity for a peer, treat the poison as untrustworthy state and refuse. The broker's attach path, its revocation registry, and the kill switch's reach all do this; see `broker.rs`.
- **Recover on cleanup and egress paths.** Where refusing would leak a slot or wedge a shutdown, recover the inner value and proceed (the broker's release and shutdown paths).
- **The native host's two writer-leg sites recover.** The stdout frame writer in `write_control_reply` and the socket-to-stdout pump in `native_host.rs` serialize frame writes to stdout; the guarded `BufWriter` carries no security state, and refusing to write would silently wedge the browser leg.

A new `Mutex` in the core must pick a side explicitly and say why at the recover site.

## Security-relevant changes (review bar)

A change is **security-relevant** if it:

- adds/broadens a Chrome permission or host permission,
- adds a way to read new sensitive data, or any write capability,
- changes confirmation, allowlist, masking, or presence-gate logic,
- changes the bridge authentication, harness admission, the trusted-client allowlist, the revocation epoch, the kill switch, the lock file, or the run secret,
- changes the enrollment ceremony, the Enclave key policy, or the audit trail's failure behavior,
- adds outbound network/IPC, or widens `page_eval`.

Such a PR must:

1. carry the [security-change](ISSUE_TEMPLATE/security-change.yml) checklist,
2. update the [tool risk matrix](../docs/security/tool-risk-matrix.md), and (if it moves a trust boundary) the [threat model](../docs/security/threat-model.md),
3. add a **negative** security test (proving the boundary holds), in addition to the positive one.

The fuzzing rule for bespoke parsing at a trust boundary in the Rust core:

- **Triggers on** a new or changed bespoke parser or semantic validator over attacker-controlled input: wire frames, hand-written byte parsers, ownership or identity decisions.
- **Requires** a new or extended cargo-fuzz target in `src/packages/core/fuzz/`, or a deliberate exclusion with its reason in the [Fuzzing section](../docs/development.md#fuzzing) of the development guide.
- **Does not trigger on** plain derived-serde readers guarded by negative tests (the allowlist, revocation, and lockfile readers); the rule is about bespoke parsing or semantic-validation logic, not `serde_json`.

Extra review care applies to these security-critical surfaces:

- `src/packages/core/src/ipc/`
- `src/packages/core/src/protocol.rs` and `protocol/`
- `src/packages/core/src/broker.rs`
- `src/packages/core/src/allowlist.rs`
- `src/packages/core/src/revocation.rs`
- `src/packages/core/src/kill.rs`
- `src/packages/core/src/presence/`
- `src/packages/core/src/enclave/`
- `src/packages/core/src/registration.rs`
- `src/packages/core/src/mcp/` (the rmcp seam, ADR-0034)
- the extension's allowlist/eval/confirmation code
- `src/apps/extension/wxt.config.ts`

### ADR-0032: the host-owned policy residual ledger

The host-owned policy work ([ADR-0032](../docs/adr/0032-host-owned-policy-settings.md)) records every accepted residual it introduced in one place, the [residual ledger in the threat model](../docs/security/threat-model.md#host-owned-policy-adr-0032-residual-ledger). A change that touches one of those mechanisms updates its ledger entry there; this file deliberately does not duplicate the entries.
