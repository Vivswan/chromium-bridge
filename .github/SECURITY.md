# Security policy

How to report a vulnerability, what is in scope, the defaults that fail safe, how release artifacts are verified, and the bar a security-relevant change must clear. What the bridge promises and where it stops is the [security page](../docs/security.md); the mechanism and every accepted residual per boundary is the [trust boundaries ledger](../docs/security/trust-boundaries.md).

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

## Scope

chromium-bridge drives a real, logged-in browser on the user's machine. It can read page content, cookies (including httpOnly), and web storage, and can execute JavaScript in pages.

In scope:

- the Rust binary in all its roles: MCP server and broker, native host, the registration engine, the pairing and presence ceremonies, the kill switch, the audit trail,
- the bridge socket and its authentication,
- harness admission and the trusted-client allowlist,
- the revocation epoch,
- the MV3 extension (background, content, the confirmation window, the options page),
- the site allowlist and confirmation model,
- the host-owned policy and its signature,
- masking.

Examples of in-scope issues:

- bypassing the site allowlist or a confirmation prompt,
- exfiltrating cookies, storage, or page content past the mask,
- a page influencing the extension into acting on a non-approved origin,
- the bridge socket accepting an unauthenticated or unattested peer,
- a harness served despite an enrolled allowlist that does not match it,
- releasing the kill switch, or relaxing the policy, without user presence,
- forging a WebAuthn presence verdict, or answering a presence request from the window on a browser with an enrolled credential,
- privilege escalation via the native messaging host.

Out of scope:

- anything requiring a pre-compromised machine,
- a malicious MCP client the user themselves paired (a paired client is trusted by design; the [non-goals](../docs/security.md#explicit-non-goals)).

## Platform support

The bridge guarantees hold on macOS, Linux, and Windows; the mechanism behind each differs per OS. The gates are the [ledger's boundary 2](../docs/security/trust-boundaries.md#boundary-2-rust-mcp-server---native-host--bridge-socket-ndjson); this table is the per-OS state.

The extension installs on Chrome 134 or later (the manifest's `minimum_chrome_version`, the floor the WebAuthn presence ceremony is supported on); the browser refuses an older install, so nothing below the floor degrades.

| Mechanism | macOS and Linux | Windows |
|-----------|-----------------|---------|
| Transport | Unix-domain socket, no listening port, created 0600 inside a 0700 per-user directory | Named pipe in the local pipe namespace, no listening port; every instance carries a security descriptor only the current user can open, and remote clients are rejected |
| Same-user check | The server rejects any peer whose UID differs from its own | The kernel enforces the pipe's descriptor at open, before the connection exists |
| Executable attestation | Both ends kernel-attest that the other side is running this exact binary, before the HMAC handshake (Linux: SHA256 of `/proc/<pid>/exe`; macOS: the running image's code-directory hash) | Both ends attest the other side before the HMAC handshake: the pid the kernel recorded for the pipe peer, then the SHA256 of the image file that pid runs (re-opened by path; see the residual below) |
| HMAC challenge-response | One gate of four | One gate of four |
| Harness admission | Enforced on the attested identity | Enforced on the attested identity: the image hash plus the Authenticode publisher (the signer's X.500 subject) as the signer anchor |
| Lock file (the per-run secret) | 0600 | No explicit restrictive mode; confidentiality rests on the default permissions of the per-user runtime directory |
| User presence | The browser's WebAuthn authenticator on an enrolled browser; the confirmation window otherwise; a phrase typed on a terminal for the CLI | The same ladder |
| Host key | `pair` mints it into the Keychain or the Secret Service, or a 0600 file with `--file-store` | `pair` mints it into the Credential Manager |

What differs on Windows:

- The runtime directory is normally `%LOCALAPPDATA%\chromium-bridge`, falling back to the temp directory when `LOCALAPPDATA` and `USERPROFILE` are unset; the temp directory is not guaranteed per-user.
- The image is measured by re-opening its path; the [ledger](../docs/security/trust-boundaries.md#boundary-2-rust-mcp-server---native-host--bridge-socket-ndjson) records what that leaves open.
- The parent pid Windows records is caller-selectable at `CreateProcess`, so the harness is measured as the creator of the server's stdin pipe instead; a console, or pipe ends opened by two different processes, fails closed, and the [ledger's boundary 1](../docs/security/trust-boundaries.md#boundary-1-mcp-client---rust-mcp-server--stdio-json-rpc-20) records what remains.
- `pair-client --this-parent` is Unix-only for the same reason (a console command has no pipe creator); the [CLI page](../docs/cli.md#trusted-clients-pair-client--revoke-client--list-clients) owns how Windows pairs.
- The publisher is read from the embedded Authenticode signature with no revocation check; a catalog-signed image (most of Windows itself) anchors by hash alone.

## page_eval and confirmation defaults (fail-safe)

`page_eval` runs arbitrary JavaScript in a real, logged-in page, so its defaults are set to fail safe:

- **Every `page_eval` call reconfirms.** The confirmation shows the full code, the target origin, and the tab title on the extension-owned window.
- **No silent-eval window.** `page_eval` is deliberately excluded from the same-origin grace window, so one approval never covers a later, different payload.
- **The grace window is click-only.** `confirmGraceMs` lets a repeated click or submit in the same tab, origin, and action kind skip re-prompting within the window; another tab on the same origin confirms again. Those clicks are lower-risk and observable in the UI.

These are host-owned policy defaults: the table shows the signed policy contract's deny baseline, which governs once a host policy applies. A power user can still relax a field, and doing so is an explicit, informed choice:

| Setting | Default | Relaxing it means | Residual risk you accept |
|---------|---------|-------------------|--------------------------|
| `confirmPageEval` | `true` | `false` = `page_eval` runs with no prompt | Arbitrary JS executes silently on approved origins |
| `pageEvalEnabled` | `false` | `true` = `page_eval` can run at all (each call still confirms per the rows above) | The arbitrary-JS surface opens on approved origins |
| `presenceConfirm` | `true` | `false` = `page_eval` and `page_upload` approvals are never routed to a presence provider; no provider is installed today, so both values confirm on the window | When a WebAuthn route for those two lands, `false` keeps their approval a window click rather than an authenticator tap |
| `confirmHighRiskClick` | `true` | `false` = high-risk clicks (submit/link) run with no prompt; `page_press` and `page_select` still confirm on every call regardless | A prompt-injected model can click submit/links on approved origins silently |
| `confirmTabClose` | `true` | `false` = `tab_close` runs with no prompt | Silent data loss in a closed tab |
| `confirmGraceMs` | `60000` | Larger = longer click/submit silence window; `0` = every click reconfirms | A same-origin click/submit within the window is silent (never eval) |

How relaxing works:

- **One write surface, one cost.** `chromium-bridge policy set` signs the policy document with the host key behind a confirmation typed on a real terminal; `policy restrict` tightens for free. The [CLI page](../docs/cli.md#host-owned-policy-policy) owns both lanes.
- **Never silent.** The extension's options page carries no relaxing toggle; its policy editor can only tighten.
- **Always in force.** The site allowlist (per-origin) and the global kill switch apply regardless of the policy.

The `pageEvalEnabled` baseline denies `page_eval` until an explicit grant: a pre-cutover install enforces the deny baseline, and so does every applied policy that does not grant it.

## Masking is heuristic and best-effort

Cookie, storage, page-text, and `page_eval`-result masking is a heuristic, best-effort filter, not a guarantee. It is applied at the service-worker egress, once for both page backends; the rules live in `src/apps/extension/src/lib/shared/masking.ts`.

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

The token rule keys off length plus the presence of a letter and a digit, not a true entropy measure. It can over-mask (a long mixed letter-and-digit identifier that is not secret) as well as under-mask.

Masking reduces accidental leakage into the model context and logs. It is not a substitute for treating any `page_eval` result or storage dump as potentially sensitive.

- `evalMask` disables masking for `page_eval` results entirely.
- `storage_get` masking is not user-toggleable.

## Release artifact integrity

Release binaries are built by GitHub Actions from the tagged commit, with a deterministic build, so the binary's hash can be re-derived from the tag. The pipeline is the repo-owned `.github/workflows/update-release.yml` hook, called by the managed ci.yml between the fleet's release and publish legs. The build recipe is `scripts/build-repro.ts` (pinned toolchain, path remapping, `SOURCE_DATE_EPOCH`, `--locked`); pipeline mechanics are on the [release page](../docs/release.md).

Each release publishes:

| Asset | Integrity data |
|-------|----------------|
| `chromium-bridge-<tag>-<platform>-<arch>.tar.gz` | its SHA-256, a separate SHA-256 of the binary inside it (`<name>.binary.sha256`), a build provenance attestation covering both, and that attestation's Sigstore bundle as `chromium-bridge-<tag>-<platform>-<arch>.attestation.jsonl` |
| the extension zip, the CycloneDX SBOM | their own attestations and `<asset>.attestation.jsonl` bundles, verifiable the same way |
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

Verifying the whole archive also covers the bundled `extension/dist`. Registration (`doctor --fix`) points browsers at the binary as it sits on disk; it downloads nothing and adds no verification step of its own. Verify first, then register.

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
- **No notarization or Authenticode yet.** Binaries are not Apple-notarized for standalone distribution, and the Windows exe is not Authenticode-signed; macOS verification today is the SHA-256 and attestation above.
- **Signing will change the check.** Once a distribution signing identity lands, released binaries will no longer be byte-identical to local rebuilds and verification will move to comparing cdhashes.
- **Install-time hostility is out of scope.** A hostile process already running as the same user during install is handled at runtime by the bridge's peer attestation and harness admission, not at install time.

### Dependency supply chain

Dependency review is fully automated; there is no manual per-crate audit step. A single maintainer cannot read the rmcp dependency tree line by line, and a gate that is always satisfied by an exemption asserts little.

| Layer | Runs | Catches |
|-------|------|---------|
| cargo-deny | inside the all-green gate on every PR and push, and again in the nightly.yml rerun | RUSTSEC advisories (yanked crates included), the license allow-list and banned sources in `deny.toml` |
| the fleet's Trivy step | in the managed ci.yml's standard-checks job on every PR and push | HIGH/CRITICAL advisories with a fix in `Cargo.lock` and `bun.lock` |
| GitHub's dependency-review action | on every PR, through the managed ci.yml's fleet-delivered job | dependencies with known advisories in the PR diff |
| Dependabot | continuously, over cargo, bun, uv, and GitHub Actions | alerts and bump PRs |

Boundaries of that stack:

- The dependency-review action only has a diff to review on pull_request events; direct pushes stay covered by cargo-deny and Trivy in the same gate plus the nightly rerun.
- License enforcement is cargo-deny's alone. The dependency-review action reads licenses from GitHub's dependency graph, which misreports real `Cargo.lock` entries (the deprecated slash syntax, crates missing from the resolved graph), so a mirrored allow-list would fail legitimate bumps.
- The nightly rerun exists so advisories disclosed between pushes still surface; a red night files the `nightly-failure` tracking issue.
- Two JS cases Trivy does not gate, both accepted cuts, both still covered by Dependabot alerts:

| Case | Why Trivy misses it | Why the cut is accepted |
|------|---------------------|-------------------------|
| dev-only packages in `bun.lock` | it runs without `--include-dev-deps` | those packages run only in the local and CI toolchain |
| HIGH/CRITICAL advisories with no fixed version | it runs with `ignore-unfixed` | a bump cannot fix it, and a red gate would only block unrelated work; the fleet's nightly Trivy scan reports the unfixed production advisories |

What this asserts is "no unwaived known advisory and an allowed license", not "a human audited this code". The RUSTSEC exceptions reviewed into `deny.toml`'s ignore list stay waived. The residual risk: a novel malicious crate, or an undiscovered flaw with no published advisory, enters the build with no human audit in its way. `deny.toml` refuses unknown registries and git sources, and PR review still sees every `Cargo.lock` diff.

### CI supply chain under the fleet template

CI configuration is fleet-managed:

- The managed ci.yml is a skeleton that calls the fleet's reusable workflows and actions at `@stable`, a moving tag in the fleet repository that names a green `main` commit. The fleet repository's own post-green job moves it after each push to `main` that passes its gate.
- Third-party actions are pinned to commit SHAs on both sides.

The moving `stable` tag is a real, accepted widening of the CI supply chain:

- A compromise of the fleet repository executes in this repository's CI, in jobs holding security-events, pages, id-token, contents, and pull-requests write.
- The acceptance rests on a trust assumption, not a technical boundary: the fleet repository stays under the same owner's control. The fleet repository's ruleset blocks deletion of the tag only; a `uses:` here executes whatever the tag names, so an out-of-band move by a push-access holder is caught by nothing at write time.
- The mover, its gates, and the remaining trusts are recorded in repo-platform's [build-provenance.md](https://github.com/Vivswan/repo-platform/blob/main/docs/platform/build-provenance.md).
- auto-format.yml pushes with `GITHUB_TOKEN`, whose commits trigger no CI, so a formatted PR head has no all-green result until someone re-runs CI. Fail-safe: the merge stays blocked.

## Identifiers

The security-relevant identifiers, each owned by the Rust core and generated into the TypeScript side (rebuilt from the core by every task that reads them):

| Identifier | Value | Note |
|------------|-------|------|
| native-messaging host id | `com.vivswan.chromium_bridge.host` | also the manifest filename stem and the extension's `connectNative` argument; `scripts/check-extension-id.ts` keeps every copy pinned to `identity.rs` |
| host-key credential-store entry prefix | `com.vivswan.chromium-bridge.enclave.signing.v1` | the runtime directory's digest is the suffix, so two directories never share one entry |
| host-key challenge domain | `chromium-bridge-enclave-v1` | host and extension changed together |
| extension id | `mkjjlmjbcljpcfkfadfmhblmmddkdihf` | derived from the manifest `key` |

## Lock poisoning policy (std::sync::Mutex)

The core is built with panics aborting the process, so a poisoned lock cannot occur in a shipped binary; library code still meets one under unwinding (tests and future embeddings). Two policies cover every lock:

| Site | On poison | Why |
|------|-----------|-----|
| the broker's `Lock<T>` wrapper (`broker.rs`), the native host's stdout writer, and the Windows pipe's listener and stream locks (`ipc/platform/windows/pipe.rs`) | recover the inner value and proceed | the reasons below |
| `session.rs`, the connection-registry and pending-call lookups | refuse | a poisoned map could route a call to the wrong browser; the kill sweep (`shutdown_all_browsers`) still recovers, so a halt always reaches every relay |

- **Why recover is safe there.** The guarded values are bookkeeping (a harness count, the relay registry, a frame writer); an inconsistent reading can at worst refuse an attach or release a slot late, never admit a peer, because admission is decided from the trust record, not from a lock.
- **Why refuse is not.** Refusing to lock would wedge the shutdown wait, leak a registry slot, or silence the browser leg, and leave the kill sweep unable to reach a relay.

A new `Mutex` in the core uses the wrapper or the same recovery; a site that refuses states why here, as `session.rs` does.

## Security-relevant changes (review bar)

A change is **security-relevant** if it:

- adds or broadens a Chrome permission or host permission,
- adds a way to read new sensitive data, or any write capability,
- changes confirmation, allowlist, masking, or presence-gate logic,
- changes the bridge authentication, harness admission, the trusted-client allowlist, the revocation epoch, the kill switch, the lock file, or the run secret,
- changes the pairing ceremony, the host-key policy, the WebAuthn exchange, the policy signature, or the audit trail's failure behavior,
- adds outbound network or IPC, or widens `page_eval`,
- touches an [invariant](../docs/security/trust-boundaries.md#invariants-that-must-not-regress).

Such a PR must:

1. carry the [security-change](ISSUE_TEMPLATE/security-change.yml) checklist,
2. update the [tool risk matrix](../docs/security/tool-risk-matrix.md), and, if it moves a boundary or a residual, the [trust boundaries ledger](../docs/security/trust-boundaries.md) (the residual it touches updates its ledger entry there; this file does not duplicate the entries),
3. add a **negative** security test (proving the boundary holds), in addition to the positive one,
4. name which row of [the security page](../docs/security.md) it moves and in which direction, or state that no row moves and why.

The fuzzing rule for bespoke parsing at a trust boundary in the Rust core:

- **Triggers on** a new or changed bespoke parser or semantic validator over attacker-controlled input: wire frames, hand-written byte parsers, ownership or identity decisions.
- **Requires** a new or extended cargo-fuzz target in `src/packages/core/fuzz/`, or a deliberate exclusion with its reason in the [Fuzzing section](../docs/development.md#fuzzing) of the development guide.
- **Does not trigger on** plain derived-serde readers guarded by negative tests (the trust record and lockfile readers); the rule is about bespoke parsing or semantic-validation logic, not `serde_json`.

Extra review care applies to these security-critical surfaces:

- `src/packages/core/src/ipc/`
- `src/packages/core/src/protocol.rs` and `protocol/`
- `src/packages/core/src/broker.rs`
- `src/packages/core/src/allowlist.rs`
- `src/packages/core/src/trust.rs`
- `src/packages/core/src/kill.rs`
- `src/packages/core/src/presence/`
- `src/packages/core/src/enclave/` (the host key)
- `src/packages/core/src/webauthn/` (the WebAuthn verifier, the reason `p256` ships)
- `src/packages/core/src/policy/`
- `src/packages/core/src/registration.rs`
- `src/packages/core/src/mcp/` (the rmcp seam)
- the extension's allowlist, eval, and confirmation code
- `src/apps/extension/src/entrypoints/options/PolicyEditor.tsx` and `src/apps/extension/src/lib/background/host-admin.ts` (the options page's policy restriction lane and registration repair)
- `src/apps/extension/wxt.config.ts`
