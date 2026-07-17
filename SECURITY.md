# Security Policy

chromium-bridge drives a **real, logged-in Chrome** on the user's machine - it
can read page content, cookies (including httpOnly), and web storage, and can
execute JavaScript in pages. Security is a first-class concern, not an
afterthought. This document covers how to report issues and the review bar for
security-relevant changes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's **[Report a vulnerability](https://github.com/Vivswan/chromium-bridge/security/advisories/new)**
(Security → Advisories) on this repository. Include:

- what an attacker can do (impact) and the trust boundary crossed,
- reproduction steps or a proof of concept,
- affected version / commit.

Expect an acknowledgement within a few days. Because this is a small project,
please allow reasonable time for a fix before any public disclosure.

## Scope

In scope: the Rust binary (MCP server + native host), the native-messaging
bridge and its auth, the MV3 extension (background/content), the allowlist and
confirmation model, masking, and the installer.

Examples of in-scope issues: bypassing the site allowlist or a confirmation
prompt; exfiltrating cookies/storage/page content past the mask; a page
influencing the extension into acting on a non-approved origin; the bridge
socket accepting an unauthenticated peer; privilege escalation via the native
messaging host.

Out of scope: anything requiring a pre-compromised machine or a malicious MCP
client the user themselves configured (the MCP client is trusted by design -
see the [threat model](docs/security/threat-model.md)).

## The security model (summary)

See [docs/security/](docs/security/) for the full picture:

- [threat-model.md](docs/security/threat-model.md) - actors, assets, what's
  trusted vs not.
- [trust-boundaries.md](docs/security/trust-boundaries.md) - the process/protocol
  boundaries and how each is enforced.
- [tool-risk-matrix.md](docs/security/tool-risk-matrix.md) - every tool's blast
  radius and protections.

Key invariants:

- **stdout is protocol** - the binary never prints diagnostics there; only
  framed/NDJSON messages (a stray write corrupts the stream).
- **Read-only credential access** - cookies/storage can be read (masked), never
  written. There is no `cookie_set`/`storage_set` by design.
- **Approve-per-origin + confirm high-risk** - page ops need an allowlisted
  origin; submit/link clicks, `page_eval`, and tab close prompt the user.
- **Bridge auth.** No bridge connection is served until it answers an HMAC
  challenge over a per-run secret from the lock file (0600 on macOS/Linux).
  On macOS/Linux the bridge is a private Unix-domain socket and the server
  also rejects peers by UID and kernel-attests the peer executable before the
  handshake; on Windows it is a loopback TCP socket with the HMAC check only
  (see Platform support below).

## Platform support

The strong bridge guarantees hold on macOS and Linux only. There the MCP
server and the native host talk over a Unix-domain socket with no listening
port, created 0600 inside a 0700 per-user directory. The server rejects any
peer whose UID differs from its own, and both ends kernel-attest that the
other side is running this exact binary (Linux: SHA256 of `/proc/<pid>/exe`;
macOS: the running image's code-directory hash) before the HMAC handshake.

Windows support is best-effort. None of those mechanisms is compiled in: the
bridge is a loopback TCP socket that any process on the machine can reach, and
the only gate is the HMAC challenge-response over the per-run secret in the
lock file. The lock file gets no explicit restrictive mode on Windows, so the
secret's confidentiality rests on the default permissions of the per-user
runtime directory (normally `%LOCALAPPDATA%\chromium-bridge`, falling back to
the temp directory when `LOCALAPPDATA` and `USERPROFILE` are unset). The
non-abuse goal stated in the threat model (another
program you are running must not be able to drive the bridge silently) does
not hold on Windows: any same-user process that reads the lock file can
authenticate. The server logs a prominent warning at startup on Windows.
Treat the bridge accordingly there; the full scoping is in the
[threat model](docs/security/threat-model.md) and
[trust boundaries](docs/security/trust-boundaries.md) docs.

## page_eval and confirmation defaults (fail-safe)

`page_eval` runs arbitrary JavaScript in a real, logged-in page, so its
defaults are set to fail safe (ADR-0008, update 2026-07-16):

- **Every `page_eval` call reconfirms.** The in-page confirmation toast (showing
  the full code, target URL, and tab title) is shown on every call. `page_eval`
  is deliberately excluded from the same-origin grace window, so there is no
  silent-eval window: one approval never covers a later, different payload.
- **The grace window is click-only.** `confirmGraceMs` (default 60000ms) lets a
  repeated same-origin click/submit skip re-prompting within the window. It does
  not apply to `page_eval`. Those clicks are lower-risk and observable in the UI.

These defaults are user-configurable knobs, not removed gates. A power user can
still relax them, and doing so is an explicit, informed choice:

| Setting | Default | Relaxing it means | Residual risk you accept |
|---------|---------|-------------------|--------------------------|
| `confirmPageEval` | `true` | `false` = `page_eval` runs with no prompt | Arbitrary JS executes silently on approved origins |
| `pageEvalEnabled` | `true` | `false` = `page_eval` refused entirely | (hardening, not a relaxation) |
| `confirmGraceMs` | `60000` | Larger = longer click/submit silence window; `0` = every click reconfirms | A same-origin click/submit within the window is silent (never eval) |

The Options page shows an explicit warning on the `confirmPageEval` toggle. The
site allowlist (per-origin) and `pageEvalEnabled` (global kill switch) remain in
force regardless of these settings.

## Masking is heuristic and best-effort

Cookie, storage, and `page_eval`-result masking (`src/apps/extension/src/shared/masking.ts`)
is a **heuristic, best-effort** filter, not a guarantee. It targets common
secret shapes (JWTs, long hex, long digit runs, opaque base64url tokens of >=32
chars containing both a letter and a digit, and `bearer`/`key=` assignments) and
redacts sensitive-looking key names. The token rule keys off length plus the
presence of a letter and a digit, not a true entropy measure, so it can both
over-mask (a long mixed letter+digit identifier that is not secret) and
under-mask. It will miss secrets that do not match these shapes: short tokens,
secrets below the length thresholds, all-letter or all-digit tokens, tokens
broken up by characters outside the matched set (whitespace, `.`, `/`, `+`,
`=`), or application-specific formats. Masking reduces accidental leakage into
the model context and logs; it is not a substitute for treating any `page_eval`
result or storage dump as potentially sensitive. Masking can be disabled per
surface (`evalMask`), which removes this filter entirely.


## Release artifact integrity

Release binaries are built by GitHub Actions from the tagged commit
(`.github/workflows/release.yml`) with a deterministic build
(`scripts/build-repro.sh`: pinned toolchain, path remapping,
`SOURCE_DATE_EPOCH`, `--locked`), so the binary's hash can be re-derived
from the tag. Byte-identical rebuilds are verified across clean builds and
checkout paths on the same machine; matching a published hash from another
machine requires the same rustup toolchain and platform SDK, and
independent cross-machine rebuilds have not been demonstrated yet. Each
release publishes the archive's SHA-256, a separate SHA-256 of the binary
inside it (`<name>.binary.sha256`), and a build provenance attestation
covering both.

In prebuilt mode `install.sh` refuses to install a binary it cannot verify
against an anchor whose trust is independent of the release asset. It hashes
the private copy it is about to install (not the source file, so the checked
bytes are the installed bytes), then takes one of two paths. With a
user-supplied `--expected-sha256`, obtained out of band, that hash is the
independent anchor and verification is a direct comparison with no network. On
the online default (no such hash), a successful GitHub build-provenance
attestation for those exact bytes is required, checked with an authenticated
`gh` against the pinned repository; the published `.binary.sha256` is fetched
and compared too, but only as a corruption check, since it lives in the same
release as the binary and so is not proof of origin on its own. The repository
whose provenance is trusted is pinned in the installer's code; the archive's
`RELEASE.txt` supplies only the tag/platform/arch and must name that same
repository, so a tampered archive cannot redirect verification to a repository
its author controls (installing a fork's release requires an explicit
`--release-repo`). If `gh` is missing or unauthenticated, or the attestation,
checksum, download, or reference fails, the install aborts, and the macOS
quarantine attribute is cleared only after verification has passed.

Known gaps, stated plainly:

- The verifier travels inside the archive it verifies. `install.sh` can
  prove the binary was tampered with, but an attacker who can rewrite the
  whole archive can rewrite `install.sh` too. Protection against that
  requires verifying the archive itself before running anything from it
  (its published `.sha256` or attestation; commands in README "Verifying
  your binary") or installing from a source checkout.
- A hostile process already running as the same user during install is out
  of scope here; that boundary is enforced at runtime by the bridge's peer
  attestation, not at install time.
- Binaries are not yet Apple-codesigned or notarized, and the Windows exe is
  not Authenticode-signed. Until a signing identity exists, macOS
  verification is the SHA-256 and attestation above rather than a
  cdhash/signature check. Once signing lands, released binaries will no
  longer be byte-identical to local rebuilds and verification will move to
  comparing cdhashes.
- The installer does not verify the bundled `extension/dist`; those files
  are covered only when the user verifies the whole archive before
  extraction, as above.
- `install.ps1` (Windows) performs no verification yet.

## Identifiers (rebrand, 2026-07)

The project renamed from the upstream `browser-bridge` to `chromium-bridge`
(ADR-0023). The security-relevant identifiers are now:

- native-messaging host id: `com.vivswan.chromium_bridge.host` (also the
  manifest filename stem and the extension's `connectNative` argument;
  `scripts/check-extension-id.ts` asserts all copies agree),
- enclave keychain label: `com.vivswan.chromium-bridge.enclave.signing.v1`,
- enclave challenge domain: `chromium-bridge-enclave-v1` (host and extension
  changed together; no enrolled key predated the rename, so there was no key
  migration),
- the extension id `mkjjlmjbcljpcfkfadfmhblmmddkdihf` is derived from the
  manifest `key` and did not change.

An install registered under the old host id stops working until re-installed;
that is a naming change, not a security regression.

Upgrading from a pre-rebrand install: the new tooling (installer, uninstaller,
`revoke`) only touches new-labeled artifacts, so it will not clean up an old
`com.browser_bridge.host.json` manifest, the old `browser-bridge` runtime
directory, or an Enclave key under the old
`com.browser-bridge.enclave.signing.v1` label. Those leftovers grant no
capability (the challenge domains differ, an old pin fails closed, and the new
host reports `not_enrolled`), but to remove them run the OLD uninstaller and
`browser-bridge revoke` with the old binary before switching over.

## Security-relevant changes (review bar)

A change is **security-relevant** - and must carry the
[security-change](.github/ISSUE_TEMPLATE/security-change.yml) checklist, update
the [tool risk matrix](docs/security/tool-risk-matrix.md), and (if it moves a
trust boundary) the [threat model](docs/security/threat-model.md) - if it:

- adds/broadens a Chrome permission or host permission,
- adds a way to read new sensitive data, or any write capability,
- changes confirmation, allowlist, or masking logic,
- changes native-messaging auth, the lock file, or the run secret,
- adds outbound network/IPC, or widens `page_eval`.

Such PRs should add a **negative** security test (proving the boundary holds),
not just a positive one.

## Supported versions

Pre-1.0: only the latest release is supported. Security fixes ship in a new
patch/minor release.
