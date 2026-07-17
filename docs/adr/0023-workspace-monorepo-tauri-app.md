# ADR-0023: Workspace monorepo, Tauri v2 control panel, and the chromium-bridge rebrand (umbrella)

- Status: Accepted
- Date: 2026-07-17
- Scope: umbrella. This ADR records the shape of the rebuild and the
  decisions that hold across it. Each security-bearing piece gets its own
  ADR as it lands (multi-client pairing and the broker, revocation,
  signing, the extension rehaul, Touch ID confirmations, the app UI);
  those ADRs bind the details, this one binds the direction.

## Context

The project is a single flat Rust crate plus an MV3 extension. That shape
was right for what it was: one binary, two modes, one trusted client. Three
pressures have outgrown it.

First, the user asked for a cross-platform desktop control panel without
giving up the Rust security core. Everything that makes the bridge safe
lives in Rust: kernel-attested peer identity, the Secure Enclave enrollment
key, constant-time HMAC verification, the 0600 Unix-domain socket. A GUI
rewrite in another stack would orphan that. A Tauri v2 app keeps the GUI in
a webview while the process and every enforcement path stay in Rust.

Second, the flat crate cannot be shared. The app needs the same path
resolution, allowlist access, and enclave logic the host uses, and today
that code is only reachable by being the host binary. Copying it would
create exactly the kind of hand-synced mirror this codebase has been
eliminating.

Third, the planned security work (multiple attested MCP clients driving
concurrently, any-side revocation, Touch ID-gated confirmations) adds
components that do not fit in a single binary's mental model and need to be
threat-modeled as their own surfaces.

Separately, the user directed a rebrand to their own identity. The original
naming (`browser-bridge`, `com.browser_bridge.host`) was kept byte-identical
to upstream `whg517/browser-bridge` so upstream fixes merged cleanly. That
invariant is now deliberately dropped.

## Decision

1. **Cargo workspace.** The flat crate splits into a workspace:
   `src/packages/core` (library: ipc, protocol, session, tools, enclave, error,
   log, plus the new allowlist / revocation / broker modules) and
   `src/apps/host` (the binary; the `main.rs` mode dispatch moves verbatim,
   so the argv and native-messaging contracts are untouched). The TS side
   becomes a bun workspace with a shared package consumed by both the
   extension and the app UI.

2. **Tauri v2 control panel.** A new `app/` member depends on `core`, not
   on `host`. It is a management surface: pair and revoke named clients,
   show status, register the native-messaging manifest, bundle the
   extension files for the user to load. It bundles and pre-signs the host
   binary; the host carries its own entitlements because Tauri does not
   guarantee entitlement inheritance to nested binaries (the signing spike
   ADR records the empirical result).

3. **The UI carries no security weight.** Every enforcement decision
   (attestation, allowlist admission, revocation comparison, Enclave
   user-presence) executes in Rust in `core` or `host`. The webview, React,
   and the rest of the frontend stack are display and input only. This is
   where the zero-trust budget goes: bespoke review effort is spent on the
   Rust security core, and the UI leans on widely-adopted,
   community-audited libraries instead of re-auditing a GUI stack.

4. **Rebrand to the user's identity.** Crate, binary, and app become
   `chromium-bridge`. The native-messaging host id becomes
   `com.vivswan.chromium_bridge.host` (that namespace allows only letters,
   digits, underscore, and dot). The Tauri bundle id and keychain access
   group become `com.vivswan.chromium-bridge`, and the enclave keychain
   label `com.vivswan.chromium-bridge.enclave.signing.v1`. The extension's
   manifest name becomes "Chromium Bridge"; its ID is derived from the
   manifest `key`, is not a name, and stays put. `LICENSE`, attribution,
   and git history keep the upstream name. Cost accepted: future upstream
   fixes become manual ports instead of clean merges. The
   "stay mergeable with upstream" guidance in `CLAUDE.md` is retired by
   this decision.

5. **New trust boundaries are named before they are built.** The rebuild
   introduces five surfaces that did not exist: admission control at the
   MCP stdio boundary, a ref-counted broker that owns the browser-facing
   socket, writers of the host-side client allowlist, the app acting as an
   issuer of pairing and revocation, and the Touch ID confirmation surface.
   Each is enumerated in the threat model now (as a stub naming the
   boundary, its enforcement point, and its residual) and gets a full
   treatment in the ADR of the phase that builds it. None of them may ship
   enforced by assumption; the mechanism lands with the component. Where a
   boundary has no known unforgeable mechanism yet (stdio admission is the
   honest example: an anonymous pipe carries no kernel peer credentials,
   so the socket layer's attestation does not transfer), the stub says so,
   and choosing or rejecting a mechanism is that phase's ADR decision.

## What is NOT changed

The security architecture of the existing bridge is carried over, not
redesigned: the 0600 socket in the 0700 runtime directory, the kernel
peer-UID check, executable attestation, the HMAC challenge-response, the
enrollment ceremony, origin allowlisting, masking, and the per-action
confirmations all survive the move into `src/packages/core` with their semantics
intact. The native-messaging protocol and the MCP tool catalogue are
unchanged by the restructure itself. "stdout is protocol" still holds in
both binary modes.

## Disposition of existing ADRs

The rebuild touches ground covered by most of the existing records. This
map is forward-looking: it says what each phase will do to which ADR, so
the phase that lands a new record knows exactly which old one to flip.
The old ADRs themselves are not edited here, because a
"Superseded by ADR-00XX" line pointing at a record that does not exist
yet is a dangling reference. Each superseding phase updates its target's
Status line in the same commit that adds the new ADR.

Superseded (the new record replaces the decision):

- ADR-0006 (toast confirmation for high-risk) by the extension-rehaul
  and Touch ID records: Phase 7 supersedes the surface (the toast moves
  off the page-reachable DOM) and marks 0006 then; Phase 8 completes the
  supersession for the tools whose confirmation becomes the Enclave tap.
- ADR-0008 (page-eval confirmation channel) by the Touch ID record
  (Phase 8).
- ADR-0012 (TypeScript + esbuild extension build) by the Phase 3
  toolchain record (bun, WXT, Biome).
- ADR-0013 (CI and toolchain) in part by this phase's CI changes and the
  rest by Phase 3.
- ADR-0014 (leveled logging) by a tracing-based record; its thiserror
  decision stays.

Extended (the decision stands; a new record builds on it):

- ADR-0019 (authenticated IPC) and ADR-0020 (kernel-attested peer
  identity) by the multi-client pairing record (Phase 4).
- ADR-0021 (enrollment ceremony) by the revocation and Touch ID records
  (Phases 5 and 8).
- ADR-0022 (multi-browser label routing) is adjacent to the broker work
  and stays valid; the broker record must not weaken its
  per-connection guarantees.

Amended (the decision stands with a detail changed):

- ADR-0001 (single Rust binary): the binary survives, now built from a
  workspace.
- ADR-0011 (options page for settings): the settings surface survives on
  the new UI stack.
- ADR-0018 (tab workspace group): the group name follows the rebrand to
  "Chromium Bridge".
- ADR-0003, ADR-0009, ADR-0017 (snapshot and CDP decisions): the
  decisions stand; Phase 7 unifies their duplicated DOM layers into one
  source.

A language note: ADR-0001 through 0018 were authored in Chinese by the
upstream project. The rebuild's docs are English-canonical, so those
records get English versions as part of the docs consolidation; that
conversion is tracked as its own change and is not part of this record.

## Residual risks, named honestly

- **The workspace move is a mass rename.** Every path in docs, CI,
  installers, and the repo-platform managed files points at the flat
  layout. A missed reference fails loudly in CI at best and silently
  (a stale doc, a wrong install path) at worst. Mitigation: the rename and
  the structural move happen in one reviewed pass, gated by a
  full-tree grep for the old names. The CI jobs added ahead of the move
  run unqualified `cargo` commands (build, test, clippy, vet, coverage);
  when `app/` joins the workspace they would pull in Tauri and its GUI
  dependencies, so that phase must scope them with explicit packages or
  workspace `default-members`.
- **Tauri is a large new dependency in the same process tree as the
  management surface.** It never sits on the enforcement path, but a
  compromised webview could present a lying UI (showing "revoked" while
  not revoking). The mitigation is that state-changing operations go
  through `core` APIs whose effects are independently observable via the
  CLI (`doctor`, `status`), and the confirmation that guards the crown
  jewels is the Enclave prompt, which no webview can forge or answer. A
  compromised webview can still decline to ask, which denies the
  operation; denial fails closed.
- **The rebrand breaks the upstream merge path permanently.** This is a
  one-way door, chosen with the cost stated. Upstream security fixes must
  now be watched for and ported by hand.
- **A workspace invites coupling.** `app` depending on `core` is the
  point; `app` growing its own enforcement logic would be a regression.
  The rule that enforcement lives only in `core`/`host` is stated here and
  in the threat model so review has something to point at.
