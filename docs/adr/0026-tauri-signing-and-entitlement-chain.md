# ADR-0026: Signing the bundled host for Secure Enclave access (Tauri v2 spike)

- Status: Accepted (Touch ID proof pending, see "What remains open")
- Date: 2026-07-17
- Scope: the macOS signing and entitlement chain for the desktop app and the
  host binary it bundles. This is the Phase 6 record ADR-0023 promised; it
  gates the Touch ID confirmations (Phase 8) and the app UI (Phase 9).

## Context

The desktop app (`src/apps/desktop`, Tauri v2) bundles the `chromium-bridge`
host binary, and the host is the process that touches the Secure Enclave. On
a Full-Security Mac the data-protection keychain, the only keychain that can
hold Enclave keys, rejects processes that lack a
`com.apple.application-identifier` entitlement backed by a real Apple Team
ID; an earlier experiment established that a self-signed certificate is
treated as ad-hoc and cannot unlock it. The user's free Apple Development
certificate is live ("Apple Development: vivswanshah@icloud.com", Team ID
`3ZMH96L4V9`, the certificate's OU), which unblocked this spike.

The open question was empirical: can a Tauri-bundled nested binary end up
with its own entitlements, correctly signed, such that macOS honors them at
exec? Tauri does not guarantee entitlement inheritance to nested binaries,
and the plan named iced/egui as the fallback if the chain could not be made
to work.

## What the experiments showed

Each step below was run on macOS 26 (Xcode 26.6) against a release build of
the workspace at this commit. The exec probes ran the bundled host with an
unknown flag (prints help, exits 2, touches nothing) and with
`XDG_RUNTIME_DIR` pointed at a throwaway temp dir.

1. Pre-signing the host and handing it to the bundler as
   `bundle.externalBin` does not survive. The bundler re-signs every binary
   it places in `Contents/MacOS` with the identity from
   `bundle.macOS.signingIdentity` and the entitlements file from
   `bundle.macOS.entitlements`. The staged host went in carrying
   `application-identifier` plus `keychain-access-groups` and came out with
   only the app's entitlements and a new cdhash. There is no per-sidecar
   entitlements knob in Tauri 2.11.

2. Re-signing after the bundle is built works and verifies. Signing
   inside-out (the nested item first with the host's own entitlements, then
   the outer .app with its own, both with hardened runtime) yields a bundle
   that passes `codesign --verify --deep --strict` and satisfies its
   designated requirement.

3. A bare nested binary with restricted entitlements is killed at exec.
   `application-identifier` and `keychain-access-groups` are restricted
   entitlements: AMFI SIGKILLs any process carrying them unless a
   provisioning profile authorizes the pairing of team, identifier, and
   entitlements. The control (same binary, same certificate, no
   entitlements) runs fine. Embedding the profile at the outer app's
   `Contents/embedded.provisionprofile` fixes the app's own binary but does
   nothing for a bare nested one, even after the app has been launched once.

4. The fix is a helper bundle. macOS honors restricted entitlements on a
   bundle's main executable when that bundle carries its own
   `embedded.provisionprofile` (Apple documents this shape in TN3125; a
   standalone tool has nowhere to attach a profile). The host now ships as
   `Chromium Bridge.app/Contents/Helpers/chromium-bridge.app`, a minimal
   bundle: `Info.plist` (checked in at `src/apps/desktop/host-bundle/`), the
   host binary as `Contents/MacOS/chromium-bridge`, and the profile. With
   that shape the exec probe passes, and `enclave-status` performs a real
   data-protection-keychain search without an entitlement error. That search
   is the last observable step before the presence-gated signature itself.

5. The provisioning profile already existed. Xcode's automatic signing
   minted "Mac Team Provisioning Profile: com.vivswan.chromium-bridge"
   during the earlier certificate spike. It authorizes exactly our
   application identifier and `keychain-access-groups` for this team and
   this machine, and it expires seven days after minting (free tier). The
   build discovers the newest usable profile in Xcode's cache and embeds it;
   both the discovery and the check script validate the whole authorization
   (identifier, team, keychain-group coverage, this device's UDID, no
   get-task-allow, expiry) and fail closed, which is how the seven-day churn
   surfaces instead of manifesting as a mysterious SIGKILL.

## Decision

- The desktop app bundles the host as a helper bundle,
  `Contents/Helpers/chromium-bridge.app`, not as a Tauri sidecar.
  `bundle.externalBin` is not used: it cannot express per-binary
  entitlements, and its re-sign would clobber ours.
- The host carries its own entitlements file
  (`src/apps/desktop/entitlements/host.entitlements`):
  `com.apple.application-identifier` and `keychain-access-groups`, both
  `3ZMH96L4V9.com.vivswan.chromium-bridge`. The app binary carries only the
  application identifier (`app.entitlements`); it never touches the Enclave,
  and keeping the two files different also makes any future bundler
  regression visible in the dumps.
- `com.apple.security.get-task-allow` is deliberately absent from both. It
  would let any same-user process attach a debugger and read the
  Enclave-holding process's memory, exactly the non-abuse guarantee this
  project exists to keep. `scripts/check-desktop-signing.ts` fails the build
  if it ever appears, alongside its other assertions (exact entitlements on
  both binaries, Team ID, deep/strict verification, live profile).
- `just desktop-bundle` (`scripts/desktop-bundle.ts`) is the one command
  that builds, assembles, signs inside-out, and verifies. `just
  desktop-check` re-runs the verification alone.
- Supply chain: the Tauri tree was reviewed at policy level per ADR-0023
  (the GUI carries no security weight). `deny.toml` documents the accepted
  licenses it brought in and the unmaintained-crate advisories for the GTK3
  bindings (Linux-only) and `unic-*`/`proc-macro-error`; none of these
  crates is reachable from `crates/core` or `crates/host`. cargo-vet
  exemptions cover the new crates at `safe-to-run`/`safe-to-deploy` policy
  criteria.
- The iced/egui fallback is not needed. The gate that mattered (a bundled
  host that macOS lets run with Enclave-capable entitlements) is passed.

## What remains open

- The live Enclave operation under Touch ID is the one step that needs a
  finger. Runbook: `just desktop-touchid-proof` (it builds, signs, and
  verifies the bundle first), which runs the bundled host's `pair` ceremony
  (fresh mint plus a presence-gated self-test signature; declining rolls
  back). On success the machine is genuinely enrolled; `revoke` on the same
  binary undoes it. Phase 8 does not start until this has been observed
  once.
- Notarization and distribution stay out of scope (publishing is on hold).
  `spctl` assesses the bundle as rejected, which is expected for a
  non-notarized local build; locally built apps carry no quarantine flag, so
  Gatekeeper does not block them.
- The free-tier profile expires every seven days and only provisions this
  machine. Re-minting is an Xcode-side action (open a project with this
  bundle id and automatic signing); the check script's expiry failure is the
  prompt. A paid Developer ID removes both limits when distribution becomes
  real.
- Free-cert renewals change the host's cdhash roughly weekly, which touches
  the Phase 4 attestation stability plan (anchor on Team ID / designated
  requirement where possible) but not this record's chain.
- The helper Info.plist pins version 0.1.0; wiring the workspace version
  through is Phase 9 housekeeping. Whether the outer app keeps its
  application-identifier entitlement (it needs none today) is also a Phase 9
  decision; dropping it would shrink the app's surface further.
