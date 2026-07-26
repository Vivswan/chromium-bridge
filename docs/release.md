# Releasing: the release-please pipeline

> This doc explains how chromium-bridge is released: merging the release PR
> cuts a release and, in the same CI run, builds prebuilt artifacts,
> checksums, and provenance attestations, plus a decoupled SBOM workflow.
> Version discipline is in [compatibility.md](./compatibility.md); on-disk
> registration paths are in
> [architecture.md section 4.3](./architecture.md#43-on-disk-artifacts).

## Trigger: merge the release PR

Releases are driven by **release-please**. Conventional commits on `main`
accumulate into a rolling release PR (`chore(main): release X.Y.Z`); merging
it tags and publishes the release. The machinery is the managed
`.github/workflows/release-please.yml`, called from the repo-owned
`.github/workflows/release.yml` pipeline, which the managed ci.yml runs
downstream of the all-green gate - so a release can only ever be cut from a
green `main`, and the packaging jobs below run in that same CI run, gated on
release-please's `release_created` output. The release PR must be created with
the `REPO_PLATFORM_TOKEN` repository secret (a PAT): a PAT-created release
triggers `on: release` workflows (sbom.yml, the Pages production deploy),
and the release PR gets CI runs. Without the secret, release-please falls
back to `GITHUB_TOKEN`, whose events fire no workflows - the release PR
needs a close/reopen to run its checks, and a published release silently
skips the SBOM and the Pages root rebuild. Configure the secret before the
first release.

Each packaging job's first step is a **version consistency check**: after stripping the leading
`v` and any `-dev`/`-rc` prerelease suffix from the tag, its core version must equal the
`version` in `Cargo.toml`, otherwise the run fails immediately. Cargo is the single
version source (see [ADR-0013](./adr/0013-ci-and-toolchain.md)). Tags with a suffix (such
as `v0.1.0-rc.1`) are marked as prereleases.

## Build matrix and prebuilt archives

release.yml builds the `binaries` job on a matrix (currently `macos-14/arm64`, `ubuntu-22.04/x64`, and
`windows-2022/x64`; Intel macOS is **deliberately omitted** because hosted runners are
scarce, and Linux uses an older glibc baseline to widen compatibility). For each target:

1. `bun scripts/build-repro.ts` produces the deterministic release binary.
2. `bun install --frozen-lockfile && bun run --cwd src/apps/extension build` produces the extension bundle.
3. Everything is packed into `chromium-bridge-<tag>-<platform>-<arch>.tar.gz` (`.zip` on
   Windows), containing the binary, `extension/dist`, `RELEASE.txt`, `LICENSE`, and
   `README.md`.
4. A `.sha256` for the archive and a separate `.binary.sha256` for the binary inside it
   are generated, and a build-provenance attestation covers both.
5. `softprops/action-gh-release` creates the GitHub Release with the assets attached and
   auto-generates release notes.

Users therefore **do not need a Rust/bun toolchain** to install: registration is the
binary's own `chromium-bridge doctor --fix` (or the desktop app), see
[quickstart.md](./quickstart.md). All third-party Actions are pinned to commit SHAs
(supply-chain governance).

## The desktop app job (macOS)

release.yml has a second macOS job, `desktop-app`, that builds the signed
desktop bundle (the helper-bundle host with its own entitlements,
[ADR-0026](./adr/0026-tauri-signing-and-entitlement-chain.md)), wraps it in a
disk image, and attaches `chromium-bridge-app-<tag>-macos-arm64.dmg` plus its
`.sha256` and a provenance attestation to the same release. It is the CI
equivalent of `moon run dmg-app`, including the re-verification of the app inside
the mounted image by `scripts/check-desktop-signing.ts`.

The job needs signing material that forks and secretless checkouts do not
have, so it is gated: a small `desktop-signing-secrets` job checks whether the
secrets are configured and the `desktop-app` job skips cleanly (it does not
fail) when they are absent. The binary and extension release is never blocked
by the desktop job.

Required repository secrets:

| Secret | Content |
|--------|---------|
| `MACOS_CERT_P12_BASE64` | base64 of the signing certificate and its private key, exported from Keychain Access as a `.p12`. Must contain the identity named in `tauri.conf.json`'s `bundle.macOS.signingIdentity` |
| `MACOS_CERT_PASSWORD` | the passphrase chosen for that `.p12` export |
| `MACOS_PROVISION_PROFILE_BASE64` | base64 of a provisioning profile that authorizes the full entitlement chain (identifier, team, keychain group) |

The certificate is imported into an ephemeral keychain that is deleted when
the job ends, and the profile is passed to the build via
`PROVISION_PROFILE_PATH` (locally, `scripts/desktop-bundle.ts` instead
discovers the newest usable profile in Xcode's cache). The build validates the
supplied profile fail-closed with one exception: the this-device check is
skipped, because a CI runner is never in the profile's device list. That check
is packaging validation, not enforcement; macOS itself refuses to run the app
on any Mac the profile does not provision.

**Free-tier churn:** a free Apple Development profile expires seven days after
Xcode mints it, so `MACOS_PROVISION_PROFILE_BASE64` has to be refreshed
shortly before merging a release PR:

```sh
base64 -i ~/Library/Developer/Xcode/UserData/Provisioning\ Profiles/<uuid>.provisionprofile \
  | gh secret set MACOS_PROVISION_PROFILE_BASE64
```

A free-tier profile also only provisions the enrolled Macs it lists, so a
`.dmg` signed this way runs on those machines and nowhere else. The profile
additionally has to authorize the exact certificate in the `.p12`:
`check-desktop-signing.ts` compares the signer's leaf certificate against the
profile's `DeveloperCertificates` and fails the build on a mismatch, so a
renewed certificate means re-minting the profile and refreshing both secrets
together. A paid Developer ID removes these limits.

### Notarization (optional, needs a paid Developer ID)

The job notarizes and staples the `.dmg` (`xcrun notarytool submit --wait`,
then `xcrun stapler staple`) only when all three notarization secrets are
configured: `APPLE_ID`, `APPLE_APP_PASSWORD` (an app-specific password), and
`APPLE_TEAM_ID`. The free Apple Development certificate **cannot notarize**;
these secrets can only exist once a paid Developer ID membership does. Without
them the step is skipped and the job logs it plainly: the `.dmg` is
dev-signed, not notarized, and Gatekeeper will warn on other Macs. Stapling
runs before the checksum and attestation steps so the published digest matches
the exact bytes users download.

## SBOM: a decoupled CycloneDX workflow

`.github/workflows/sbom.yml` is independent of release.yml and triggers on
`release: published` (that is, **after** the release has been created):

- It uses `anchore/sbom-action` to generate CycloneDX JSON
  (`chromium-bridge.cdx.json`) from the **committed lock files** (`Cargo.lock` +
  `bun.lock`), scanning declared dependencies rather than an installed
  tree (a fresh checkout has no `node_modules`/`target`).
- It attaches the SBOM as an asset to the Release for the corresponding tag.

The decoupling is deliberate: an SBOM tooling failure can **never block** a binary
release.

## SemVer rules

Compatibility discipline holds before 1.0 too; `0.x` is not treated as a license to break
compatibility at will:

- **Patch**: bug fixes, internal refactors, logging improvements; no changes to tool
  parameters or security semantics.
- **Minor**: new tools, new optional fields, new capabilities, new configuration;
  backward compatible.
- **Major**: removing/renaming tools, changing field meanings, changing default
  permissions, loosening a security boundary, or an incompatible Bridge protocol or
  extension version (corresponding to an internal bridge protocol version bump, see
  [compatibility.md](./compatibility.md)).

## Not yet in place (honest statement)

- macOS **real integration tests in the release gate**: they need a real browser and are
  not part of the release gate yet.
- **Desktop app signing secrets**: none are configured yet, so the `desktop-app` job
  currently skips on every run. Wiring exists; the secrets (and a decision to publish)
  do not.
- **Notarization**: needs a paid Apple Developer ID membership. Until then any published
  `.dmg` would be dev-signed only, and device-limited by the free-tier profile.

## Related

- Operations and diagnostics: [operations.md](./operations.md).
- Versions and the handshake: [compatibility.md](./compatibility.md).
- CI and toolchain: [ADR-0013](./adr/0013-ci-and-toolchain.md).
