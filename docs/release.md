# Releasing: the tag-driven release pipeline

> This doc explains how chromium-bridge is released: pushing a tag triggers
> prebuilt artifacts, checksums, and provenance attestations, plus a
> decoupled SBOM workflow. Version discipline is in
> [compatibility.md](./compatibility.md); on-disk registration paths are in
> [architecture.md section 4.3](./architecture.md#43-on-disk-artifacts).

## Trigger: push a tag

Releases are driven by a **git tag** (`.github/workflows/release.yml`,
`on: push: tags: ["v*"]`, with a `workflow_dispatch` manual entry point as well):

```bash
git tag v0.1.0 && git push --tags
```

The pipeline's first step is a **version consistency check**: after stripping the leading
`v` and any `-dev`/`-rc` prerelease suffix from the tag, its core version must equal the
`version` in `Cargo.toml`, otherwise the run fails immediately. Cargo is the single
version source (see [ADR-0013](./adr/0013-ci-and-toolchain.md)). Tags with a suffix (such
as `v0.1.0-rc.1`) are marked as prereleases.

## Build matrix and prebuilt archives

release.yml builds on a matrix (currently `macos-14/arm64`, `ubuntu-22.04/x64`, and
`windows-2022/x64`; Intel macOS is **deliberately omitted** because hosted runners are
scarce, and Linux uses an older glibc baseline to widen compatibility). For each target:

1. `scripts/build-repro.sh` produces the deterministic release binary.
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

## SBOM: a decoupled CycloneDX workflow

`.github/workflows/sbom.yml` is independent of release.yml and triggers on
`release: published` (that is, **after** the release has been created):

- It uses `anchore/sbom-action` to generate CycloneDX JSON
  (`chromium-bridge.cdx.json`) from the **committed lock files** (`Cargo.lock` +
  `bun.lock`), scanning declared dependencies rather than an installed
  tree (a fresh checkout has no `node_modules`/`target`).
- It attaches the SBOM as an asset to the Release for the corresponding tag.

**Why decoupled**: the SBOM workflow is separated from the binary release, so an SBOM
tooling failure can **never block** a binary release.

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

## Related

- Operations and diagnostics: [operations.md](./operations.md).
- Versions and the handshake: [compatibility.md](./compatibility.md).
- CI and toolchain: [ADR-0013](./adr/0013-ci-and-toolchain.md).
