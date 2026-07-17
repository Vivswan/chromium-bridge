# Releasing: the tag-driven release pipeline

> This doc explains how browser-bridge is released: pushing a tag triggers
> prebuilt artifacts, checksums, and the dual-mode install script, plus a
> decoupled SBOM workflow. Version discipline is in
> [compatibility.md](./compatibility.md); install artifact paths are in
> [architecture.md section 4.3](./architecture.md#43-install-artifacts).

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

## Build matrix and prebuilt tarballs

release.yml builds on a matrix (currently `macos-14/arm64` and `ubuntu-22.04/x64`; Intel
macOS is **deliberately omitted** because hosted runners are scarce, and Linux uses an
older glibc baseline to widen compatibility). For each target:

1. `cargo build --release` produces the binary.
2. `npm ci && npm run build` produces the extension bundle (`extension/dist/`).
3. Everything is packed into `browser-bridge-<tag>-<platform>-<arch>.tar.gz`, containing
   the binary, `extension/dist`, `install.sh`, `mcp-config.example.json`, `LICENSE`, and
   `README.md`.
4. A `.tar.gz.sha256` checksum is generated (`shasum` or `sha256sum`).
5. `softprops/action-gh-release` creates the GitHub Release with the tarball + `.sha256`
   attached, and auto-generates release notes.

Users therefore **do not need a Rust/Node toolchain** to install. All third-party Actions
are pinned to commit SHAs (supply-chain governance).

## Dual-mode install.sh

The same `install.sh` automatically distinguishes two modes:

- **Source mode** (a `Cargo.toml` is present): builds the binary with Rust and the
  extension with Node/npm on the spot, then installs.
- **Prebuilt mode** (no `Cargo.toml`, i.e. after unpacking a release tarball): installs
  the bundled binary and `extension/dist` directly, requiring **neither** Rust nor Node.

Both modes register the Chrome native messaging host manifest (`allowed_origins` is
hard-coded to the extension ID); details are in
[architecture.md section 4.3](./architecture.md#43-install-artifacts) and
[operations.md](./operations.md). Windows uses `install.ps1` (see
[ADR-0015](./adr/0015-windows-support.md)).

## SBOM: a decoupled CycloneDX workflow

`.github/workflows/sbom.yml` is independent of release.yml and triggers on
`release: published` (that is, **after** the release has been created):

- It uses `anchore/sbom-action` to generate CycloneDX JSON
  (`browser-bridge.cdx.json`) from the **committed lock files** (`Cargo.lock` +
  `extension/package-lock.json`), scanning declared dependencies rather than an installed
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
