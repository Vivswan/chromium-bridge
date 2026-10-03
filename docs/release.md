# Releasing: the release-please pipeline

> This doc explains how chromium-bridge is released: merging the release PR cuts a draft release and, in the same CI run, builds prebuilt artifacts, checksums, provenance attestations, and an SBOM onto the draft, then publishes it. Version discipline is in [compatibility.md](./compatibility.md); on-disk registration paths are in [architecture.md section 4.3](./architecture.md#43-on-disk-artifacts).

## Trigger: merge the release PR

Releases are driven by **release-please**. Conventional commits on `main` accumulate into a rolling release PR (`chore(main): release X.Y.Z`); merging it cuts the release. GitHub releases are immutable once published (the tag and assets freeze), so every release moves through the same three steps, always draft-first, all in one CI run:

1. release-please creates the release as a **draft** with its tag already forced at the merge SHA (`draft` + `force-tag-creation` in `release-please-config.json`). The release body is release-please's changelog entry; GitHub's auto-generated notes are not added.
2. The packaging jobs below - this repository's jobs in the repo-owned `.github/workflows/update-release.yml` hook - mutate the draft: they build from the tag and attach their assets with `gh release upload`. A `mark-prerelease` job in the hook flags tags with a suffix as prereleases while the release is still a draft.
3. The fleet's `publish-release` stage waits for every hook job, attests build provenance for every asset on the draft into a single `attestation.json` asset, and flips the draft live. Publishing is structurally last: the hook cannot reorder or skip it.

If the pipeline dies after the draft exists, a rerun cannot recreate it (release-please sees the forced tag); re-run the failed jobs, or finish by hand with `gh release upload <tag> <assets> --clobber` and `gh release edit <tag> --draft=false` (a hand-published release carries no `attestation.json`).

The machinery is the managed `.github/workflows/ci.yml`, downstream of the all-green gate, so a release can only ever be cut from a green `main`, and the packaging jobs run in that same CI run. Its jobs, in order: `release` calls the fleet's `fleet-release.yml` (release-please cuts the draft); `update-release` calls this repository's hook, only when release-please reports `release_created`; `publish-release` calls the fleet's `fleet-release-publish.yml` (attest, then publish); `pages` deploys the site after the publish, in the same run. `update-release-pr` calls the repo-owned `update-release-pr.yml` hook whenever release-please creates or refreshes the release PR. The managed workflows run on `github.token` alone; no repository secret is involved. release-please creates the release PR with that token, so the PR's CI run does not start on its own: close and reopen it (or push to it) to run its checks. A release cut can also fail when a workflow-file change lands on `main` between the release PR merge and the cut job, because `github.token` cannot create a ref on a commit whose workflow files differ from `main`; the next merge to `main` runs release-please again and cuts it, or cut the release by hand.

Each packaging job's first step is a **version consistency check**: after stripping the leading `v` and any `-dev`/`-rc` prerelease suffix from the tag, its core version must equal the `version` in `Cargo.toml`, otherwise the run fails immediately. Cargo is the single version source (see [ADR-0013](./adr/0013-ci-and-toolchain.md)). Tags with a suffix (such as `v0.1.0-rc.1`) are marked as prereleases.

## Build matrix and prebuilt archives

update-release.yml builds the `binaries` job on a matrix (currently `macos-14/arm64`, `ubuntu-22.04/x64`, and `windows-2022/x64`; Intel macOS is **deliberately omitted** because hosted runners are scarce, and Linux uses an older glibc baseline to widen compatibility). For each target:

1. `bun scripts/build-repro.ts` produces the deterministic release binary.
2. `bun install --frozen-lockfile && bun run --cwd src/apps/extension build` produces the extension bundle.
3. Everything is packed into `chromium-bridge-<tag>-<platform>-<arch>.tar.gz` (`.zip` on Windows), containing the binary, `extension/dist`, `RELEASE.txt`, `LICENSE.md`, and `README.md`.
4. A `.sha256` for the archive and a separate `.binary.sha256` for the binary inside it are generated, and a build-provenance attestation covers both; its Sigstore bundle becomes the `chromium-bridge-<tag>-<platform>-<arch>.attestation.jsonl` asset. The standalone extension zip and the SBOM ship `<asset>.attestation.jsonl` bundles the same way; `--bundle` verification is documented in [SECURITY.md](../.github/SECURITY.md#release-artifact-integrity).
5. `gh release upload` attaches the assets to the draft release; the fleet's `publish-release` stage then attests every asset on the draft into the release-level `attestation.json` and publishes it once every hook job is done.

Users therefore **do not need a Rust/bun toolchain** to install: registration is the binary's own `chromium-bridge doctor --fix`, see [quickstart.md](./quickstart.md). Third-party Actions are pinned to commit SHAs in this repository's workflows and in the fleet's release legs alike; the platform's own actions and reusable workflows are taken at `@stable`, a moving tag that names a green `main` commit of the platform (the residual recorded in [ADR-0033](./adr/0033-adopt-repo-platform-fleet-template.md); the trust model in repo-platform's [build-provenance.md](https://github.com/Vivswan/repo-platform/blob/main/docs/build-provenance.md)).

## SBOM: CycloneDX onto the draft

The `sbom` job in update-release.yml runs alongside the packaging jobs (it used to be a decoupled `release: published` workflow, but a published release is immutable, so the SBOM has to land on the draft):

- It uses `anchore/sbom-action` to generate CycloneDX JSON (`chromium-bridge.cdx.json`) from the **committed lock files** (`Cargo.lock` + `bun.lock`), scanning declared dependencies rather than an installed tree (a fresh checkout has no `node_modules`/`target`).
- It attests the SBOM's build provenance (same `actions/attest-build-provenance` step as the binaries), so `gh attestation verify chromium-bridge.cdx.json --repo <repo>` works on the downloaded asset.
- It attaches the SBOM and its `.attestation.jsonl` bundle to the draft release for the tag.

An SBOM tooling failure still **never blocks** a binary release: the job is `continue-on-error`, so the fleet's publish stage (which waits for every hook job) still runs - the release goes out without an SBOM and the annotated failure on the run flags it. Because the attest step runs before the upload (an asset nobody can verify must not ship), an attestation outage costs the SBOM asset the same way. The loss is permanent for that tag - the published release is immutable, so the SBOM cannot be attached afterwards; the next release carries one again.

## SemVer rules

Compatibility discipline holds before 1.0 too; `0.x` is not treated as a license to break compatibility at will:

- **Patch**: bug fixes, internal refactors, logging improvements; no changes to tool parameters or security semantics.
- **Minor**: new tools, new optional fields, new capabilities, new configuration; backward compatible.
- **Major**: removing/renaming tools, changing field meanings, changing default permissions, loosening a security boundary, or an incompatible Bridge protocol or extension version (corresponding to an internal bridge protocol version bump, see [compatibility.md](./compatibility.md)).

## Not yet in place (honest statement)

- macOS **real integration tests in the release gate**: they need a real browser and are not part of the release gate yet.

## Related

- Operations and diagnostics: [operations.md](./operations.md).
- Versions and the handshake: [compatibility.md](./compatibility.md).
- CI and toolchain: [ADR-0013](./adr/0013-ci-and-toolchain.md).
