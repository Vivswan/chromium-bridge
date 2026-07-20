# ADR-0013: Unified toolchain and CI (task entry point + GitHub Actions + single version source)

- **Status**: Accepted (the task-entry-point part was amended twice: justfile -> Makefile-only upstream, then moon after the ADR-0023 rebuild)
- **Date**: 2026-07-10
- **Deciders**: user + AI assistant

> **Amendment note**: this ADR originally adopted a **justfile** as the task entry
> point, and for a while carried a 1:1 mirrored `Makefile` (for environments
> without `just`). Two hand-synced task runners carry drift risk, so this later
> **converged on keeping only the `Makefile`** (zero install, no
> `cargo install just` needed); the `justfile` had been deleted. Wherever the text
> below says `justfile` / `just <recipe>`, read `Makefile` / `make <target>`; the
> recipe names and aggregates (`make ci` etc.) are unchanged, and the remaining
> decisions (CI, gates, version sync) are unaffected.
>
> **Second amendment (2026-07, after the ADR-0023 rebuild)**: the rebuilt repo
> readopted a justfile, then retired it for **[moon](https://moonrepo.dev)** as
> the canonical command interface, with **proto** (`.prototools`) as the
> bootstrap toolchain manager. Wherever the text below says `just <recipe>`,
> read `moon run <task>` (`moon run ci`, `moon run test-e2e`, ...); the task
> names and aggregates survive, gate tasks are deliberately uncached
> (`options.cache: false` - a gate must never be skippable by a cache hit),
> and the remaining decisions (CI shape, gates, version sync) still stand.
> See docs/development.md for the current interface.

## Context

The project spans two stacks (Rust backend + TypeScript extension) and several kinds of tests (Rust unit, protocol e2e, DOM layer, smoke), but before the cleanup it had no unified developer entry point and no automated gates:

- **Scattered commands**: build, test, and lint were each a string of commands to memorize (`cargo ...`, `npm --prefix extension run ...`, `python3 tests/protocol/e2e.py`, `bun ...`), spread across the README and human memory; a new contributor could not reproduce "what counts as passing."
- **No CI**: no automated checks at all; formatting, lint, and tests relied on contributor discipline, and regressions slipped into main easily.
- **Version drift**: the same version number lived in three places: `Cargo.toml`, `src/apps/extension/manifest.json`, `src/apps/extension/package.json`. Manual edits easily missed one, leaving backend and extension versions inconsistent.

The cleanup had to give the project a baseline of "one command runs the whole suite + CI blocks regressions + versions cannot drift."

## Decision

**Adopt a justfile as the unified task entry point, GitHub Actions CI, rustfmt/clippy/eslint/prettier gates, and a version-sync mechanism with Cargo.toml as the single source of truth.**

### 1. justfile task entry point
The `justfile` collects every developer action into named recipes: `build` / `fmt` / `lint` / `test-rust` / `test-e2e` / `build-ext` / `ext-typecheck` / `ext-lint` / `ext-format-check` / `test-browser` / `install` / `sync-version` / `check-version`, plus the aggregate recipe **`just ci`** (= fmt-check-rust + clippy + Rust unit tests + extension typecheck/lint/format-check/build + e2e). Running `just ci` before submitting reproduces most of the CI gates locally (browser tests need Chrome and are split out as `test-browser`).

### 2. GitHub Actions CI (`.github/workflows/ci.yml`)
Triggered on push to main / PR / manual dispatch, with concurrency cancellation, in five jobs:

| job | contents |
|-----|------|
| **rust** | `cargo fmt --check` -> `clippy --all-targets -D warnings` -> `cargo test` -> `cargo build --release` |
| **extension** | `npm ci` -> `typecheck` -> `lint` -> `format:check` -> `build` (in `src/apps/extension/`) |
| **version-consistency** | `./scripts/check-version.sh` |
| **e2e** | build the release binary, then `python3 tests/protocol/e2e.py` (drives the real binary) |
| **browser** | install Chrome + bun, build the extension, run `dom_test.ts` + `ext_test.ts` |

### 3. Quality gates
- **Rust**: `rustfmt` (`--check`) plus `clippy` with **`-D warnings`**, promoting every lint warning to an error.
- **Extension**: `tsc --noEmit` (strict types) + **ESLint** (flat config, focused on correctness) + **Prettier** (`--check`, the sole arbiter of formatting). Prettier owns formatting and ESLint owns correctness; the responsibilities do not overlap.

### 4. Single source of truth for the version
**`Cargo.toml` is the only source of truth for the version**, kept consistent by two scripts:
- `scripts/check-version.sh`: verifies `src/apps/extension/manifest.json` and `src/apps/extension/package.json` match `Cargo.toml`, exit 1 on mismatch (CI's version-consistency job runs it).
- `scripts/sync-version.sh`: propagates the Cargo version into the manifest (in-place sed, avoiding the `manifest_version` key) and package.json (plus package-lock.json, via `npm version`), running the check automatically at the end.

The version-bump flow: edit `Cargo.toml` -> `just sync-version` -> commit.

## Alternatives considered

### Task entry point: Makefile vs npm scripts vs justfile
- **Makefile**: universal, but full of syntax traps (tab sensitivity, `.PHONY`, variable escaping); heavyweight for "just run a string of commands."
- **npm scripts**: belongs naturally to the Node world only; shoving Rust/Python tasks into `package.json` is awkward and demands a Node project at the root.
- **justfile (adopted)**: built precisely to be a named task runner; plain syntax, no tab traps, recipes can depend on each other (`test-e2e: build`), and it fronts the Rust/Node/Python stacks equally, neutral to language.

### CI platform: GitHub Actions
The project is hosted on GitHub, so Actions has zero integration cost, and off-the-shelf actions (`dtolnay/rust-toolchain` / `Swatinem/rust-cache` / `browser-actions/setup-chrome`) cover every need. External CI was not considered.

### Version source: Cargo as source vs a standalone VERSION file
- **Standalone VERSION file**: one more intermediate source everything has to read, which adds sync points instead of removing them.
- **Cargo.toml as source (adopted)**: the backend is the project's main body, so the crate version is naturally the release version; the extension manifest/package are downstream and one-way propagation is enough, with a clear direction.

## Consequences

### Positive
- **One-command reproduction**: `just ci` makes "what counts as passing" executable and reproducible; contributors self-check locally.
- **Regressions blocked at the door**: formatting, lint (clippy `-D warnings`), types, unit tests, e2e, and DOM/smoke are all automated; main stays green.
- **Versions cannot drift**: CI forces the three locations to agree, and bumping has a clear one-way flow (edit Cargo -> sync).
- **Clear responsibilities**: Prettier owns formatting; ESLint/clippy own correctness.

### Negative
- **Contributors need the toolchain**: full local self-check requires `just`, Rust (rustfmt/clippy), Node, and Python, with browser tests additionally needing bun + Chrome. The bar is higher than "just edit."
- **Version bumps must go through sync**: you cannot edit just one version number; skipping `sync-version` gets caught by the version-consistency job (which is the design intent, but a one-time learning cost for anyone new to the flow).
- **`-D warnings` is strict**: any new clippy warning turns CI red. The upside is no lint debt; the cost is occasionally dealing with a harmless warning or writing an explicit allow.

### Neutral
- Browser tests (which need Chrome) are not in the `just ci` aggregate; they are split out as `test-browser` / CI's browser job, because their environment dependency is heavy and they layer separately from the pure-logic gates.

## Implementation

- `justfile`: all recipes plus the `ci` / `test` aggregates.
- `.github/workflows/ci.yml`: the five jobs rust / extension / version-consistency / e2e / browser.
- `scripts/check-version.sh` + `scripts/sync-version.sh`: Cargo-sourced version verification and propagation.
- Rust: `cargo fmt` / `clippy -D warnings`; extension: `eslint.config.js` (flat) + Prettier.

## Relationship to other ADRs

- **[ADR-0012](./0012-typescript-esbuild-extension-build.md)**: the extension job's typecheck/lint/format/build gates serve exactly the TS + esbuild pipeline that ADR introduced.
- **[ADR-0014](./0014-leveled-logging.md)**: the new Rust logging/error modules are covered by the rust job's clippy + `cargo test`.
