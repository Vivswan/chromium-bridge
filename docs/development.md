# Development guide

This document covers the local dev loop, the build/test toolchain, and the
release process. For the **branch / commit / sync / merge workflow** (worktrees,
Conventional Commits, rebase, squash-merge, gates), see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md). For *why* the project is structured
the way it is, see [architecture.md](./architecture.md) and the [ADRs](./adr/).

## Prerequisites

| Tool | Used for | Notes |
|------|----------|-------|
| Rust (cargo) | the `chromium-bridge` binary | stable toolchain; `rustfmt` + `clippy` components, `cargo-nextest` as the test runner |
| bun | everything TypeScript | package manager, script runner, extension bundling, TS test suites. Pinned via the root `package.json` `packageManager` field |
| Python 3 | protocol e2e tests | stdlib only |
| Chrome | DOM + smoke tests | `CHROME_BIN` overrides the path |
| [`just`](https://just.systems/) | task runner | the `justfile` collects every dev task; `just` lists the human-facing ones, grouped (internal sub-checks are `[private]`: hidden from the list, still runnable by name). Each recipe is a plain command you can also run by hand |
| [`typos`](https://github.com/crate-ci/typos) + [`cargo-machete`](https://github.com/bnjbvr/cargo-machete) | spelling + unused-dependency gates | `just typos` / `just machete`; CI gates both |

Git hooks are managed by [lefthook](https://lefthook.dev) (`lefthook.yml`):
`bun install` wires a pre-commit hook that runs `just ci`, so a commit that
would fail CI fails at commit time instead.

## Layout

The TypeScript side is a bun workspace rooted at the repo top level
(`package.json` `workspaces`), sharing one `bun.lock` and one `node_modules/`.
Buildable code lives under `src/` (apps and packages); every directory there is
a member of either the cargo workspace or the bun workspace, so one gate
compiles the whole graph. TS packages keep sources and tests in separate
folders (`src/` and `tests/`).

```
src/apps/host/           Rust binary "chromium-bridge" (thin argv dispatch over the library)
src/apps/extension/      MV3 extension (WXT); builds to build/extension/ (gitignored)
src/apps/desktop/        Tauri v2 desktop app (ADR-0026/0029): workspace member but
                         NOT a default member; `just desktop-bundle` builds + signs
                         it with the bundled host (see docs/desktop-app.md)
src/packages/core/       Rust library "chromium-bridge-core": MCP server + native-host bridge
src/packages/core/fuzz/  cargo-fuzz workspace for the wire parsers (nightly + libFuzzer)
src/packages/shared/     contract types / validators / i18n (bun workspace member)
tests/protocol/          e2e.py, adversarial.py, chaos.py - drive the real release binary
tests/browser/           dom_test.ts, ext_test.ts, security_browser_test.ts,
                         integration_e2e.ts, run_all.ts (bun workspace member; isolated Chrome only)
tests/fixtures/          HTML/CSS pages and the probe extension the browser suites load
scripts/                 bun workspace member: gen-ops.ts, check-version.ts, sync-version.ts,
                         check-extension-id.ts, build-repro.ts, lib.ts, ...
.github/scripts/         CI-only scripts (fuzz_smoke.ts, run by the nightly fuzz job;
                         typechecked by `tsc -p scripts` alongside scripts/)
src/apps/web/           bun workspace member: minimal Astro site rendering the
                         repo's markdown docs + translations (just web-build;
                         not part of `just ci`)
```

All tooling scripts are TypeScript run via bun. Scripts whose only consumer
is a GitHub workflow live in `.github/scripts/`; everything with a local
consumer (justfile, other scripts) stays in `scripts/`. Two of them
(`scripts/build-repro.ts` and `.github/scripts/fuzz_smoke.ts`) are
deliberately self-contained on node builtins so they work before
`bun install` - the release workflow builds the binary before installing
the workspace.

Rust dependencies are gated by supply-chain review (`cargo vet`, the
`cargo-vet` CI job). Adding or bumping a crate fails CI until the new version
has a recorded decision in `supply-chain/`: run `cargo vet` to see what is
missing, then `cargo vet certify` if you actually reviewed the code, or
`cargo vet add-exemption` to record a deliberate exemption. The initial
baseline exempts the pre-existing tree; the point of the gate is that no new
code enters the build without someone choosing to let it in.

## Common tasks

With `just` (`just` lists the top-level verbs; every sub-step - `ext-build`,
`test-browser`, `gen`, `typecheck`, `build-repro`, the CI sub-checks, ... -
is `[private]`: hidden from the list but runnable by name):

```sh
just build     # build everything (see below)
just dev       # dev everything: extension (WXT) + docs site (Astro) + desktop app (tauri)
just test      # rust tests (nextest) + protocol e2e
just ci        # everything CI runs, minus the browser job
just release   # pre-release gate: version checks + full ci
just install   # build the release binary, then register it (doctor --fix)
just lint      # lint everything: clippy -D warnings + biome lint
just fmt       # format everything: cargo fmt + biome format
just fix       # auto-fix everything: biome check --write + cargo fmt
just app-run   # build, sign, verify, then launch the desktop app
```

`just build` builds the entire repo in one command: it typechecks
`src/packages/shared`, bundles the extension, builds the desktop UI,
typechecks `scripts/`, runs `cargo build --workspace`, and finishes by
building the docs site. Use it to
prove the whole graph still compiles after a cross-cutting change.

The justfile is the canonical command interface: every task is a `just`
recipe, and the root `package.json` scripts are thin aliases that delegate to
the corresponding recipe, so both entry points share one implementation. The
JS-flavored root verbs (`lint`, `format`, `format:check`, `check`, `test`)
delegate to the `*-ts` recipes; `build`, `gen`, and `typecheck` delegate to
the same-named recipes; the repo-wide verbs in `just` cover every language at
once (`just lint` = clippy + biome lint, `just fmt` = cargo fmt + biome
format, `just test` = Rust + protocol e2e). Each recipe is a plain command
you can also run by hand:

```sh
cargo build --release
cargo nextest run
cargo fmt --check && cargo clippy --all-targets -- -D warnings
python3 tests/protocol/e2e.py
bun install
bunx tsc -p src/apps/extension  # one TS project; `just typecheck` covers all five
bunx biome ci .                 # lint + format check (biome.json)
bun run --cwd src/apps/extension build
```

## Working on the extension

The extension is built on WXT
([ADR-0027](./adr/0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md)),
which generates the manifest (including the pinned key) and bundles the
entrypoints under `src/apps/extension/src/entrypoints/`.

```sh
bun install
bun run --cwd src/apps/extension dev       # WXT dev mode: rebuild on change
bun run --cwd src/apps/extension build     # production bundle
```

Load `build/extension/chrome-mv3` as an unpacked extension in
`chrome://extensions` (Developer mode). Unit tests
(`bun run --cwd src/apps/extension test`) run on Vitest with `fakeBrowser`,
no real browser needed.

## Testing

Three suites, all wired into `tests/browser/run_all.ts` (and CI):

- **Protocol** (`tests/protocol/e2e.py`) - drives the real release binary as
  subprocesses over the actual wire protocols. No browser needed.
- **DOM** (`tests/browser/dom_test.ts`, bun) - injects the built content script
  (`build/extension/chrome-mv3/content-scripts/content.js`) into
  a headless Chrome page via CDP and exercises every content-script op.
- **Smoke** (`tests/browser/ext_test.ts`, bun + puppeteer-core) - launches Chrome with
  `build/extension/chrome-mv3` loaded and checks the service worker boots. Set
  `BB_EXT_DIR` to point
  at a different unpacked extension.

```sh
bun tests/browser/run_all.ts          # all three (skips browser tests if Chrome absent)
CHROME_BIN=/path/to/chrome bun tests/browser/run_all.ts
```

## Logging

Both binary modes log to **stderr** (stdout carries the wire protocols). Set the
level with `BB_LOG`:

```sh
BB_LOG=debug chromium-bridge          # verbose
BB_LOG=error chromium-bridge          # quiet
# default is info
```

## Releasing

`Cargo.toml` is the single source of truth for the version.

```sh
# 1. bump the version in Cargo.toml
# 2. propagate it to the extension manifest + package files
just sync-version        # bun scripts/sync-version.ts
# 3. update CHANGELOG.md (move [Unreleased] items under the new version)
# 4. gate on a clean tree
just release             # check-version + full ci
# 5. tag - pushing a v* tag triggers .github/workflows/release.yml, which
#    builds macOS Apple Silicon, Linux x64, and Windows x64 archives (binary
#    + built extension) and publishes them to GitHub Releases.
git tag vX.Y.Z && git push --tags
```

CI (`.github/workflows/ci.yml`) enforces version consistency on every push, so
a forgotten `sync-version` fails the build. The release workflow also refuses to
run if the tag doesn't match the Cargo version.
