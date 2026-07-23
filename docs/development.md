# Development guide

This document covers the local dev loop, the build/test toolchain, and the
release process. For the **branch / commit / sync / merge workflow** (worktrees,
Conventional Commits, rebase, squash-merge, gates), see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md). For *why* the project is structured
the way it is, see [architecture.md](./architecture.md) and the [ADRs](./adr/).

## Prerequisites

[proto](https://moonrepo.dev/proto) is the bootstrap toolchain manager: one
`proto install` in a fresh checkout provisions every tool pinned in the
repo-root `.prototools` (bun, moon, a rustup pre-install of the pinned rust,
uv). One prerequisite proto does not cover: `rustup` itself must already be
installed (proto's rust plugin manages toolchains *through* rustup rather
than installing it) - a truly fresh machine needs
[rustup.rs](https://rustup.rs) first. Install proto once, make sure
`~/.proto/shims` and `~/.proto/bin` are on your PATH, then:

```sh
proto install    # provisions bun, moon, rust, uv at the pinned versions
bun install      # workspace deps + wires the git hooks (lefthook)
```

Four gate tools have no first-party proto plugin and are installed once by
hand: `cargo install cargo-nextest` and `brew install typos-cli
cargo-machete actionlint` (typos and cargo-machete can also come from `cargo
install`). CI pins typos, cargo-machete, and actionlint in its own jobs, so
a local version skew can at worst surface a finding early, never hide one
from CI.

| Tool | Used for | Notes |
|------|----------|-------|
| [proto](https://moonrepo.dev/proto) | toolchain bootstrap | provisions everything pinned in `.prototools`; the pins are cross-checked by `moon run check-toolchain` |
| [moon](https://moonrepo.dev) | task runner | the canonical command interface: every dev task is a moon task. `moon run help` lists them; `moon run <task>` runs one |
| Rust (cargo) | the `chromium-bridge` binary | pinned by `rust-toolchain.toml` (the authoritative pin; rustup and IDEs read it); `rustfmt` + `clippy` components, `cargo-nextest` as the test runner |
| bun | everything TypeScript | package manager, script runner, extension bundling, TS test suites. Pinned in `.prototools` (and mirrored in `package.json` `packageManager`) |
| [`uv`](https://docs.astral.sh/uv/) | protocol e2e tests | provisions the exact Python pinned in the repo-root `.python-version`, so local runs and CI use the same interpreter. uv itself is pinned only in `.prototools`. The suites are stdlib-only |
| Chrome | DOM + smoke tests | `CHROME_BIN` overrides the path |
| [`typos`](https://github.com/crate-ci/typos) + [`cargo-machete`](https://github.com/bnjbvr/cargo-machete) | spelling + unused-dependency gates | `moon run typos` / `moon run machete`; CI gates both |
| [`actionlint`](https://github.com/rhysd/actionlint) | GitHub Actions workflow lint gate | `moon run check-actions`; CI pins its version in the actionlint job |

Git hooks are managed by [lefthook](https://lefthook.dev) (`lefthook.yml`):
`bun install` wires a pre-commit hook that runs `moon run ci`, so a commit
that would fail CI fails at commit time instead.

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
                         NOT a default member; `moon run bundle-app` builds + signs
                         it with the bundled host (see docs/desktop-app.md)
src/packages/core/       Rust library "chromium-bridge-core": MCP server + native-host bridge
src/packages/core/fuzz/  cargo-fuzz workspace: wire parsers + semantic validators
                         (nightly + libFuzzer; see the Fuzzing section below)
src/packages/shared/     contract types / validators / i18n (bun workspace member)
tests/protocol/          e2e.py, adversarial.py, chaos.py - drive the real release binary
tests/browser/           dom_test.ts, ext_test.ts, security_browser_test.ts,
                         integration_e2e.ts, run_all.ts (bun workspace member; isolated Chrome only)
tests/fixtures/          HTML/CSS pages and the probe extension the browser suites load
scripts/                 bun workspace member: gen-ops.ts, check-version.ts, sync-version.ts,
                         check-extension-id.ts, build-repro.ts, fuzz-smoke.ts, lib.ts, ...
src/apps/web/           bun workspace member: minimal Astro site rendering the
                         repo's markdown docs + translations (moon run web:build;
                         not part of `moon run ci`)
```

All tooling scripts are TypeScript run via bun. Scripts whose only consumer
is a GitHub workflow live in `.github/scripts/`; everything with a local
consumer (moon tasks, other scripts) stays in `scripts/`. The fuzz smoke
moved from the former to the latter when it grew a local moon task, which
currently leaves `.github/scripts/` empty. Two scripts
(`scripts/build-repro.ts` and `scripts/fuzz-smoke.ts`) are deliberately
self-contained on node builtins so they run without a `bun install`: the
release workflow builds the binary before installing the workspace, and the
nightly fuzz job never installs it at all.

Rust dependencies are gated by supply-chain review (`cargo vet`, the
`cargo-vet` CI job). Adding or bumping a crate fails CI until the new version
has a recorded decision in `supply-chain/`: run `cargo vet` to see what is
missing, then `cargo vet certify` if you actually reviewed the code, or
`cargo vet add-exemption` to record a deliberate exemption. The initial
baseline exempts the pre-existing tree; the point of the gate is that no new
code enters the build without someone choosing to let it in. The fuzz
workspace (`src/packages/core/fuzz/`) is the one deliberate exception to the
vet gate; the [Fuzzing](#fuzzing) section records that scope decision.

## Common tasks

moon is the canonical command interface: every dev task is a moon task, and
`moon run help` prints the full menu with descriptions (raw JSON:
`moon query tasks`). Unscoped names (`moon run ci`) resolve to the root
project; per-project tasks are `project:task` (`moon run extension:build`).

```sh
moon run build     # build everything (see below)
moon run dev       # dev everything: extension (WXT) + docs site (Astro) + desktop app (tauri)
moon run test      # rust tests (nextest + doctests) + protocol e2e
moon run ci        # THE GATE: the cross-platform CI steps (see below for what CI adds)
moon run release   # pre-release gate: version checks + full ci
moon run install   # build the release binary, then register it (doctor --fix)
moon run lint      # lint everything: clippy -D warnings + biome lint
moon run fmt       # format everything: cargo fmt + biome format
moon run fix       # auto-fix everything: biome check --write + cargo fmt
moon run run-app   # build, sign, verify, then launch the desktop app
```

`moon run build` builds the entire repo in one command: it renders the
icons, typechecks `src/packages/shared`, bundles the extension, builds the
desktop UI and the docs site, typechecks `scripts/`, and runs
`cargo build --workspace`. Use it to prove the whole graph still compiles
after a cross-cutting change.

`moon run ci` runs the cross-platform gate steps - the same list the old
`just ci` ran: rust fmt/clippy/nextest+doctests, typos/machete, TS
typecheck/biome/tests/extension build, protocol e2e, and the contract +
hygiene checks. CI runs more on top: the macOS/Windows rust matrices,
cargo-vet, linux-install, the adversarial/chaos suites, the browser suites,
the web build, and the macOS-only desktop gate.

The root `package.json` scripts are thin aliases that delegate to the
corresponding moon task, so both entry points share one implementation. The
JS-flavored root verbs (`lint`, `format`, `format:check`, `check`, `test`)
delegate to the `*-ts` tasks; `build`, `gen`, and `typecheck` delegate to the
same-named tasks; the repo-wide verbs cover every language at once
(`moon run lint` = clippy + biome lint, `moon run fmt` = cargo fmt + biome
format, `moon run test` = Rust + protocol e2e). Each task body is a plain
command you can also run by hand:

```sh
cargo build --release
cargo nextest run
cargo fmt --check && cargo clippy --all-targets -- -D warnings
uv run --no-project --isolated tests/protocol/e2e.py
bun install
bunx tsc -p src/apps/extension  # one TS project; `moon run typecheck` covers all five
bunx biome ci .                 # lint + format check (biome.json)
bun run --cwd src/apps/extension build
```

The full task menu, by area:

| Area | Tasks |
|------|-------|
| Aggregates | `build`, `test`, `ci`, `release`, `lint`, `fmt`, `fix` |
| Dev loops | `dev`, `dev-app`, `dev-web`, `extension:dev`, `desktop-ui:dev` |
| Rust | `core:fmt-check`, `core:lint`, `test-rust` (= `core:test` + `core:test-doc`), `build-release`, `build-repro`, `typos`, `machete`, `audit`, `fuzz-smoke` |
| TypeScript | `typecheck`, `test-ts` (= `shared:test` + `extension:test`), `lint-ts`, `check-ts`, `fmt-ts`, `fmt-check-ts`, `extension:build`, `desktop-ui:build`, `web:build` |
| Contract codegen | `gen` (= `gen-shared` + `gen-app-types`), `gen-icons`, `check-gen`, `check-gen-app`, `check-envelope`, `check-gen-isolation` |
| Protocol suites | `test-e2e`, `test-adversarial`, `test-chaos`, `check-uv` |
| Browser suites | `test-browser`, `test-integration` (isolated Chrome only; never in `ci`) |
| Desktop app | `bundle-app`, `dmg-app`, `run-app`, `install-app`, `check-app-signing`, `check-app-rust`, `desktop-ui:test` |
| Touch ID runbooks | `touchid-proof`, `touchid-gates` (USER-RUN: raise real Touch ID prompts) |
| Versioning | `sync-version`, `check-version`, `check-extension-id` |
| Repo hygiene | `check-cjk`, `check-typography`, `check-all-green`, `check-toolchain`, `check-hasher`, `check-yaml`, `check-actions`, `check-commit-names` |

## moon: the canonical command interface

Every task has one definition with declared inputs: the repo-wide tasks and
runbooks live in the root `moon.yml`, per-project tasks (`core`, `shared`,
`extension`, `desktop-ui`, `web`) live in a `moon.yml` next to their code,
and CI runs the same tasks (`.github/workflows/ci.yml` calls
`moon run <task>` wherever the step is more than a single thin command).

**Gates are never cached.** The `ci` aggregate, every task reachable from
it, every `check-*` task, the python suites, and the runbook/ceremony tasks
all set `options.cache: false` in their moon.yml: a gate that a cache hit
can satisfy is not a gate, because a wrong hash (moon cannot hash gitignored
inputs like the generated `.wxt/tsconfig.json`, and a mistaken
`hasher.ignorePattern` would silently drop tracked files from every hash)
would let unverified code land. `moon run ci` therefore always executes the
full suite, in the fixed order its `deps` list declares
(`runDepsInParallel: false`). The underlying tools (cargo, tsc, vite, bun)
keep their own incremental caches, so warm reruns stay fast.

What moon still buys beyond one task vocabulary:

```sh
moon run extension:build   # one task, one definition, used by dev + CI
moon run :test             # every project's test task
moon ci                    # affected-only, based on touched files - a LOCAL
                           # convenience for quick iteration, NEVER the gate
```

Two tasks are macOS-shaped: `gen-app-types` and `check-app-rust` compile the
Tauri desktop crate, which needs the platform GUI toolchain (WebKitGTK on
Linux; nothing ships that setup). They refuse with a pointer to
`gen-shared` on a box without it, are not part of `moon run ci`, and CI runs
them in the dedicated macOS `desktop` job.

Cache trust, and the one edge that must never be narrowed: the Rust core is
the canonical cross-process contract (ADR-0028), so the `shared` and
`extension` tasks declare the whole core crate (plus `scripts/gen-ops.ts` and
the cargo manifests) as inputs - the `rust-contract` file group in
`.moon/tasks/all.yml`. That list is deliberately over-broad; a change anywhere
in `src/packages/core` marks the downstream TS tasks affected, because a stale
result on the contract path is the one failure mode this repo cannot accept.
If you edit these task definitions, it is always safe to widen inputs and
never safe to narrow them. Generated and downloaded output (target/, build/,
.wxt/, rendered icons, ...) is kept out of every hash by
`hasher.ignorePatterns` in `.moon/workspace.yml`; if you add a new gitignored
output directory, add it there too (forgetting only over-invalidates, it
cannot go stale), and `moon run check-hasher` (part of the gate) proves no
tracked file matches any pattern. `.moon/cache/` is local state and
gitignored; `rm -rf .moon/cache` is the reset button.

## Toolchain pinning (proto)

`.prototools` pins proto itself, bun, moon, rust, and uv; `proto install`
provisions them all, and CI provisions the same way (the
`moonrepo/setup-toolchain` action, pinned by commit SHA, installs proto +
moon and the jobs `proto install` what they need). Four pins are
necessarily duplicated, and `moon run check-toolchain` (part of the gate and
of CI's version-consistency job) fails if any pair disagrees (for proto and
moon it checks every setup-toolchain invocation in ci.yml individually, and
that each is pinned to a full commit SHA):

- **rust**: `rust-toolchain.toml` is the authoritative pin - rustup, IDEs,
  and CI's `setup-rust-toolchain` read it natively, and it carries the
  components + profile. The `.prototools` entry only pre-installs that
  toolchain.
- **bun**: mirrored in `package.json` `packageManager` (read by `setup-bun`
  in the CI jobs that do not go through proto).
- **proto/moon**: `ci.yml` passes explicit `proto-version` / `moon-version`
  inputs (the action cannot read the proto pin from `.prototools`).

uv is pinned only in `.prototools`, and python is owned by uv exactly as
before: the protocol suites run under the interpreter pinned in
`.python-version` via `uv run --no-project --isolated`. proto deliberately
never provisions python (`settings.builtin-plugins` in `.prototools`).

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

## Fuzzing

`src/packages/core/fuzz/` is its own cargo workspace (cargo-fuzz + libFuzzer,
nightly rust) with ten targets. Five fuzz the wire-frame decoders
(`nm_frame`, `mcp_jsonrpc`, `bridge_envelope`, `handshake`, `attach`); five
fuzz the semantic validators behind them (`handshake_verify`,
`classify_frame`, `enclave_der`, `enclave_challenge`,
`registration_manifest`). Where a correctness property exists, the semantic
targets assert it instead of only checking for panics: the MAC verifier must
accept a correctly computed MAC, the challenge and presence messages must
stay domain-separated, and manifest ownership must answer `Foreign` for
anything not provably ours. (The `handshake_verify` target also drives the
full server handshake over in-memory I/O; the server generates a fresh nonce
per handshake and the response MAC must bind it, so a static fuzzed response
can only exercise the fail-closed rejection path there. The accept path is
covered by the same target's MAC oracle and the socketpair unit tests in
`handshake.rs`.)

The semantic targets reach private functions through the core crate's
`fuzzing` feature: off by default, enabled only by the fuzz workspace, and
consisting of re-exports with no runtime behavior. `--all-features` does
compile it; the isolation argument is that no shipped binary enables the
feature and the fuzz crate lives in a separate workspace, so feature
unification cannot pull it into a real build.

Three directories with different lifecycles:

- `fuzz/seeds/<target>/`: committed, hand-curated starting inputs for the
  byte-input targets (a valid frame per shape, a valid DER signature plus
  truncations, our real manifest plus near-misses). The structured targets
  (`handshake_verify`, `enclave_challenge`) take `Arbitrary`-derived input
  whose encoding is unstable across `arbitrary` versions, so they get no
  committed seeds.
- `fuzz/corpus/<target>/`: gitignored, fuzzer-generated. Nightly CI restores
  and saves it through `actions/cache`, so exploration accumulates across
  runs instead of restarting from zero every night.
- `fuzz/dictionaries/`: token dictionaries handed to libFuzzer
  (`json_protocol.dict` for the JSON-shaped targets, `der.dict` for
  `enclave_der`).

Run it locally:

```sh
moon run fuzz-smoke      # bun scripts/fuzz-smoke.ts: every target, bounded run
```

The smoke needs a nightly toolchain plus `cargo install cargo-fuzz` and
skips with a message when either is missing. It discovers targets from
`cargo +nightly fuzz list`, so the list cannot drift from `fuzz/Cargo.toml`.
Locally each target gets 30 seconds; the nightly `fuzz` job runs the same
script at 120 seconds per target and passes `--cmin`, which minimizes each
corpus before the cache save (cmin bounds the size of each snapshot; the
number of accumulated cache entries is bounded by GitHub's LRU cache
eviction, not by cmin). On a crash the job uploads `fuzz/artifacts/` as a
workflow artifact so the reproducing input outlives the runner. For a real
campaign on one target, `cargo +nightly fuzz run <target>` from
`src/packages/core` runs unbounded.

Deliberately not fuzzed, and why:

- `allowlist.rs`, `revocation.rs`, `ipc/lockfile.rs`: pure
  `serde_json::from_slice` into derived `deny_unknown_fields` structs.
  Fuzzing them would fuzz serde_json, not our code; negative unit tests
  already pin the fail-closed behavior.
- `enclave/pubkey.rs`: `EnclavePublicKey::from_x963` is a length check plus
  a lead-byte check, not point validation. Too trivial to earn a target.
- Broker semantics: owned by loom model checking and
  `tests/protocol/adversarial.py`, which exercise interleavings and hostile
  peers rather than byte parsing.
- Presence signing: Security.framework calls, not a byte parser.
- The TypeScript side (the generated Zod schemas and the hand-written
  envelope asymmetry layer): a scope decision, not a claim that the code is
  many-eyes-reviewed.

Policy: a PR that adds or changes a bespoke parser or semantic validator at
a trust boundary in the Rust core must add or extend a fuzz target, or add
the exclusion, with its reason, to the list above. The exact rule, with its
scoping, lives in
[SECURITY.md](../SECURITY.md#security-relevant-changes-review-bar).

Supply-chain scope: the fuzz workspace sits outside the `cargo vet` gate by
design. It runs in nightly CI only, is never linked into a shipped binary,
and its third-party direct dependencies are limited to `libfuzzer-sys`,
`arbitrary`, and `serde_json` (alongside `chromium-bridge-core` itself, the
crate under test); `derive_arbitrary` comes in transitively through
`arbitrary`'s derive feature. A new fuzz dependency still goes through the
`cargo deny` pass over `fuzz/Cargo.toml` in the security workflow, plus
ordinary PR review.

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
moon run sync-version    # bun scripts/sync-version.ts
# 3. update CHANGELOG.md (move [Unreleased] items under the new version)
# 4. gate on a clean tree
moon run release         # check-version + full ci
# 5. tag - pushing a v* tag triggers .github/workflows/release.yml, which
#    builds macOS Apple Silicon, Linux x64, and Windows x64 archives (binary
#    + built extension) and publishes them to GitHub Releases.
git tag vX.Y.Z && git push --tags
```

CI (`.github/workflows/ci.yml`) enforces version consistency on every push, so
a forgotten `sync-version` fails the build. The release workflow also refuses to
run if the tag doesn't match the Cargo version.
