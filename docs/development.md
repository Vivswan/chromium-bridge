# Development guide

This document covers the local dev loop, the build/test toolchain, and the release process. For the **branch / commit / sync / merge workflow** (worktrees, Conventional Commits, rebase, squash-merge, gates), see [`../CONTRIBUTING.md`](../CONTRIBUTING.md). For *why* the project is structured the way it is, see [architecture.md](./architecture.md) and [security/rationale.md](./security/rationale.md).

## Prerequisites

[proto](https://moonrepo.dev/proto) is the bootstrap toolchain manager: one `proto install` in a fresh checkout provisions every tool pinned in the repo-root `.prototools` (bun, moon, node, uv); rust is rustup's alone, from `rust-toolchain.toml`. Install proto once and make sure `~/.proto/shims` and `~/.proto/bin` are on your PATH.

One prerequisite proto does not cover: `rustup` itself must already be installed (proto deliberately leaves rust to it: proto's rust plugin registers a toolchain rustup then believes is installed), so a truly fresh machine needs [rustup.rs](https://rustup.rs) first. Then:

```sh
proto install    # provisions bun, moon, node, uv at the pinned versions (rustup owns rust)
bun install      # workspace deps + wires the git hooks (lefthook)
```

Four gate tools have no first-party proto plugin and are installed once by hand: `cargo install cargo-nextest` and `brew install typos-cli cargo-machete actionlint` (typos and cargo-machete can also come from `cargo install`). CI pins cargo-machete in checks.yml; typos and actionlint run through the managed ci.yml's fleet actions, which follow the platform's own pins (a template-sync decision), so a local version skew can at worst surface a finding early.

| Tool | Used for | Notes |
|------|----------|-------|
| [proto](https://moonrepo.dev/proto) | toolchain bootstrap | provisions everything pinned in `.prototools`, locally and in CI (`.github/actions/setup-moon`); the one pin that also lives elsewhere (bun) is cross-checked by `moon run check-toolchain` |
| [moon](https://moonrepo.dev) | task runner | the canonical command interface: every dev task is a moon task. `moon run help` lists them; `moon run <task>` runs one |
| Rust (cargo) | the `chromium-bridge` binary | pinned by `rust-toolchain.toml` (the authoritative pin; rustup and IDEs read it); `rustfmt` + `clippy` components, `cargo-nextest` as the test runner |
| bun | everything TypeScript | package manager, script runner, extension bundling, TS test suites. Pinned in `.prototools` (and mirrored in `package.json` `packageManager`) |
| node | the vitest suites (`extension:test`, `web:test`) | pinned only in `.prototools`; proto provisions it, so no job or image installs its own |
| [`uv`](https://docs.astral.sh/uv/) | protocol e2e tests | provisions the exact Python pinned in the repo-root `.python-version`, so local runs and CI use the same interpreter. uv itself is pinned only in `.prototools`. The suites are stdlib-only |
| Chrome | DOM + smoke tests | `CHROME_BIN` overrides the path |
| [`typos`](https://github.com/crate-ci/typos) + [`cargo-machete`](https://github.com/bnjbvr/cargo-machete) | spelling + unused-dependency gates | `moon run typos` / `moon run machete`; CI gates typos in the managed ci.yml and machete in checks.yml |
| [`actionlint`](https://github.com/rhysd/actionlint) | GitHub Actions workflow lint gate | `moon run check-actions`; CI runs it in the managed ci.yml's actionlint job |

Git hooks are managed by [lefthook](https://lefthook.dev) (`lefthook.yml`): `bun install` wires a pre-commit hook that runs `moon run ci`, so a commit that would fail CI fails at commit time instead.

## Layout

The TypeScript side is a bun workspace rooted at the repo top level (`package.json` `workspaces`), sharing one `bun.lock` and one `node_modules/`. Buildable code lives under `src/` (apps and packages); every directory there is a member of either the cargo workspace or the bun workspace, so one gate compiles the whole graph. TS packages keep sources and tests in separate folders (`src/` and `tests/`).

```
src/apps/host/           Rust binary "chromium-bridge" (thin argv dispatch over the library)
src/apps/extension/      MV3 extension (WXT); builds to build/extension/ (gitignored)
src/packages/core/       Rust library "chromium-bridge-core": MCP server + native-host bridge
src/packages/core/fuzz/  cargo-fuzz workspace: wire parsers + semantic validators
                         (nightly + libFuzzer; see the Fuzzing section below)
src/packages/shared/     contract types / validators / i18n (bun workspace member)
tests/protocol/          e2e.py, adversarial.py, chaos.py - drive the real release binary
tests/browser/           dom_test.ts, ext_test.ts, security_browser_test.ts,
                         integration_e2e.ts, run_all.ts (bun workspace member; isolated Chrome only)
tests/fixtures/          HTML/CSS pages and the probe extension the browser suites load
scripts/                 bun workspace member: gen-ops.ts, check-version.ts, sync-version.ts,
                         check-extension-id.ts, check-docs-literals.ts, check-docs-policy.ts,
                         build-repro.ts, fuzz-smoke.ts, lib.ts, ...
src/apps/web/           bun workspace member: minimal Astro site rendering the
                         repo's markdown docs + translations (moon run web:build;
                         not part of `moon run ci`)
```

All tooling scripts are TypeScript run via bun. Scripts whose only consumer is a GitHub workflow live in `.github/scripts/`; everything with a local consumer (moon tasks, other scripts) stays in `scripts/`. The fuzz smoke moved from the former to the latter when it grew a local moon task, which currently leaves `.github/scripts/` empty. Two scripts (`scripts/build-repro.ts` and `scripts/fuzz-smoke.ts`) are deliberately self-contained on node builtins so they run without a `bun install`: the release workflow builds the binary before installing the workspace, and the nightly fuzz job never installs it at all.

Rust dependencies are gated by automated supply-chain checks: `cargo deny` (license allow-list, banned sources, RUSTSEC advisories) runs in every CI gate and again in the nightly rerun, the managed ci.yml's fleet Trivy step gates `Cargo.lock` and `bun.lock` at HIGH/CRITICAL, PRs additionally get the GitHub dependency-review action (an advisory diff, via the platform-managed job in the managed ci.yml), and Dependabot watches cargo, bun, and GitHub Actions. Adding or bumping a crate fails CI on a known advisory or a license outside `deny.toml`'s allow list; there is no manual per-crate audit step. Run `moon run audit` to reproduce the cargo-deny pass locally.

## Common tasks

moon is the canonical command interface: every dev task is a moon task, and `moon run help` prints the full menu with descriptions (raw JSON: `moon query tasks`). Unscoped names (`moon run ci`) resolve to the root project; per-project tasks are `project:task` (`moon run extension:build`).

```sh
moon run build     # build everything (see below)
moon run dev       # dev everything: extension (WXT) + docs site (Astro) + a dev browser
moon run test      # rust tests (nextest + doctests) + protocol e2e
moon run ci        # THE GATE: the cross-platform CI steps (see below for what CI adds)
moon run release   # pre-release gate: version checks + full ci
moon run install   # build the release binary, then register it (doctor --fix)
moon run lint      # lint everything: clippy -D warnings + biome lint
moon run fmt       # format everything: cargo fmt + biome format
moon run fix       # auto-fix everything: biome check --write + cargo fmt
```

`moon run build` builds the entire repo in one command: it typechecks `src/packages/shared`, bundles the extension (rendering its icons first), builds the docs site, typechecks `scripts/`, and runs `cargo build --workspace`. Use it to prove the whole graph still compiles after a cross-cutting change.

`moon run ci` runs the cross-platform gate steps - the same list the old `just ci` ran: rust fmt/clippy/nextest+doctests, typos/machete, TS typecheck/biome/tests/extension build, protocol e2e, and the contract + hygiene checks. CI runs more on top: the macOS/Windows rust matrices, dependency review, linux-install, the adversarial/chaos suites, the browser suites, and the web build.

The root `package.json` scripts are thin aliases that delegate to the corresponding moon task, so both entry points share one implementation. The JS-flavored root verbs (`lint`, `format`, `format:check`, `check`, `test`) delegate to the `*-ts` tasks; `build`, `gen`, and `typecheck` delegate to the same-named tasks; the repo-wide verbs cover every language at once (`moon run lint` = clippy + biome lint, `moon run fmt` = cargo fmt + biome format, `moon run test` = Rust + protocol e2e). Each task body is a plain command you can also run by hand:

```sh
cargo build --release
cargo nextest run
cargo fmt --check && cargo clippy --all-targets -- -D warnings
uv run --no-project --isolated tests/protocol/e2e.py
bun install
bunx tsc -p src/apps/extension  # one TS project; `moon run typecheck` covers them all
bunx biome ci .                 # lint + format check (biome.json)
bun run --cwd src/apps/extension build
```

The full task menu, by area:

| Area | Tasks |
|------|-------|
| Aggregates | `build`, `test`, `ci`, `release`, `lint`, `fmt`, `fix` |
| Dev loops | `dev`, `dev-web`, `extension:dev` |
| Rust | `core:fmt-check`, `core:lint`, `test-rust` (= `core:test` + `core:test-doc`), `build-release`, `build-repro`, `typos`, `machete`, `audit`, `fuzz-smoke` |
| TypeScript | `typecheck`, `test-ts` (= `shared:test` + `extension:test` + `web:test`), `lint-ts`, `check-ts`, `fmt-ts`, `fmt-check-ts`, `extension:build`, `web:build` |
| Contract codegen | `gen` (= `gen-shared`), `gen-icons`, `check-gen`, `check-envelope`, `check-gen-isolation` |
| Protocol suites | `test-e2e`, `test-adversarial`, `test-chaos`, `check-uv` |
| Interop suites | `test-interop` (official MCP SDK v2 client against the release binary), `harness-smoke` (real harness CLIs, isolated config dirs; the legacy-era opening-method canary) |
| Browser suites | `test-browser`, `test-integration` (isolated Chrome only; never in `ci`) |
| Touch ID runbooks | `touchid-proof`, `touchid-gates` (USER-RUN: raise real Touch ID prompts) |
| Versioning | `sync-version`, `check-version`, `check-extension-id` |
| Repo hygiene | `check-cjk`, `check-typography`, `check-fuzz-smoke`, `check-toolchain`, `check-hasher`, `check-ignored`, `check-yaml`, `check-actions`, `check-docs-literals`, `check-docs-policy` |

## moon: the canonical command interface

Every task has one definition with declared inputs: the repo-wide tasks and runbooks live in the root `moon.yml`, per-project tasks (`core`, `shared`, `extension`, `web`) live in a `moon.yml` next to their code.

CI runs the same tasks: the repo-owned `.github/workflows/checks.yml` calls `moon run <task>` wherever a task exists for the step. The Rust OS matrix keeps raw cargo verbs, and the `runInCI: false` suites such as `test-interop` are invoked directly, since moon does not resolve them when `CI=true`.

**Gates are never cached.** Every task is uncached by the workspace default (`taskOptions.cache: false` in `.moon/tasks/all.yml`): a gate that a cache hit can satisfy is not a gate, because a wrong hash would let unverified code land, and moon cannot hash gitignored inputs like the generated `.wxt/tsconfig.json`, while a mistaken `hasher.ignorePattern` would silently drop tracked files from every hash.

The two tasks that opt back in (`web:build`, `shared:typecheck`) are not gate steps. `moon run ci` therefore always executes the full suite, in the fixed order its `deps` list declares (`runDepsInParallel: false`). The underlying tools (cargo, tsc, vite, bun) keep their own incremental caches, so warm reruns stay fast.

What moon still buys beyond one task vocabulary:

```sh
moon run extension:build   # one task, one definition, used by dev + CI
moon run :test             # every project's test task
moon ci                    # affected-only, based on touched files - a LOCAL
                           # convenience for quick iteration, NEVER the gate
```

Cache trust, and the one edge that must never be narrowed: the Rust core is the canonical cross-process contract, so the `shared` and `extension` tasks declare the whole core crate (plus `scripts/gen-ops.ts` and the cargo manifests) as inputs - the `rust-contract` file group in `.moon/tasks/all.yml`. That list is deliberately over-broad; a change anywhere in `src/packages/core` marks the downstream TS tasks affected, because a stale result on the contract path is the one failure mode this repo cannot accept. If you edit these task definitions, it is always safe to widen inputs and never safe to narrow them. Generated and downloaded output (target/, build/, .wxt/, rendered icons, ...) is kept out of every hash by `hasher.ignorePatterns` in `.moon/workspace.yml`; if you add a new gitignored output directory, add it there too (forgetting only over-invalidates, it cannot go stale), and `moon run check-hasher` (part of the gate) proves no tracked file matches any pattern. `.moon/cache/` is local state and gitignored; `rm -rf .moon/cache` is the reset button.

## Toolchain pinning (proto)

`.prototools` pins proto itself, bun, moon, node, and uv; `proto install` provisions them all, and rust comes from `rust-toolchain.toml` through rustup alone. CI provisions the same way through one composite action, `.github/actions/setup-moon`, used by every repo-owned job that needs a toolchain: it parses proto's own version from `.prototools` (the one pin `moonrepo/setup-toolchain` cannot read), lets that action install proto, runs `proto install`, and on request installs rust with `setup-rust-toolchain`.

The CI image (`Containerfile`) runs the same `proto install` at build time. Inside it the action finds everything present and only re-runs `proto install`, a no-op unless a pin moved after the image was published.

One pin also lives in a second file, and `moon run check-toolchain` (part of the gate and of CI's hygiene job) fails if the copies disagree, or if `.prototools` ever pins rust or enables proto's rust or python plugin:

- **bun**: mirrored in `package.json` `packageManager` and the template-managed `.bun-version`.

uv is pinned only in `.prototools`, and python is owned by uv exactly as before: the protocol suites run under the interpreter pinned in `.python-version` via `uv run --no-project --isolated`. proto deliberately never provisions python (`settings.builtin-plugins` in `.prototools`).

## CI layout

`checks.yml` defines each concern once: a Rust OS matrix (ubuntu, macOS, Windows), one `build-release` job whose binary the protocol matrix (`e2e`, `adversarial`, `chaos`), `interop`, and `linux-install` download as an artifact, and the browser suites through the reusable `browser.yml` (input `chrome-version`), which `nightly.yml` calls too.

The Linux jobs run inside the published CI image (`ghcr.io/<owner>/<repo>-ci:latest`, built by `container-image.yml` from main); the workflow-level `CI_IMAGE_TAG` is the one switch, and an empty value runs every job on the bare runner with the same composite action.

Four jobs stay on the bare runner regardless: `build-release` (so the binary links against the runner's older glibc and runs in both environments), `linux-install` (needs only that binary), the browser job (Chrome from `setup-chrome`), and, until the republished image carries iproute2 for `ss`, the protocol matrix.

## Working on the extension

The extension is built on WXT, which generates the manifest (including the pinned key) and bundles the entrypoints under `src/apps/extension/src/entrypoints/`.

```sh
bun install
bun run --cwd src/apps/extension dev       # WXT dev mode: rebuild on change
bun run --cwd src/apps/extension build     # production bundle
```

Load `build/extension/chrome-mv3` as an unpacked extension in `chrome://extensions` (Developer mode). Unit tests (`bun run --cwd src/apps/extension test`) run on Vitest with `fakeBrowser`, no real browser needed.

## Testing

The protocol suites (`tests/protocol/e2e.py`, `adversarial.py`, `chaos.py`) drive the real release binary as subprocesses over the actual wire protocols, no browser needed: `moon run test-e2e` (in the gate), `test-adversarial`, `test-chaos`. The three browser suites share one runner, `tests/browser/run_all.ts`, which CI's `browser.yml`, the container, and `moon run test-browser` all invoke:

- **DOM** (`tests/browser/dom_test.ts`, bun) - injects the built content script (`build/extension/chrome-mv3/content-scripts/content.js`) into a headless Chrome page via CDP and exercises every content-script op.
- **Smoke** (`tests/browser/ext_test.ts`, bun + puppeteer-core) - launches Chrome with `build/extension/chrome-mv3` loaded and checks the service worker boots. Set `BB_EXT_DIR` to point at a different unpacked extension.
- **Security proofs** (`tests/browser/security_browser_test.ts`) - the browser-side half of the security model, against the same loaded extension.

```sh
bun tests/browser/run_all.ts                           # builds the extension, then the three suites
CHROME_BIN=/path/to/isolated/chrome bun tests/browser/run_all.ts
```

Without an isolated `CHROME_BIN` the runner skips; the two CI switches that make a skip or a vacuous suite fail are stated once, in the Safety section of [`tests/README.md`](../tests/README.md#-safety---never-point-browser-tests-at-your-daily-chrome).

## Running the gate and the browser suites in a container

The container is the isolation: it carries every gate tool at the repository's pins plus a distro Chromium, and no browser or process on the host is in its reach. `Containerfile` builds it; `compose.yaml` runs it, within the Compose Specification subset both `docker compose` and `podman compose` implement (`moon run check-compose`, in the gate, holds it there).

| Task | Runs inside the container |
|------|---------------------------|
| `moon run ci-container` | `moon run ci` |
| `moon run test-browser-container` | `xvfb-run -a moon run test-browser` (`scripts/container-browser-suites.sh`) with `BB_REQUIRE_BROWSER=1` and `BB_BROWSER_CANARY_DIR=/work/tmp/browser-canary`, so a skipped or vacuous suite fails as in CI and the RAN markers stay readable on the host |
| `moon run shell-container` | an interactive `bash` at `/work` |

Docker is the default engine; `CONTAINER_ENGINE=podman moon run ci-container` switches. The first run builds the image (minutes, once); the checkout is bind-mounted at `/work`, so a build lands in the gitignored `build/` on the host like a native one.

```text
$ moon run test-browser-container
...
dom_test: 79 passed, 0 failed
ext_test: 20 passed, 0 failed
security_browser_test: 14 passed, 0 failed
```

Named volumes keep the Linux artifacts out of the host checkout and make reruns warm; `docker compose down -v` (or `podman compose down -v`) drops them all:

| Volume | Mounted at | Holds |
|--------|------------|-------|
| `cargo-registry` | `/home/ci/.cargo/registry` | downloaded crates |
| `cargo-target` | `/work/target` | the Linux build, hiding the host's `target/` |
| `bun-cache` | `/home/ci/.bun/install/cache` | downloaded packages |
| `node-modules` | `/work/node_modules` | the Linux install (the entrypoint runs `bun install --frozen-lockfile`) |
| `moon-cache` | `/work/.moon/cache` | moon state for the container's runs |

Podman rootless maps the host user to container root, so `compose.podman.yaml` adds `userns_mode: keep-id:uid=1000,gid=1000`, mapping the host user onto the image's user instead; the tasks pass that file when `CONTAINER_ENGINE=podman`. Running compose by hand needs the same facts the task supplies (`scripts/compose-run.ts`):

```sh
env UID="$(id -u)" GID="$(id -g)" docker compose run --rm shell
# from a linked worktree, use the launcher instead: bun scripts/compose-run.ts shell
```

The isolation guard's container exception is stated once, in the Safety section of [`tests/README.md`](../tests/README.md#-safety---never-point-browser-tests-at-your-daily-chrome).

## Fuzzing

`src/packages/core/fuzz/` is its own cargo workspace (cargo-fuzz + libFuzzer, nightly rust) with eleven targets. Where a correctness property exists, a target asserts it instead of only checking for panics.

| Targets | What they fuzz | Oracle beyond no-panic |
|---------|----------------|------------------------|
| `nm_frame`, `mcp_jsonrpc`, `handshake`, `attach` | the wire-frame decoders | decode -> encode -> decode is identity |
| `bridge_envelope` | the internal bridge envelope reader, as a raw value and as both typed frames | none (reject-or-decode, three times) |
| `handshake_verify` | the MAC verifier and the server accept path | a correctly computed MAC verifies |
| `enclave_challenge` | the challenge-message builders | enrollment and presence messages stay domain-separated |
| `classify_frame` | the control-frame router | a frame's `type` is exactly the tag it was read as |
| `enclave_der` | the strict-DER signature parser | none (reject-or-decode) |
| `registration_manifest` | the ours/foreign manifest decision | anything not provably ours is `Foreign` |
| `policy_doc` | the policy store parse surface | serde round trip, the comparison lattice partitions every pair |

`handshake_verify` drives the full server handshake over in-memory I/O. The server binds a fresh nonce per handshake, so a static fuzzed response only reaches the fail-closed rejection path there; the accept path is the same target's MAC oracle plus the socketpair unit tests in `handshake.rs`.

The byte-input target bodies live in the crate's library (`fuzz/src/targets.rs`); each `fuzz_targets/<name>.rs` binary wraps one in `fuzz_target!`, and the library's tests run the same bodies in-process over every generated seed on stable rust.

The semantic targets reach private functions through the core crate's `fuzzing` feature: off by default, enabled only by the fuzz workspace, and consisting of re-exports with no runtime behavior. `--all-features` does compile it; the isolation argument is that no shipped binary enables the feature and the fuzz crate lives in a separate workspace, so feature unification cannot pull it into a real build.

Three directories with different lifecycles, plus the failure reports:

- `fuzz/seeds/<target>/`: gitignored, generated by `moon run fuzz-seeds` (`fuzz/src/seeds/`) from the production types before every fuzz pass. The crate's tests hold every seed to its label, so a seed cannot drift from the types it was generated from.
- A happy-path seed goes through the real encoder: the NDJSON and native-messaging writers, the record envelope's `encode`, the tool catalogue's own argument schemas.
- An adversarial seed is a one-step mutation of a happy-path one (an unknown field, a bound plus one, a version above the ladder, a repeated key, truncated base64), labelled with the reader that must refuse it.
- The structured targets (`handshake_verify`, `enclave_challenge`) take `Arbitrary`-derived input whose encoding is unstable across `arbitrary` versions, so they get no seeds; their regressions get unit tests instead.
- `fuzz/corpus/<target>/`: gitignored, fuzzer-generated. Nightly CI restores and saves it through `actions/cache`, so exploration accumulates across runs instead of restarting from zero every night.
- `fuzz/dictionaries/`: token dictionaries handed to libFuzzer. `json_protocol.dict` (every key and string value of the JSON seeds) is generated alongside the seeds and gitignored; `der.dict` for `enclave_der` is hand-written DER grammar atoms and tracked.
- `fuzz/failures/<target>/`: gitignored, cleared and rewritten by each `fuzz-smoke.ts` run. One directory per crashed target holding a `report.md` (replay command, seed, a base64 embed of small inputs, the pinning instruction) plus a copy of the crash input, following the fleet's failure-report contract (the fleet repository's docs/fuzzer.md). The nightly job's issue-filing action consumes these.

Run it locally:

```sh
moon run fuzz-seeds        # regenerate fuzz/seeds/ and the JSON dictionary (fuzz-smoke runs this first)
moon run fuzz-smoke        # bun scripts/fuzz-smoke.ts: every target, bounded run
moon run test-fuzz         # every generated seed through its target in-process (in the ci gate)
moon run check-fuzz-smoke  # unit tests for the driver itself (in the ci gate)
```

The smoke needs a nightly toolchain plus `cargo install cargo-fuzz`, and skips with a message when either is missing. The nightly job passes `--require-toolchain`, which turns that skip into a failure: a skipped night must not read as green and auto-close the tracking issue.

- Targets come from `cargo +nightly fuzz list`, so the list cannot drift from `fuzz/Cargo.toml`.
- With the toolchain present, a checkout without the generated seeds or dictionary is refused with the task to run (`moon run fuzz-seeds`), so a bare `bun scripts/fuzz-smoke.ts` on a fresh clone exits 1 instead of fuzzing without the corpus.
- A crashing target does not abort the pass: the script writes that target's failure report, moves on, and exits 1 at the end when anything failed.
- `--seed=N` pins libFuzzer's PRNG for a best-effort deterministic re-run; the crash input file stays the real reproducer, since the persisted corpus differs from night to night.
- Locally each target gets 30 seconds. The nightly run gives 120 seconds per target and passes `--cmin`, which minimizes each passing target's corpus before the cache save (cmin bounds each snapshot's size; GitHub's LRU cache eviction bounds the number of snapshots).
- For a real campaign on one target, `cargo +nightly fuzz run <target>` from `src/packages/core` runs unbounded.

The nightly job lives in `.github/workflows/nightly-fuzz.yml`, this repository's instance of the fleet's fuzzer-module starter. Browser and mutation testing stay in `nightly.yml`, which files the same lifecycle under its own `nightly-failure` label with no failure artifacts, so its issue points at the run log.

- Red night: uploads `fuzz/artifacts/` and `fuzz/failures/` as the `fuzz-failures-<attempt>` artifact, files or updates the `fuzz-nightly` tracking issue from the reports, and dispatches auto-assign at it.
- Green night: closes the open issue.
- `workflow_dispatch` takes `seed` and `iterations`, so any night's configuration can be re-run on demand.

When a crash is filed:

1. Replay it with the command in the issue (download the artifact, or decode the embedded base64).
2. Fix the bug.
3. Pin the input as a labelled seed in the generator (`fuzz/src/seeds/`: the mutation that produced it, with the reader that must refuse it) or, for the two structured targets, as a unit test, and commit it with the fix. The pin is what makes the next green night's auto-close evidence rather than luck.

Deliberately not fuzzed, and why:

- `allowlist.rs`, `revocation.rs`, `ipc/lockfile.rs`: pure `serde_json::from_slice` into derived `deny_unknown_fields` structs. Fuzzing them would fuzz serde_json, not our code; negative unit tests already pin the fail-closed behavior.
- `enclave/pubkey.rs`: `EnclavePublicKey::from_x963` is a length check plus a lead-byte check, not point validation. Too trivial to earn a target.
- Broker semantics: owned by loom model checking and `tests/protocol/adversarial.py`, which exercise interleavings and hostile peers rather than byte parsing.
- Presence signing: Security.framework calls, not a byte parser.
- The TypeScript side (the generated Zod schemas and the hand-written envelope asymmetry layer): a scope decision, not a claim that the code is many-eyes-reviewed.

Policy: a PR that adds or changes a bespoke parser or semantic validator at a trust boundary in the Rust core must add or extend a fuzz target, or add the exclusion, with its reason, to the list above. The exact rule, with its scoping, lives in [SECURITY.md](../.github/SECURITY.md#security-relevant-changes-review-bar).

Supply-chain scope: the fuzz workspace runs in nightly CI only, is never linked into a shipped binary, and its third-party direct dependencies are limited to `libfuzzer-sys`, `arbitrary`, and `serde_json` (alongside `chromium-bridge-core` itself, the crate under test); `derive_arbitrary` comes in transitively through `arbitrary`'s derive feature. A new fuzz dependency still goes through the `cargo deny` pass over `fuzz/Cargo.toml` in the security workflow, plus ordinary PR review.

## Logging

Both binary modes log to **stderr** (stdout carries the wire protocols). Set the level with `BB_LOG`:

```sh
BB_LOG=debug chromium-bridge          # verbose
BB_LOG=error chromium-bridge          # quiet
# default is info
```

## Releasing

Releases are cut by release-please: conventional commits on `main` accumulate into a rolling release PR that bumps the version and writes `CHANGELOG.md`; merging it tags the release, and the same CI run builds the macOS Apple Silicon, Linux x64, and Windows x64 archives (binary + built extension), and publishes them to GitHub Releases (see [docs/release.md](./release.md)). The bump covers `Cargo.toml` and every synced JSON manifest (`versionedJsonFiles` in `scripts/lib.ts`: the extension `package.json`), per release-please-config.json's extra-files.

`Cargo.toml` stays the single source of truth between releases: after a manual version change, `moon run sync-version` (`bun scripts/sync-version.ts`) propagates it to the synced JSON manifests (the extension `package.json`, which the WXT-built manifest reads its version from), and CI enforces the consistency on every push (`moon run check-version`), so drift fails the build - including on the release PR itself. Each packaging job additionally refuses to run if the tag doesn't match the Cargo version.
