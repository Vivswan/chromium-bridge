# Development guide

This page is the local dev loop, the toolchain, the test and fuzz machinery, and the version copies a release moves. The branch, commit, and merge workflow is [CONTRIBUTING.md](../CONTRIBUTING.md); why the project is shaped as it is lives in [architecture.md](./architecture.md) and [security/rationale.md](./security/rationale.md).

## Prerequisites

[proto](https://moonrepo.dev/proto) is the bootstrap toolchain manager: install it once, put `~/.proto/shims` and `~/.proto/bin` on your PATH, and one `proto install` in a fresh checkout provisions every tool pinned in the repo-root `.prototools` (bun, moon, node, uv).

Rust is rustup's alone, from `rust-toolchain.toml`, so a fresh machine needs [rustup.rs](https://rustup.rs) first. proto deliberately leaves rust to it: proto's rust plugin registers a toolchain that rustup then believes is installed. Then:

```sh
proto install    # provisions bun, moon, node, uv at the pinned versions (rustup owns rust)
moon run setup   # installs the bun workspace, the pinned Rust toolchain, and the crates; wires the git hooks (lefthook); the gate itself never installs
```

Four tools have no first-party proto plugin and are installed once by hand: `cargo install cargo-nextest` (the test runner `moon run gate` uses) and `brew install typos-cli cargo-machete actionlint` (tools only `moon run ci` runs; typos and cargo-machete also come from `cargo install`). Where CI gets them:

- **The `Containerfile` pins all four plus cargo-deb** as `ARG <TOOL>_VERSION`. The CI image carries the four; cargo-deb is installed on the bare release and installer runners alone.
- **A job that installs a tool itself reads the same pin** through `bun scripts/pin.ts <tool>`: checks.yml's tooling job for cargo-machete (inside the image, where that version is already present), `installers.yml` and `update-release.yml` for cargo-deb on their bare runners.
- **typos and actionlint run through the managed ci.yml's fleet actions** at the platform's own pins, so a local skew can at worst surface a finding early.

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

Git hooks are managed by [lefthook](https://lefthook.dev) (`lefthook.yml`): `moon run setup` wires a pre-commit hook that runs `moon run gate`, the checks the repository's own toolchain provides, and `moon run ci` adds the tools only CI provisions.

## Layout

The TypeScript side is one bun workspace rooted at the repo top level (`package.json` `workspaces`), with one `bun.lock` and one node_modules tree. Buildable code lives under `src/` (apps and packages); every directory there is a member of the cargo workspace or the bun workspace, so one gate compiles the whole graph. TS packages keep sources and tests apart (`src/` and `tests/`).

```text
src/apps/host/           Rust binary "chromium-bridge" (thin argv dispatch over the library)
src/apps/extension/      MV3 extension (WXT); builds to build/extension (gitignored)
src/apps/web/            minimal Astro site rendering the repo's markdown docs (bun workspace member;
                         moon run web:build; not part of `moon run ci`)
src/packages/core/       Rust library "chromium-bridge-core": MCP server + native-host bridge
src/packages/core/fuzz/  cargo-fuzz workspace: wire parsers + semantic validators
                         (nightly + libFuzzer; see the Fuzzing section below)
src/packages/shared/     contract types / validators / i18n (bun workspace member)
tests/protocol/          e2e.py, adversarial.py, chaos.py - drive the real release binary
tests/browser/           the browser suites (run_all.ts lists them); integration_e2e.ts and
                         presence_exchange_test.ts run apart (bun workspace member; isolated Chrome only)
tests/interop/           the official MCP SDK client against the release binary (bun workspace member)
tests/harness/           harness-smoke: real harness CLIs in isolated config dirs
tests/fixtures/          HTML/CSS pages and the probe extension the browser suites load
scripts/                 bun workspace member: gen-ops.ts, check-version.ts, check-extension-id.ts,
                         check-docs-literals.ts, check-docs-policy.ts, build-repro.ts,
                         fuzz-smoke.ts, lib.ts, ...; unit tests in scripts/tests/
```

All tooling scripts are TypeScript run via bun and live in `scripts/`, a bun workspace member. A moon `script:` or a workflow `run:` stays a straight line of tool invocations; the moment it needs control flow, output parsing, or error handling, it is a script here with a unit test in `scripts/tests/`.

Two scripts, `scripts/build-repro.ts` and `scripts/fuzz-smoke.ts`, stay self-contained on node builtins so they run without a `bun install`: the release workflow builds the binary before installing the workspace, and the nightly fuzz job never installs it at all.

Dependencies are gated by automated supply-chain checks, with no manual per-crate audit step; the layers and what each catches are in [SECURITY.md](../.github/SECURITY.md#dependency-supply-chain). `moon run audit` reproduces the cargo-deny pass locally.

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

`moon run ci` runs the cross-platform gate steps, in the order its `deps` list declares:

| Step | Tasks |
|------|-------|
| Rust | `core:fmt-check`, `core:lint`, `typos`, `machete`, `core:test`, `core:test-doc`, `core:test-loom`, `doc` |
| TypeScript | `typecheck`, `check-ts`, `shared:test`, `extension:test`, `extension:build` |
| Protocol | `test-e2e` |
| Hygiene | `hygiene` (the bun-side checks below), `check-refresh-lockfiles`, `check-fuzz-workspace`, `test-fuzz` |
| Contract | `check-gen`, `check-envelope`, `check-gen-isolation` |
| Workflows | `check-yaml`, `check-actions` |

CI runs more on top: the macOS and Windows rust matrices, coverage, linux-install, the adversarial and chaos suites, the interop suite, the browser suites, the installers, the web build, and the audits (the [CI layout](#ci-layout) below).

The root `package.json` scripts are thin aliases, so both entry points share one implementation:

| `bun run ...` | moon task |
|------|------|
| `build`, `gen`, `typecheck` | the same-named task |
| `lint`, `format`, `format:check`, `check`, `test` | `lint-ts`, `fmt-ts`, `fmt-check-ts`, `check-ts`, `test-ts` |

The repo-wide verbs cover every language at once: `moon run lint` is clippy plus biome lint, `moon run fmt` is cargo fmt plus biome format, `moon run test` is Rust plus protocol e2e. Each task body is a plain command you can also run by hand:

```sh
cargo build --release
cargo nextest run
cargo fmt --check && cargo clippy --all-targets -- -D warnings
uv run --no-project --isolated tests/protocol/e2e.py
bun install
bun run tsc -p src/apps/extension        # one TS project; `moon run typecheck` covers them all
bun run biome ci . --error-on-warnings   # lint + format check, warnings fail (biome.jsonc)
bun run --cwd src/apps/extension build
```

The full task menu, by area:

| Area | Tasks |
|------|-------|
| Aggregates | `build`, `test`, `ci`, `hygiene` (the bun-side checks CI's hygiene job runs; `ci` depends on it), `release`, `lint`, `fmt`, `fix` |
| Dev loops | `dev`, `dev-web`, `extension:dev` |
| Rust | `core:fmt-check`, `core:lint`, `test-rust` (= `core:test` + `core:test-doc` + `core:test-loom`, the broker ref-count model check under the core's `loom` feature), `doc`, `build-release`, `build-repro`, `typos`, `machete`, `audit` |
| Fuzz workspace | `fuzz-seeds`, `fuzz-smoke`, `check-fuzz-smoke`, `check-fuzz-workspace`, `test-fuzz` |
| TypeScript | `typecheck`, `test-ts` (= `shared:test` + `extension:test` + `web:test` + `check-harness-driver`), `lint-ts`, `check-ts`, `fmt-ts`, `fmt-check-ts`, `extension:build`, `web:build` |
| Contract codegen | `gen` (= `gen-shared`), `gen-icons`, `gen-architecture-map`, `check-gen`, `check-envelope`, `check-gen-isolation` |
| Protocol suites | `test-e2e`, `test-adversarial`, `test-chaos`, `check-uv` |
| Interop suites | `test-interop` (official MCP SDK v2 client against the release binary), `harness-smoke` (real harness CLIs, isolated config dirs; the legacy-era opening-method canary) |
| Browser suites | `test-browser`, `test-integration` (isolated Chrome only; never in `ci`) |
| Versioning | `check-version`, `check-extension-id`, `check-refresh-lockfiles` |
| Repo hygiene (the `hygiene` deps) | `check-version`, `check-extension-id`, `check-toolchain`, `check-pins`, `check-hasher`, `check-moon-edges`, `check-ignored`, `check-cjk`, `check-typography`, `check-fuzz-smoke`, `check-harness-driver`, `check-docs-literals`, `check-docs-policy`, `check-planning-refs`, `check-compose`, `check-ci-scripts`, `check-docs-probe`, `check-architecture`, `check-docs-locales` |
| Workflows | `check-yaml`, `check-actions` |

`check-docs-probe` holds every paragraph and list item of the English docs under 70 words and every path they name real. A translated page (under the `zh-cn` or `zh-tw` docs tree, or the root `README.<locale>.md`) is probed for paths and links only: a whitespace word count does not read CJK, so the English page carries the cap and `check-docs-locales` keeps the translated tree mirroring it file-for-file.

## moon: the canonical command interface

Every task has one definition with declared inputs: the repo-wide tasks and runbooks live in the root `moon.yml`, per-project tasks (`core`, `shared`, `extension`, `web`) live in a `moon.yml` next to their code.

CI runs the same tasks: the repo-owned `.github/workflows/checks.yml` calls `moon run <task>` wherever a task exists for the step. The Rust OS matrix keeps raw cargo verbs, and the `runInCI: false` suites such as `test-interop` are invoked directly, since moon does not resolve them when `CI=true`.

**Gates are never cached.** Every task is uncached by the workspace default (`taskOptions.cache: false` in `.moon/tasks/all.yml`): a gate that a cache hit can satisfy is not a gate, because a wrong hash would let unverified code land. moon cannot hash gitignored inputs like the generated `.wxt/tsconfig.json`, and a mistaken `hasher.ignorePattern` would silently drop tracked files from every hash.

The two tasks that opt back in (`web:build`, `shared:typecheck`) are not gate steps. `moon run ci` therefore always executes the full suite, in the fixed order its `deps` list declares (`runDepsInParallel: false`). The underlying tools (cargo, tsc, vite, bun) keep their own incremental caches, so warm reruns stay fast.

What moon still buys beyond one task vocabulary:

```sh
moon run extension:build   # one task, one definition, used by dev + CI
moon run :test             # every project's test task
moon ci                    # affected-only, based on touched files - a LOCAL
                           # convenience for quick iteration, NEVER the gate
```

**The contract edge is never narrowed.** The Rust core is the canonical cross-process contract, so the `shared` and `extension` tasks declare the whole core crate, every `scripts/gen-*.ts` script, and the cargo manifests as inputs: the `rust-contract` file group in `.moon/tasks/all.yml`.

The list is deliberately over-broad, because a stale result on the contract path is the one failure mode this repo cannot accept. Editing these task definitions, it is always safe to widen inputs and never safe to narrow them.

What stays out of every hash:

- **Generated and downloaded output** (target, build, .wxt, rendered icons, fuzz corpus and artifacts) is listed in `hasher.ignorePatterns` in `.moon/workspace.yml`. A new gitignored output directory goes there too; forgetting only over-invalidates, it cannot go stale.
- **No tracked file may match a pattern:** `moon run check-hasher` (part of the gate) proves it.
- **moon's own state** lives in the gitignored .moon/cache directory; `rm -rf .moon/cache` is the reset button.

## Toolchain pinning (proto)

`.prototools` pins proto itself, bun, moon, node, and uv; `proto install` provisions them all, and rust comes from `rust-toolchain.toml` through rustup alone. CI provisions the same way through one composite action, `.github/actions/setup-moon`, used by every repo-owned job that needs a toolchain:

1. `setup-bun` installs the `.bun-version` bun, only to run the pin reader.
2. `bun scripts/pin.ts proto` reads proto's own version, the one pin `moonrepo/setup-toolchain` cannot read.
3. That action installs proto, and `proto install` provisions the `.prototools` tools (its bun lands on top of the first, so a bare runner carries two).
4. With `cargo: "true"`, `setup-rust-toolchain` installs rust from `rust-toolchain.toml`.

The CI image (`Containerfile`) runs the same `proto install` at build time, with the proto version arriving as its one build arg (`container-image.yml` and `scripts/compose-run.ts` compute it with `bun scripts/pin.ts proto`). Inside it the action finds everything present and only re-runs `proto install`, a no-op unless a pin moved after the image was published.

`bun scripts/pin.ts <tool>` is the one reader of a pin needed before proto exists. It scans both owner files together and fails when a tool is pinned in both, twice, or nowhere; `bun scripts/pin.ts --all` sweeps every pin of both files through the same rule, and `moon run check-pins` (under `hygiene`) runs the sweep and the reader's unit tests:

| Tools | Owner file | Line shape |
|-------|------------|------------|
| proto, bun, moon, node, uv | `.prototools` | `tool = "x.y.z"` |
| cargo-nextest, typos, actionlint, cargo-machete (the image's tools) and cargo-deb (the release and installer runners') | `Containerfile` | `ARG <TOOL>_VERSION=x.y.z` |

One pin also lives in a second file, and `moon run check-toolchain` (part of the gate and of CI's hygiene job) fails if the copies disagree, or if `.prototools` ever pins rust or enables proto's rust or python plugin:

- **bun**: mirrored in `package.json` `packageManager` and the template-managed `.bun-version`.

uv is pinned only in `.prototools`, and python is owned by uv: the protocol suites run under the interpreter pinned in `.python-version` via `uv run --no-project --isolated`. proto deliberately never provisions python (`settings.builtin-plugins` in `.prototools`).

## CI layout

`checks.yml` defines each concern once, called by the managed ci.yml inside the all-green gate. The Linux jobs run inside the published CI image (`ghcr.io/<owner>/<repo>-ci:latest`, built by `container-image.yml` from main).

The workflow-level `CI_IMAGE_TAG` is the one switch: an empty value runs every job on the bare runner with the same composite action.

| Job | Runs | Where |
|-----|------|-------|
| `image` | resolves the image tag to its digest once, so every job pins the same content | bare runner |
| `rust` | clippy and tests on ubuntu, macOS, and Windows; fmt, the loom model, rustdoc, and the fuzz workspace's check and tests on Linux alone | image on Linux, bare elsewhere |
| `build-release` | `moon run build-release`, uploaded for the suites below | bare runner, so the binary links against the runner's older glibc and runs in both environments |
| `coverage` | `cargo llvm-cov`, informational (`continue-on-error`, no threshold) | image |
| `extension` | `typecheck`, `check-ts`, `shared:test`, `extension:test`, `extension:build`, then `check-extension-id` against the built manifest | image |
| `contract` | `check-gen` alone first (it rewrites the generated modules), then `check-envelope`, `check-gen-isolation`, `check-refresh-lockfiles` | image |
| `hygiene` | `moon run hygiene` | image |
| `tooling` | `machete`, with cargo-machete at the `Containerfile` pin | image |
| `web` | `web:build`, `web:test` | image |
| `linux-install` | downloads the `build-release` binary, then `scripts/linux-registration.ts`: `doctor --fix`, re-register, multi-browser, `uninstall` under isolated HOME and XDG directories | bare runner: it needs only that binary and a bun for the scenario driver |
| `protocol` | the `e2e`, `adversarial`, and `chaos` suites against the downloaded binary | image |
| `interop` | the official MCP SDK client against the downloaded binary | image |
| `browser` | the reusable `browser.yml` (input `chrome-version`), which `nightly.yml` calls too | bare runner, Chrome from `setup-chrome` |
| `installers` | `installers.yml` builds the .pkg, .deb, and .msi and installs each on its runner | each platform's runner |
| `audits` | `audits.yml`: cargo deny over the root and fuzz workspaces | bare runner |

## Working on the extension

The extension is built on WXT, which generates the manifest (including the pinned key) and bundles the entrypoints under `src/apps/extension/src/entrypoints/`.

```sh
bun install
bun run --cwd src/apps/extension dev       # WXT dev mode: rebuild on change
bun run --cwd src/apps/extension build     # production bundle
```

Load `build/extension/chrome-mv3` as an unpacked extension in `chrome://extensions` (Developer mode). Unit tests (`bun run --cwd src/apps/extension test`) run on Vitest with `fakeBrowser`, no real browser needed.

## Testing

The protocol suites (`tests/protocol/e2e.py`, `adversarial.py`, `chaos.py`) drive the real release binary as subprocesses over the actual wire protocols, no browser needed: `moon run test-e2e` (in the gate), `test-adversarial`, `test-chaos`.

The browser suites listed in `tests/browser/run_all.ts` share one runner, which CI's `browser.yml`, the container, and `moon run test-browser` all invoke. It builds the extension, runs those suites, then checks that each left its RAN marker. The last row below runs apart:

| Suite | What it proves |
|-------|----------------|
| `dom_test.ts` | every content-script op, with the built content script (content-scripts/content.js under `build/extension/chrome-mv3`) injected into a headless page via CDP |
| `ext_test.ts` | the service worker boots with `build/extension/chrome-mv3` loaded (puppeteer-core); `BB_EXT_DIR` points at another unpacked extension |
| `security_browser_test.ts` | the browser-side half of the security model, against the same loaded extension |
| `webauthn_test.ts` | the facts about Chrome's WebAuthn client the host's verifier assumes, with a CDP virtual authenticator standing in for Touch ID |
| `cancel_test.ts` | a `cancel` frame from a stand-in host is consumed and never answered; not run on Windows |
| `presence_exchange_test.ts` | the WebAuthn exchange end to end: two isolated Chromes against the real release host. Runs apart (`moon run test-presence-exchange`); `suitesFor` in `run_all.ts` says why |

```sh
bun tests/browser/run_all.ts                           # builds the extension, then the suites
CHROME_BIN=/path/to/isolated/chrome bun tests/browser/run_all.ts
```

Without an isolated `CHROME_BIN` the runner skips; the two CI switches that make a skip or a vacuous suite fail are stated once, in the Safety section of [`tests/README.md`](../tests/README.md#-safety---never-point-browser-tests-at-your-daily-chrome). `moon run test-integration` (`tests/browser/integration_e2e.ts`) is the opt-in end-to-end run: the real binary, the isolated Chrome, and the extension together.

## Running the gate and the browser suites in a container

The container is the isolation: it carries every gate tool at the repository's pins plus a distro Chromium, and no browser or process on the host is in its reach. `Containerfile` builds it; `compose.yaml` runs it, within the Compose Specification subset both `docker compose` and `podman compose` implement (`moon run check-compose`, in the gate, holds it there).

| Task | Runs inside the container |
|------|---------------------------|
| `moon run ci-container` | `moon run ci` |
| `moon run test-browser-container` | `xvfb-run -a moon run test-browser` with `BB_REQUIRE_BROWSER=1` and `BB_BROWSER_CANARY_DIR=/work/tmp/browser-canary`, so a skipped or vacuous suite fails as in CI and the RAN markers stay readable on the host |
| `moon run shell-container` | an interactive `bash` at `/work` |

Docker is the default engine; `CONTAINER_ENGINE=podman moon run ci-container` switches. The first run builds the image (minutes, once); the checkout is bind-mounted at `/work`, so a build lands in the gitignored build directory on the host like a native one.

Named volumes keep the Linux artifacts out of the host checkout and make reruns warm; `docker compose down -v` (or `podman compose down -v`) drops them all:

| Volume | Mounted at | Holds |
|--------|------------|-------|
| `cargo-registry` | `/home/ci/.cargo/registry` | downloaded crates |
| `cargo-target` | `/work/target` | the Linux build, hiding the host's target directory |
| `bun-cache` | `/home/ci/.bun/install/cache` | downloaded packages |
| `node-modules` | `/work/node_modules` | the Linux install (the entrypoint runs `bun install --frozen-lockfile`) |
| `moon-cache` | `/work/.moon/cache` | moon state for the container's runs |

Podman rootless maps the host user to container root, so `compose.podman.yaml` adds `userns_mode: keep-id:uid=1000,gid=1000`, mapping the host user onto the image's user instead; the tasks pass that file when `CONTAINER_ENGINE=podman`. Running compose by hand needs the same facts the task supplies (`scripts/compose-run.ts`), the image's one build arg included:

```sh
env UID="$(id -u)" GID="$(id -g)" docker compose build --build-arg "PROTO_VERSION=$(bun scripts/pin.ts proto)" shell
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
| `enclave_challenge` | the host-key challenge-message builder | exactly the documented field matrix is accepted, and an accepted message splits back into its fields |
| `classify_frame` | the control-frame router | a frame's `type` is exactly the tag it was read as |
| `registration_manifest` | the ours/foreign manifest and extension-pointer decisions | anything not provably ours is `Foreign` |
| `policy_doc` | the policy store parse surface | serde round trip, the comparison lattice partitions every pair |
| `webauthn_authdata` | the WebAuthn authenticatorData layout parser, with the attestation object and the assertion verifier fed the same bytes | a credential key parsed from attested data round-trips through its storage spelling |

`handshake_verify` drives the full server handshake over in-memory I/O. The server binds a fresh nonce per handshake, so a static fuzzed response only reaches the fail-closed rejection path there; the accept path is the same target's MAC oracle plus the socketpair unit tests in `handshake.rs`.

The byte-input target bodies live in the crate's library (`fuzz/src/targets.rs`); each `fuzz_targets/<name>.rs` binary wraps one in `fuzz_target!`, and the library's tests run the same bodies in-process over every generated seed on stable rust.

The semantic targets reach private functions through the core crate's `fuzzing` feature: off by default, enabled only by the fuzz workspace, and consisting of re-exports with no runtime behavior. `--all-features` does compile it; the isolation argument is that no shipped binary enables the feature and the fuzz crate lives in a separate workspace, so feature unification cannot pull it into a real build.

Three directories with different lifecycles, plus the failure reports:

- `fuzz/seeds/<target>/`: gitignored, generated by `moon run fuzz-seeds` (`fuzz/src/seeds/`) from the production types before every fuzz pass. The crate's tests hold every seed to its label, so a seed cannot drift from the types it was generated from.
- A happy-path seed goes through the real encoder: the NDJSON and native-messaging writers, the record envelope's `encode`, the tool catalogue's own argument schemas.
- An adversarial seed is a one-step mutation of a happy-path one (an unknown field, a bound plus one, a version above the ladder, a repeated key, truncated base64), labelled with the reader that must refuse it.
- The structured targets (`handshake_verify`, `enclave_challenge`) take `Arbitrary`-derived input whose encoding is unstable across `arbitrary` versions, so they get no seeds; their regressions get unit tests instead.
- `fuzz/corpus/<target>/`: gitignored, fuzzer-generated. Nightly CI restores and saves it through `actions/cache`, so exploration accumulates across runs instead of restarting from zero every night.
- `fuzz/dictionaries/`: the token dictionary handed to libFuzzer. `json_protocol.dict` (every key and string value of the JSON seeds) is generated alongside the seeds and gitignored.
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

- `allowlist.rs`, `trust.rs`, `ipc/lockfile.rs`: pure `serde_json::from_slice` into derived `deny_unknown_fields` structs. Fuzzing them would fuzz serde_json, not our code; negative unit tests already pin the fail-closed behavior.
- `enclave/pubkey.rs`: `EnclavePublicKey::from_x963` is a length check plus a lead-byte check, not point validation. Too trivial to earn a target.
- Broker semantics: owned by loom model checking and `tests/protocol/adversarial.py`, which exercise interleavings and hostile peers rather than byte parsing.
- Presence signing: Security.framework calls, not a byte parser.
- The TypeScript side (the generated Zod schemas and the hand-written envelope asymmetry layer): a scope decision, not a claim that the code is many-eyes-reviewed.

Policy: a PR that adds or changes a bespoke parser or semantic validator at a trust boundary in the Rust core must add or extend a fuzz target, or add the exclusion, with its reason, to the list above. The exact rule, with its scoping, lives in [SECURITY.md](../.github/SECURITY.md#security-relevant-changes-review-bar).

Supply-chain scope: the fuzz workspace runs in nightly CI only, is never linked into a shipped binary, and its third-party direct dependencies are limited to `libfuzzer-sys`, `arbitrary`, and `serde_json` (alongside `chromium-bridge-core` itself, the crate under test); `derive_arbitrary` comes in transitively through `arbitrary`'s derive feature. A new fuzz dependency still goes through the `cargo deny` pass over `fuzz/Cargo.toml` in the audits workflow, plus ordinary PR review.

## Logging

Both binary modes log to **stderr** (stdout carries the wire protocols). Set the level with `BB_LOG`:

```sh
BB_LOG=debug chromium-bridge          # verbose
BB_LOG=error chromium-bridge          # quiet
# default is info
```

## Releasing

Releases are cut by release-please from a green `main`; the pipeline (draft release, packaging matrix, attestation, publish) is [docs/release.md](./release.md). The release PR is the only version bump: its extra-files in `release-please-config.json` rewrite every copy below, and `moon run check-version` fails CI when a copy or the config disagrees, including on the release PR itself.

| Version copy | Who reads it |
|---|---|
| `Cargo.toml` `[workspace.package] version` | the crates, the packaging jobs' tag check |
| `src/apps/extension/package.json` `version` | the WXT-built manifest (`versionedJsonFiles` in `scripts/lib.ts`) |
