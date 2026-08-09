# AGENTS.md

This file provides guidance to AI coding agents working in this repository.
`CLAUDE.md`, `.github/copilot-instructions.md`, and `.github/agents.md` are
symlinks to this file, so edit only here.

## Project

Chromium Bridge: Authenticated MCP bridge to your real Chromium browsers (Brave, Chrome): Rust native-messaging host + MV3 extension, no debug port

## Toolchain

- Runtime and package manager: bun (`bun install`, `bun test`, `bun run <script>`)
- See `package.json` scripts for the available commands.
- Rust managed with cargo (`cargo build`, `cargo test`, `cargo clippy`)
- See `Cargo.toml` for the workspace/crate layout and dependencies.
- In THIS repository, moon wraps both toolchains as the canonical command
  interface (`moon run <task>`) - see "Toolchain specifics" under
  Repository-specific guidance below before reaching for raw commands.

## Conventions

- PR titles and commit subjects must be Conventional Commits (`feat:`, `fix:`,
  `feat!:`, `chore:`, ...). PRs are squash-merged, so the PR title becomes the
  commit subject and drives release-please versioning. CI validates both
  (the ci.yml pr-title job + validate-commit-names).
- CI gates on a single required check named `all-green` in the managed
  `.github/workflows/ci.yml`. This repository's own test/lint jobs belong in
  `.github/workflows/checks.yml` (repo-owned, called inside the gate); do not
  edit ci.yml, template sync overwrites it. The `release` job runs on top
  of the gate (`needs: all-green`); the release pipeline is repo-owned in
  `.github/workflows/release.yml` (pre/post-release jobs go there, around the
  managed release-please machinery).
- No typographic look-alike characters (curly quotes, em-dashes, invisible
  unicode). CI enforces this with the check-typography action; use plain ASCII
  punctuation.

## Managed by repo-platform

- Files whose header says "managed by Vivswan/repo-platform"
  arrive via sync PRs pushed by that repository. Do not edit them here;
  change them in Vivswan/repo-platform and let the next sync
  PR deliver the update.
- Repository settings (description, topics, labels, rulesets, merge policy)
  are applied from Vivswan/repo-platform: by the
  `settings/repos/` file named after this repository over there when one
  exists, otherwise by this repository's own `.github/settings.yml`. Do not
  change settings by hand in the GitHub UI; edit the settings file.
- Repo-owned escape hatches stay local: `.github/workflows/checks.yml` and
  `.github/workflows/release.yml`, `.gitignore`'s marked LOCAL section,
  `.typography-allow.local` (typography exemptions; the managed
  `.typography-allow` is overwritten by sync), and the repository-specific
  section below.
- Module selection is this repository's own: edit the `modules` list in
  `.repo-platform.yml` and the next sync PR applies the change.

## Repository-specific guidance

<!-- Add project-specific instructions below. This section survives template
     updates via three-way merge. -->

Chromium Bridge (adopted from `whg517/browser-bridge`, Apache-2.0) is a Rust
MCP server + native-messaging host + MV3 extension that lets an MCP client
drive the user's real Chromium browser (Brave, Chrome). This is small,
security-sensitive software: it acts in a logged-in browser, so correctness
and the safety model come first. Identifiers are OUR OWN (a deliberate
divergence from upstream, ADR-0023): crate/binary `chromium-bridge`,
native-messaging host id `com.vivswan.chromium_bridge.host`, enclave keychain
label `com.vivswan.chromium-bridge.enclave.signing.v1`. No `upstream` remote
is configured, and the rebrand ended the keep-mergeable-with-upstream policy:
port upstream fixes manually and by judgment, never shape our changes around
a clean `git merge`. `LICENSE` and git history keep the upstream name.

**The full development process is [`CONTRIBUTING.md`](./CONTRIBUTING.md) - it
is authoritative; this file only summarizes.**

### Toolchain specifics

- Bootstrap: [proto](https://moonrepo.dev/proto) provisions every pinned
  tool from `.prototools` (bun, moon, rust pre-install, uv) - one
  `proto install` in a fresh checkout. uv keeps owning python
  (`.python-version`); cargo-nextest, typos, cargo-machete, and actionlint
  are separate one-time installs (docs/development.md).
- Task runner: [moon](https://moonrepo.dev) is the canonical command
  interface. `moon run <task>` runs a task; `moon run help` (or
  `moon query tasks`) lists them all. See `docs/development.md`.
- Scripts used ONLY by GitHub Actions live in `.github/scripts/`. `scripts/`
  holds local and dual-use tooling: everything moon tasks or developers run,
  even if CI also calls it (e.g. `scripts/fuzz-smoke.ts`, run by both
  `moon run fuzz-smoke` and the nightly fuzz job).
  `scripts/check-typography.ts` is the local mirror of the platform's
  check-typography action, run by `moon run ci` (its tests ride in
  checks.yml's `cjk` job).

### Safety red lines (a past incident nearly crashed a machine)

- **Never** run `pkill` / `killall` / any pattern-matched process kill. Only
  `kill` a specific PID you started and verified.
- **Never** run browser tests against a browser that could capture the user's
  real session. Browser tests use an **isolated Chrome for Testing / Chromium**
  via `CHROME_BIN` only. Do not launch the user's daily Chrome or Brave.
- Anything affecting a process or window you did not start yourself -> **stop
  and ask**.
- Runtime-behavior changes (reconnect, capability handshake, service-worker
  logic) can only be *fully* verified in an isolated browser - flag that
  verification gap; don't claim it's done from static checks alone.

### Gates

```sh
moon run ci    # rust fmt/clippy/nextest + typos/machete + TS typecheck/biome/test/build + protocol e2e
```

moon is the canonical command interface: every task lives in a `moon.yml`
(the repo-wide tasks and runbooks in the root `moon.yml`, per-project tasks
next to their code), `moon run help` lists them all with descriptions, the
root `package.json` scripts are thin aliases delegating to moon, and the
per-workspace `package.json` scripts are implementation details the moon
tasks and CI call. The gate and every check task set `cache: false` - a gate
must never be skippable by a cache hit - so `moon run ci` always executes
the full suite in a fixed order; affected-only runs (`moon ci`) are a local
convenience only.
Individually: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo nextest run`; `moon run typecheck`, `bunx biome ci .`,
`bun run --cwd src/packages/shared test`, `bun run --cwd src/apps/extension test`;
`bun scripts/gen-ops.ts` (must leave no diff); `bun scripts/check-extension-id.ts`.
A lefthook pre-commit hook runs `moon run ci` automatically (`bun install`
wires it; moon itself comes from `proto install`). Browser suites
(`moon run test-browser`) need `CHROME_BIN` -> isolated Chrome and are
**not** part of `moon run ci`; CI runs them in checks.yml's `browser` job
(inside the all-green gate) against its own isolated Chrome.

### Project map

| Area | Where | Notes |
|------|-------|-------|
| Dev process | [`CONTRIBUTING.md`](./CONTRIBUTING.md) | branch/commit/sync/merge rules (authoritative) |
| Build & test toolchain | [`docs/development.md`](./docs/development.md) | prerequisites, moon tasks, releasing |
| Architecture | [`docs/architecture.md`](./docs/architecture.md) | components, protocols, security model |
| Cross-process contracts | [`docs/architecture.md` section 11](./docs/architecture.md#11-protocol-boundary-contracts-error-taxonomy-and-handshake) | the Rust core is the single source (ADR-0028); tools, error codes, capabilities, protocol version, envelopes |
| Operations / CLI | [`docs/operations.md`](./docs/operations.md), [`docs/cli.md`](./docs/cli.md) | `doctor`/`status`, `BB_LOG`/audit |
| Tests & browser safety | [`tests/README.md`](./tests/README.md) | suites + the `CHROME_BIN` isolation rule |

### Conventions worth knowing

- **stdout is protocol** in both binary modes - all diagnostics go to stderr
  via the `log_*!` macros (`src/packages/core/src/log.rs`), never bare `eprintln!`.
- Tool-call errors use the typed `CallError` (`src/packages/core/src/error.rs`), mapped to the
  stable codes in `ERROR_SPECS` (same file, the canonical taxonomy).
- The Rust core is the canonical cross-process contract (ADR-0028): the tool
  catalogue (`src/packages/core/src/tools/catalogue.rs`), error taxonomy,
  capabilities, protocol version, identity, and wire envelopes generate the
  TS side (`moon run gen` -> `src/packages/shared/src/*.gen.ts`, with Zod
  validators the extension enforces at its trust boundaries; CI fails on a
  stale diff). The enforced envelope validators wrap the generated wire
  schemas (`envelope-wire.gen.ts`, emitted at gen time by the in-repo
  emitter in `scripts/gen-envelope.ts`) with
  a hand-written layer of deliberate, individually pinned parser
  asymmetries, held to exactly that list by the asymmetry gate
  (`moon run check-envelope`). Adding a
  tool touches both sides - see `CONTRIBUTING.md`.
- Never develop on `main`; work in a git worktree under `.worktrees/` on a
  `type/branch-name` branch, rebase on `origin/main`, land via squash-merge
  PR. Security-critical surfaces (`src/packages/core/src/ipc/`,
  `src/packages/core/src/protocol.rs`, `broker.rs`, `allowlist.rs`,
  `revocation.rs`, `kill.rs`, `presence/`, `enclave/`, `registration.rs`,
  the extension's allowlist/eval/confirmation code,
  `src/apps/extension/wxt.config.ts`) deserve extra review care - see
  `SECURITY.md`.

### Security principle: zero trust (the browser is a critical asset)

The user's real, logged-in browser is a critical security boundary: it holds
live sessions, cookies, and the ability to act as the user. Treat every change
here under standard cyber-security principles.

- **Trust no party by default - including ourselves.** Do not trust the MCP
  client, the model, other local processes, the installer, the browser, or any
  other component of this software just because it is "ours." A component is
  trusted only for what an unforgeable mechanism proves it is.
- **Enforce every trust boundary with a mechanism, never an assumption.** Use
  kernel-attested peer identity (peer-UID / peer-PID -> on-disk binary hash or
  code signature), constant-time cryptographic checks, and OS-enforced file
  permissions. A self-reported identity, a value that is merely "hard to
  guess," or "no other process would do that" is not enforcement.
- **Assume any same-user process may be hostile.** Design so that driving the
  browser requires proof of identity, not mere presence on the machine or the
  ability to read a file. The stated goal is a Codex-level non-abuse
  guarantee: another program you are running must not be able to use this
  bridge silently.
- **Fail closed.** On any ambiguity, missing credential, failed attestation, or
  unexpected peer, refuse and log to stderr - never proceed degraded.
- **Never weaken a check for convenience.** Do not add a flag, default, env
  var, or grace window that bypasses a security gate without an explicit,
  reviewed decision recorded in `SECURITY.md` / an ADR. Confirmations the user
  sees in the browser are a feature, not friction to optimize away.
- **Name the residual risk honestly.** Where a boundary cannot be fully
  enforced in user space, say so in the threat model rather than implying it is
  covered.

Two refinements bound where that rigor is spent (decided with the 2026-07
rebuild plan, ADR-0023):

- **Zero trust is for the security boundary, not all tooling.** The
  enforcement core (attestation, handshake, allowlist, enclave, the wire
  parsers) gets the full treatment above. UI code, build tooling, and dev
  dependencies carry no security weight - enforcement never lives there - so
  relying on heavily-adopted, community-audited libraries and tools there is
  the right trust boundary, not a violation of it. Do not burn review budget
  re-auditing React or esbuild; spend it on `src/packages/core`.
- **Prefer many-eyes libraries over homegrown code, even in the security
  core.** A widely-used, audited crate (RustCrypto `hmac`/`sha2`, `subtle`,
  `serde`) has had more hostile review than anything we write ourselves.
  Bespoke code is reserved for what genuinely has no library - kernel-attested
  peer identity, our IPC and native-messaging protocol - and is compensated
  with fuzzing and adversarial tests. Automated gates - `deny.toml`
  (cargo-deny), cargo-audit, the managed ci.yml's PR-time dependency
  review job, and Dependabot (ADR-0035) - screen every new dependency; the
  bar is well-vetted, not few.
