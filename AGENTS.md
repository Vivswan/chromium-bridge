# AGENTS.md

This file provides guidance to AI coding agents working in this repository.
`CLAUDE.md`, `.github/copilot-instructions.md`, and `.github/agents.md` are
symlinks to this file, so edit only here.

## Project

Chromium Bridge: Authenticated MCP bridge to your real Chromium browsers (Brave, Chrome): Rust native-messaging host + MV3 extension, no debug port

## Toolchain

- Runtime and package manager: bun (`bun install`, `bun test`, `bun run <script>`)
- See `package.json` scripts for the available commands.

## Conventions

- PR titles and commit subjects must be Conventional Commits (`feat:`, `fix:`,
  `feat!:`, `chore:`, ...). PRs are squash-merged, so the PR title becomes the
  commit subject and drives release-please versioning. CI validates both
  (pr-title workflow + validate-commit-names).
- CI gates on a single required check named `all-green`, which `needs:` every
  other job in `.github/workflows/ci.yml`. When adding a CI job, add it to
  all-green's `needs` list.
- No typographic look-alike characters (curly quotes, em-dashes, invisible
  unicode). CI enforces this with the check-typography action; use plain ASCII
  punctuation.
- Files marked "managed by Vivswan/repo-platform" are updated by
  template sync PRs. Put repository-specific content in `.gitignore`'s marked
  LOCAL section or below this line in this file.

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
label `com.vivswan.chromium-bridge.enclave.signing.v1`. Upstream fixes are
manual ports now, not clean merges; `LICENSE` and git history keep the
upstream name.

**The full development process is [`CONTRIBUTING.md`](./CONTRIBUTING.md) - it
is authoritative; this file only summarizes.**

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
just ci        # rust fmt/clippy/nextest + typos/machete + TS typecheck/biome/test/build + protocol e2e
```

The justfile is the canonical command interface: `just --list` shows every
task, the root `package.json` scripts are thin aliases delegating to just,
and the per-workspace `package.json` scripts are implementation details the
justfile and CI call.
Individually: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo nextest run`; `just typecheck`, `bunx biome ci .`,
`bun run --cwd src/packages/shared test`, `bun run --cwd src/apps/extension test`;
`bun scripts/gen-ops.ts` (must leave no diff); `bun scripts/check-extension-id.ts`.
A lefthook pre-commit hook runs `just ci` automatically (`bun install` wires
it). Browser suites (`just test-browser`) need `CHROME_BIN` -> isolated Chrome
and are **not** part of `just ci`; CI runs them in the required `browser` job
against its own isolated Chrome.

### Project map

| Area | Where | Notes |
|------|-------|-------|
| Dev process | [`CONTRIBUTING.md`](./CONTRIBUTING.md) | branch/commit/sync/merge rules (authoritative) |
| Build & test toolchain | [`docs/development.md`](./docs/development.md) | prerequisites, `just` recipes, releasing |
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
  capabilities, protocol version, and identity generate the TS side
  (`just gen` -> `src/packages/shared/src/*.gen.ts`, with Zod validators the
  extension enforces at its trust boundaries; CI fails on a stale diff), and
  the hand-written Zod envelope validators are checked against the Rust
  wire types by the double-derivation diff (`just check-envelope`):
  structural equivalence, modulo a short list of deliberate, individually
  asserted parser asymmetries. Adding a
  tool touches both sides - see `CONTRIBUTING.md`.
- Never develop on `main`; work in a git worktree under `.worktree/` on a
  `type/branch-name` branch, rebase on `origin/main`, land via squash-merge
  PR. Security-critical surfaces (`src/packages/core/src/ipc/`,
  `src/packages/core/src/protocol.rs`, `broker.rs`, `allowlist.rs`,
  `revocation.rs`, `kill.rs`, `presence/`, `enclave/`, `registration.rs`,
  the extension's allowlist/eval/confirmation code,
  `src/apps/extension/wxt.config.ts`) deserve extra review care - see
  `SECURITY.md`.
- `upstream` remote is `whg517/browser-bridge`. The rebrand (ADR-0023) ended
  the keep-mergeable-with-upstream policy: port upstream fixes manually and
  by judgment, do not shape our changes around a clean `git merge`.

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
  with fuzzing and adversarial tests. `deny.toml` and supply-chain review gate
  every new dependency; the bar is well-vetted, not few.
