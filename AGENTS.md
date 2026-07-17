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
and the safety model come first. Internal identifiers (crate name, binary
name, `com.browser_bridge.host`) intentionally keep the upstream
`browser-bridge` naming to stay mergeable with upstream.

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
make ci        # rust fmt/clippy/test + extension typecheck/lint/format + protocol e2e + version/gen consistency
```

Individually: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`; `npm --prefix extension run typecheck|lint|format:check`,
`npm --prefix extension test`; `node scripts/gen-ops.mjs` (must leave no diff).
Browser suites (`make test-browser`) need `CHROME_BIN` -> isolated Chrome and
are **not** part of the required gate.

### Project map

| Area | Where | Notes |
|------|-------|-------|
| Dev process | [`CONTRIBUTING.md`](./CONTRIBUTING.md) | branch/commit/sync/merge rules (authoritative) |
| Build & test toolchain | [`docs/development.md`](./docs/development.md) | prerequisites, `make` targets, releasing |
| Architecture | [`docs/architecture.md`](./docs/architecture.md) | components, protocols, security model |
| Cross-process contracts | [`contracts/`](./contracts/README.md) | tools, error codes, capabilities, protocol version, envelopes - single source of truth |
| Operations / CLI | [`docs/operations.md`](./docs/operations.md), [`docs/cli.md`](./docs/cli.md) | `doctor`/`status`, `BB_LOG`/audit |
| Tests & browser safety | [`tests/README.md`](./tests/README.md) | suites + the `CHROME_BIN` isolation rule |

### Conventions worth knowing

- **stdout is protocol** in both binary modes - all diagnostics go to stderr
  via the `log_*!` macros (`src/log.rs`), never bare `eprintln!`.
- Tool-call errors use the typed `CallError` (`src/error.rs`), mapped to the
  stable codes in [`contracts/errors.json`](./contracts/errors.json).
- The tool catalogue is generated from [`contracts/tools.json`](./contracts/tools.json)
  (`make gen` -> `extension/src/shared/ops.ts`); Rust parity is enforced by
  `cargo test`. Adding a tool touches both sides - see `CONTRIBUTING.md`.
- Never develop on `main`; work in a git worktree under `.worktree/` on a
  `type/branch-name` branch, rebase on `origin/main`, land via squash-merge
  PR. Security-critical surfaces (`src/ipc.rs`, `src/protocol.rs`, allowlist,
  eval/toast content scripts, `extension/manifest.json`, `install/`) deserve
  extra review care - see `SECURITY.md`.
- `upstream` remote is `whg517/browser-bridge`; prefer changes that stay
  mergeable with upstream.

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
