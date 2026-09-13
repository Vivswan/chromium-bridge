<!-- BEGIN REPO-PLATFORM MANAGED -->
# AGENTS.md

Guidance for AI coding agents in this repository. `CLAUDE.md`, `.github/copilot-instructions.md`, and `.github/agents.md` are symlinks to this file, so edit only here.

Everything between the BEGIN and END markers is managed by the platform and replaced on every sync. This repository's own guidance goes below the END marker.

## Project

Chromium Bridge: Authenticated MCP bridge to your real Chromium browsers (Brave, Chrome): Rust native-messaging host + MV3 extension, no debug port

## Conventions

- PR titles and commit subjects are Conventional Commits; PRs are squash-merged, so the PR title becomes the commit subject.
- CI gates on the `all-green` check. This repository's own jobs go in the repo-owned `checks.yml` (tests, lint) and `post-green.yml` (green-gated work on main); `ci.yml` is managed.
- Plain ASCII punctuation only; the check-typography gate enforces it.

## Managed by the platform

- A file whose header says "managed by Vivswan/repo-platform" arrives by sync PR. Change it there, never here.
- Repository settings come from `.github/settings.local.yml` (this repository's own) merged with the fleet layers into the rendered `.github/settings.yml`. Edit the local file, never the rendered one or the GitHub UI.
- Module selection is the `modules` list in `.repo-platform.yml`; the next sync applies a change. Contracts: the platform's docs/new-repo.md and docs/fleet-guidelines.md.

## Toolchain

- bun: `bun install`, `bun test`, `bun run <script>` (scripts in `package.json`)
- `.bun-version` is managed by sync; pin another version in a repo-owned workflow's version input, not in the dotfile.
- Rust with cargo: `cargo build`, `cargo test`, `cargo clippy` (crate layout and dependencies in `Cargo.toml`)

## Repository-specific guidance

<!-- Add project-specific instructions below the END marker; they are this repository's own and survive every sync. -->
<!-- END REPO-PLATFORM MANAGED -->

- Chromium Bridge is a Rust MCP server, native-messaging host, and MV3 extension that drives the user's real, logged-in Chromium browser. Correctness and the safety model come first.
- Adopted from `whg517/browser-bridge` (Apache-2.0; attribution in `LICENSE-APACHE` and `NOTICE`). The identifiers are our own, not upstream's (ADR-0023); there is no upstream remote, so upstream fixes are ported by judgment.
- `CONTRIBUTING.md` is the authoritative development process. moon is the command interface: `moon run help` lists the tasks, `moon run ci` is the gate.

### Safety red lines

- Never `pkill`, `killall`, or any pattern-matched kill. Only `kill` a PID you started and verified.
- Browser tests run only against an isolated Chrome for Testing via `CHROME_BIN`, never a browser that holds the user's session.
- Anything that touches a process or window you did not start: stop and ask.
- Runtime-behavior changes (reconnect, handshake, service worker) are verified only in an isolated browser; say so when that has not happened.

### Decisions to keep

- stdout is protocol in both binary modes; diagnostics go to stderr (`src/packages/core/src/log.rs`).
- The Rust core is the single cross-process contract and generates the TypeScript side (ADR-0028); never hand-edit a `*.gen.ts`.
- Never develop on `main`: one branch per change, landed by squash-merge PR. The surfaces that get extra security review are listed in `.github/SECURITY.md`.

### Security principle: zero trust

- Trust no party by default, our own components included; enforce every boundary with a mechanism, never an assumption.
- Fail closed. No flag, default, env var, or grace window bypasses a gate without a reviewed decision in `.github/SECURITY.md` or an ADR. Confirmations the user sees are a feature.
- Name residual risk honestly in the threat model.
- Rigor goes to the enforcement core (`src/packages/core`); elsewhere rely on well-adopted libraries. Prefer audited crates over homegrown code even in the core (ADR-0035).

### Pointers

| Area | Where |
|------|-------|
| Toolchain and releasing | `docs/development.md` |
| Architecture and cross-process contracts | `docs/architecture.md` |
| Operations and CLI | `docs/operations.md`, `docs/cli.md` |
| Tests and browser safety | `tests/README.md` |
| Security model and review bar | `.github/SECURITY.md` |
