<!-- BEGIN REPO-PLATFORM MANAGED -->
# AGENTS.md

Guidance for AI coding agents working in this repository. `CLAUDE.md`, `.github/copilot-instructions.md`, and `.github/agents.md` are symlinks to this file, so edit only here.

Everything between the BEGIN and END markers is managed by Vivswan/repo-platform and replaced on every sync. This repository's own guidance goes below the END marker.

## Project

Chromium Bridge: Authenticated MCP bridge to your real Chromium browsers (Brave, Chrome): Rust native-messaging host + MV3 extension, no debug port

## Conventions

- PR titles and commit subjects are Conventional Commits; with the release-please module they drive its versioning. PRs are squash-merged, so the PR title becomes the commit subject; with the pr-title module, its check validates the title.
- CI gates on the `all-green` check, required by the managed ruleset. Under `.github/workflows/`, this repository's test and lint jobs go in `checks.yml`, its green-gated work on main in `post-green.yml` (both repo-owned); `ci.yml` is managed.
- With the release-please module, a green push to main releases through the fleet's release pipeline; this repository's release steps go in the repo-owned `update-release.yml` and `update-release-pr.yml` hooks.
- Plain ASCII punctuation only: no curly quotes, em-dashes, or invisible unicode. The check-typography gate enforces it.

## Managed by repo-platform

- Files whose header says "managed by Vivswan/repo-platform" arrive via sync PRs from that repository. Do not edit them here; change them there.
- Repository settings are rendered into `.github/settings.yml` by Vivswan/repo-platform's sync from its fleet layers plus this repository's own `.github/settings.local.yml`. Edit that file, never the rendered one or the GitHub UI; the merge rules are in repo-platform's docs/settings.md.
- Repo-owned, never overwritten by sync: `checks.yml`, `post-green.yml`, `.gitleaks.toml`, `.gitignore` outside its managed region, `.typography-allow.local`, the release hooks, and the module starters (the release-please JSON files, the `.claude-plugin/` manifests, the nightly workflows).
- Module selection is the `modules` list in `.repo-platform.yml`; the next sync PR applies a change. The per-module contracts are in repo-platform's docs/new-repo.md.
- Fleet-wide conventions: repo-platform's docs/fleet-guidelines.md.

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
