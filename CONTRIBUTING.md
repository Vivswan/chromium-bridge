# Contributing to chromium-bridge

Thanks for contributing! This document covers the conventions every change in this repository goes through.

Some files arrive from [Vivswan/repo-platform](https://github.com/Vivswan/repo-platform); `.github/repo-platform-manifest.json` records each one's class, and [AGENTS.md](./AGENTS.md) summarizes the split.

| Class | Meaning | Examples |
|---|---|---|
| `managed` | Replaced on every sync; edit it in the fleet repository | `.github/settings.yml` (rendered from the overlay on every sync) |
| `starter` | Written once; this repository's own | `checks.yml`, the release hooks, `.github/settings.local.yml` |

- Changes land through pull requests and are squash-merged; the PR title becomes the commit subject on `main`. Titles and commit subjects follow the [commit convention](#commit-convention) below.
- By opening a pull request, or offering code in an issue or review for inclusion, you agree to the Contributions section of the [LICENSE.md](./LICENSE.md), which licenses that code to the licensor - including for relicensing under any terms - unless you conspicuously say otherwise when you submit it.
- Never report vulnerabilities in issues or pull requests - see [SECURITY.md](./.github/SECURITY.md) for the private reporting route.
- Participation is governed by the account-wide [code of conduct](https://github.com/Vivswan/.github/blob/main/CODE_OF_CONDUCT.md).

## Before you start

This is a small, security-sensitive project (it drives a real logged-in browser), so changes are held to a high bar for correctness and for preserving the safety model.

- Read [docs/development.md](./docs/development.md) for the dev loop and [docs/architecture.md](./docs/architecture.md) for the design.
- Behavioral or security-model changes state their reason in the PR body and, when they change a load-bearing decision, update its row in [docs/security/rationale.md](./docs/security/rationale.md). Don't quietly weaken a confirmation/allowlist boundary.
- `moon run ci` runs every check locally (see [Workflow](#workflow)) - run it, not individual commands, when you want the verdict before pushing.

## Workflow

`main` is protected - you cannot push to it directly, and development **never** happens on `main`. Every change lives on a branch in its own git worktree, and lands via a squash-merged PR whose gates are green.

1. **Sync + branch in a worktree.** Each change gets its own git worktree under `.worktrees/` (gitignored), branched from the latest `origin/main`. Branch names are `type/branch-name`: `type` is a commit type (see [Commit convention](#commit-convention)), `branch-name` is kebab-case and descriptive (e.g. `feat/capability-handshake`, `fix/reconnect-writer-clobber`):
   ```sh
   git fetch origin
   git worktree add .worktrees/feat/my-change -b feat/my-change origin/main
   cd .worktrees/feat/my-change
   ```
2. Make the change with a matching test where practical.
3. **Stay synced.** Before committing, and again before merging, rebase onto the latest main so history stays linear (no merge commits):
   ```sh
   git pull --rebase origin main
   ```
4. **Commit; the hook checks.** The lefthook hooks (wired by `moon run setup`) run `moon run static`, the static checks (formatting, lint, types, spelling, the YAML and workflow lints, hygiene), before a commit and after a rebase; a refused commit's message names the fix task. The test suites and builds run in CI on every pull request; `moon run ci` runs everything locally, and `moon run help` lists every task:
   ```sh
   moon run ci        # rust fmt/clippy/nextest + typos/machete + TS typecheck/biome/test/build + protocol e2e
   ```
   - The gate is uncached by design (the workspace task default; [docs/development.md](./docs/development.md#moon-the-canonical-command-interface) says why), so it always runs the full suite. `moon ci` (affected-only) is a local convenience, never the gate.
   - Browser tests (`moon run test-browser`) are not part of `moon run ci`. They run **only** against an isolated Chrome for Testing via `CHROME_BIN`, never your daily Chrome (see Safety below and [tests/README.md](./tests/README.md)).
   - CI runs them in checks.yml's `browser` job (inside the all-green gate) against an isolated Chrome. Runtime-behavior changes (reconnect, handshake, service worker) must still be verified there manually.
5. **Open a PR and squash-merge.** Push the branch, open a PR against `main`, wait for **all required checks green**, then **squash-merge** (one change = one commit on `main`):
   ```sh
   git push -u origin feat/my-change
   gh pr create --base main
   gh pr merge --squash        # after review + green checks
   ```
   Humans review, approve, and merge - automation never self-approves or self-merges.
6. Clean up: `git worktree remove .worktrees/feat/my-change && git branch -d feat/my-change`.

## Commit convention

Commits follow [Conventional Commits](https://www.conventionalcommits.org): `type(scope): subject`.

- Allowed `type`: `build` `chore` `ci` `docs` `feat` `fix` `perf` `refactor` `revert` `style` `test`. This is the fleet-wide list; CI enforces it on the PR title (the `pr-title` check) and on every commit subject in the push/PR range (the fleet's validate-commit-names action).
- Prefer the most precise type over `chore`: dependency bumps -> `build`, workflow changes -> `ci`, documentation -> `docs`.
- `scope` is optional and names the area (`core`, `extension`, `options`, `cli`, `gen`, `ci`, ...).
- `subject` is a declarative sentence: what the change does once it lands, not an instruction. `the pre-commit gate runs the repository's own toolchain and installs nothing`, not `run the gate with the repo toolchain`.
- The two checks above hold the subject's grammar: lower-case start, no trailing period, one scope.
- The *why* goes in the body, and one commit carries one logical change.

## Safety (non-negotiable)

This project drives a real logged-in browser, and a past incident nearly took down a machine.

- **Never** run `pkill` / `killall` / any pattern process-kill. Only `kill` a specific PID you started and verified.
- **Never** point browser tests at a browser that could capture your real session. Use an isolated Chrome for Testing / Chromium via `CHROME_BIN`.
- Anything that would affect a process or window you didn't start yourself: stop and ask first.

## Code style

- **Rust** - `cargo fmt` (enforced by `cargo fmt --check`) and `cargo clippy` with `-D warnings`.
  - Cargo workspace: `src/packages/core` (the `chromium-bridge-core` library), and `src/apps/host` (the `chromium-bridge` binary).
  - Errors on the tool-call path use the typed `CallError` (`src/packages/core/src/error.rs`).
  - Log via the `log_*!` macros (`src/packages/core/src/log.rs`), never bare `eprintln!` for diagnostics. **stdout is protocol** - all logging goes to stderr.
- **TypeScript** - Biome lints and formats every TS/JS/JSON file in the bun workspace (`moon run check-ts` to check, `moon run fix` to auto-fix; config in `biome.jsonc`).
  - `noExplicitAny` is enforced in extension source; test files and the tests/ harness are exempt until their CDP plumbing gets real types.
- **Shared schemas** - the cross-boundary TS shapes (settings, envelopes, runtime messages) live as Zod schemas in `src/packages/shared`; the types are inferred from them and the extension parses untrusted input against them at runtime. Don't reintroduce a hand-written duplicate type next to a schema - extend the schema.

## Adding a tool

A new tool touches both sides ([docs/architecture.md](./docs/architecture.md) section 10):

1. **Add it to the Rust catalogue**: one `catalogue!` row in [`src/packages/core/src/tools/catalogue.rs`](src/packages/core/src/tools/catalogue.rs) (name, variant, args struct, risk, permission, confirmation, grants, dispatch with its capability, description) plus a typed args struct in [`src/packages/core/src/tools/args.rs`](src/packages/core/src/tools/args.rs), whose field docs become the schema descriptions. The row is the only table: the `BridgeCommand` variant, the `ToolId` index, the `Tool` record, and the capability roster derive from it.
2. **The TS side follows on its own**: every task that reads it (`typecheck`, the tests, the extension build) rebuilds `src/packages/shared/generated` from the Rust core first; `moon run gen` rebuilds it alone.
   - A new arg that widens the envelope's args bag is picked up automatically.
   - A new envelope FIELD is a protocol change: see `BridgeReq` in `src/packages/core/src/protocol.rs` and the envelope parity gate, `moon run check-envelope`.
3. **Give the op a home in the extension.** The roster test and the exhaustive switches fail until the partition is complete:
   - a service-worker op: `SW_OPS` + a `dispatchSw` case in `src/apps/extension/src/lib/background/dispatch.ts`;
   - a page op: `PAGE_OPS` (`src/apps/extension/src/lib/shared/page-ops.ts`) + cases in `src/apps/extension/src/lib/content/handle.ts` and `src/apps/extension/src/lib/background/backends/cdp.ts`;
   - its UI label: `tools.<op>` in `src/apps/extension/src/locales/*.yml`; the key-parity test fails until every locale has it.
4. Give it a risk row in the [tool risk matrix](docs/security/tool-risk-matrix.md).
5. Extend `tests/protocol/e2e.py` (and `dom_test.ts` for DOM ops).

## Versioning

Versions are bumped only by the rolling release PR; the copies and the gate are in [Releasing](./docs/development.md#releasing).

## License

By contributing you agree your contributions are licensed under the [Individual and Small Organization License 1.0.0](./LICENSE.md).
