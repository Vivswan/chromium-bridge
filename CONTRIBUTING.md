# Contributing to chromium-bridge

Thanks for your interest. This is a small, security-sensitive project (it drives
a real logged-in browser), so changes are held to a high bar for correctness and
for preserving the safety model.

## Before you start

- Read [docs/development.md](./docs/development.md) for the dev loop and
  [docs/architecture.md](./docs/architecture.md) for the design.
- Behavioral or security-model changes should reference (or add) an
  [ADR](./docs/adr/). Don't quietly weaken a confirmation/allowlist boundary.

## Workflow

`main` is protected - you cannot push to it directly, and development **never**
happens on `main`. Every change lives on a branch in its own git worktree, and
lands via a squash-merged PR whose gates are green.

1. **Sync + branch in a worktree.** Each change gets its own git worktree under
   `.worktree/` (gitignored), on a branch named `type/branch-name` - `type` is a
   commit type (see [Commit convention](#commit-convention)) and `branch-name`
   is kebab-case and descriptive (e.g. `feat/capability-handshake`,
   `fix/reconnect-writer-clobber`). Always branch from the latest `origin/main`:
   ```sh
   git fetch origin
   git worktree add .worktree/feat/my-change -b feat/my-change origin/main
   cd .worktree/feat/my-change
   ```
2. Make the change with a matching test where practical.
3. **Stay synced.** Before committing, and again before merging, rebase onto the
   latest main so history stays linear (no merge commits):
   ```sh
   git pull --rebase origin main
   ```
4. **Gate locally - everything must pass** (`just` lists all recipes; the
   lefthook pre-commit hook, wired by `bun install`, runs this for you):
   ```sh
   just ci            # rust fmt/clippy/nextest + typos/machete + TS typecheck/biome/test/build + protocol e2e
   ```
   Browser tests (`just test-browser`) run **only** against an isolated Chrome
   for Testing via `CHROME_BIN`, never your daily Chrome (see Safety below and
   [tests/README.md](./tests/README.md)). They are not in the required gate;
   runtime-behavior changes (reconnect, handshake, service worker) must be
   verified there manually.
5. **Open a PR and squash-merge.** Push the branch, open a PR against `main`,
   wait for **all required checks green**, then **squash-merge** (one change =
   one commit on `main`):
   ```sh
   git push -u origin feat/my-change
   gh pr create --base main
   gh pr merge --squash        # after review + green checks
   ```
   Humans review, approve, and merge - automation never self-approves or
   self-merges.
6. Clean up: `git worktree remove .worktree/feat/my-change && git branch -d feat/my-change`.

## Commit convention

Commits follow [Conventional Commits](https://www.conventionalcommits.org):
`type(scope): subject`.

- Allowed `type`: `feat` `fix` `docs` `refactor` `perf` `test` `ci` `build`
  `style` `revert`. **`chore` is not allowed** - every change maps to a more
  precise type (dependency bumps → `build`/`ci`, misc scripts → `build`,
  documentation → `docs`).
- `scope` is optional (`session`, `tools`, `error`, `ci`, `ext`, ...).
- `subject` is imperative, present tense, lower-case, no trailing period; explain
  the *why* in the body. One logical change per commit.

## Safety (non-negotiable)

This project drives a real logged-in browser, and a past incident nearly took
down a machine. Never run `pkill` / `killall` / any pattern process-kill - only
`kill` a specific PID you started and verified. Never point browser tests at a
browser that could capture your real session - use an isolated Chrome for
Testing / Chromium via `CHROME_BIN`. Anything that would affect a process or
window you didn't start yourself: stop and ask first.

## Code style

- **Rust** - `cargo fmt` (enforced by `cargo fmt --check`) and `cargo clippy`
  with `-D warnings`. The code lives in a Cargo workspace: `crates/core` (the
  `chromium-bridge-core` library) and `crates/host` (the `chromium-bridge`
  binary). Errors on the tool-call path use the typed `CallError`
  (`crates/core/src/error.rs`); log via the `log_*!` macros
  (`crates/core/src/log.rs`), never bare `eprintln!` for diagnostics.
  Remember: **stdout is protocol** - all logging goes to stderr.
- **TypeScript** - Biome lints and formats every TS/JS/JSON file in the bun
  workspace (`bunx biome ci .` to check, `just fix-ts` to auto-fix; config in
  `biome.json`). `noExplicitAny` is enforced in extension source; test files
  and the tests/ harness are exempt until their CDP plumbing gets real types.
- The cross-boundary TS shapes (settings, envelopes, runtime messages) live as
  Zod schemas in `packages/shared`; the types are inferred from them and the
  extension parses untrusted input against them at runtime. Don't reintroduce
  a hand-written duplicate type next to a schema - extend the schema.

## Adding a tool

A new tool touches both sides (see architecture.md §10):

1. **Add it to [`contracts/tools.json`](contracts/tools.json)** - the single
   source for the catalogue (name, description, uiLabel, risk, scope,
   permission, confirmation, inputSchema). Run `just gen` to regenerate
   `packages/shared/src/ops.gen.ts`, and bump the count in
   `tool_count_is_pinned`. A new arg name must also be mirrored into
   `bridge-request.schema.json`'s `OpArgs`, and the tool needs a home in
   `capabilities.json` - the packages/shared tests point at whichever of
   these you miss.
2. Add the matching `Tool` definition (`crates/core/src/tools/catalogue.rs`)
   and a `HANDLERS` registry entry + `build_*` payload fn
   (`crates/core/src/tools/handlers.rs`). The `matches_contract` and
   `registry_covers_catalogue` tests (`cargo test`) enforce parity with the
   contract.
3. Give the op a home in the extension: `SW_OPS` + a `dispatchSw` case in
   `extension/src/background/dispatch.ts`, or `PAGE_OPS`
   (`extension/src/shared/page-ops.ts`) + cases in `content/handle.ts` and
   `backends/cdp.ts`. The roster test and the exhaustive switches fail until
   the partition is complete.
4. Give it a risk row in the [tool risk matrix](docs/security/tool-risk-matrix.md).
5. Extend `tests/e2e.py` (and `dom_test.ts` for DOM ops).

## Versioning

`Cargo.toml` is the source of truth. Bump it, run `just sync-version`, and update
`CHANGELOG.md`. CI fails if the crate and extension versions drift.

## License

By contributing you agree your contributions are licensed under
[Apache-2.0](./LICENSE).
