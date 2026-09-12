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
- Behavioral or security-model changes should reference (or add) an [ADR](./docs/adr/). Don't quietly weaken a confirmation/allowlist boundary.
- The local gate is `moon run ci` (see [Workflow](#workflow)) - run it, not individual commands, before pushing.

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
4. **Gate locally - everything must pass.** The lefthook pre-commit hook (wired by `bun install`) runs this for you; `moon run help` lists every task:
   ```sh
   moon run ci        # rust fmt/clippy/nextest + typos/machete + TS typecheck/biome/test/build + protocol e2e
   ```
   - The gate is uncached by design (every step sets `cache: false` in its moon.yml), so it always runs the full suite. `moon ci` (affected-only) is a local convenience, never the gate.
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
- `scope` is optional (`session`, `tools`, `error`, `ci`, `ext`, ...).
- `subject` is imperative, present tense, lower-case, no trailing period; explain the *why* in the body. One logical change per commit.

## Safety (non-negotiable)

This project drives a real logged-in browser, and a past incident nearly took down a machine.

- **Never** run `pkill` / `killall` / any pattern process-kill. Only `kill` a specific PID you started and verified.
- **Never** point browser tests at a browser that could capture your real session. Use an isolated Chrome for Testing / Chromium via `CHROME_BIN`.
- Anything that would affect a process or window you didn't start yourself: stop and ask first.

## Code style

- **Rust** - `cargo fmt` (enforced by `cargo fmt --check`) and `cargo clippy` with `-D warnings`.
  - Cargo workspace: `src/packages/core` (the `chromium-bridge-core` library), `src/apps/host` (the `chromium-bridge` binary), and `src/apps/desktop` (the Tauri app).
  - Errors on the tool-call path use the typed `CallError` (`src/packages/core/src/error.rs`).
  - Log via the `log_*!` macros (`src/packages/core/src/log.rs`), never bare `eprintln!` for diagnostics. **stdout is protocol** - all logging goes to stderr.
- **TypeScript** - Biome lints and formats every TS/JS/JSON file in the bun workspace (`bunx biome ci .` to check, `moon run fix` to auto-fix; config in `biome.json`).
  - `noExplicitAny` is enforced in extension source; test files and the tests/ harness are exempt until their CDP plumbing gets real types.
- **Shared schemas** - the cross-boundary TS shapes (settings, envelopes, runtime messages) live as Zod schemas in `src/packages/shared`; the types are inferred from them and the extension parses untrusted input against them at runtime. Don't reintroduce a hand-written duplicate type next to a schema - extend the schema.

## Adding a tool

A new tool touches both sides ([docs/architecture.md](./docs/architecture.md) section 10):

1. **Add it to the Rust catalogue** ([`src/packages/core/src/tools/catalogue.rs`](src/packages/core/src/tools/catalogue.rs)), the single source for the tool's identity (name, description, risk, scope, permission, confirmation, inputSchema). Then give it:
   - a `HANDLERS` registry entry plus a `build_*` payload fn (`src/packages/core/src/tools/handlers.rs`);
   - a home in [`src/packages/core/src/tools/capabilities.rs`](src/packages/core/src/tools/capabilities.rs);
   - a bumped count in `tool_count_is_pinned`.

   The `registry_covers_catalogue` and capability-parity tests (`cargo test`) point at whichever you miss.
2. **Regenerate the TS side** with `moon run gen` (`src/packages/shared/src/*.gen.ts`); CI fails if the generated files are stale.
   - A new arg that widens the envelope's args bag is picked up automatically.
   - A new envelope FIELD is a protocol change: see `BridgeReq` in `src/packages/core/src/protocol.rs` and the envelope parity gate, `moon run check-envelope`.
3. **Give the op a home in the extension.** The roster test and the exhaustive switches fail until the partition is complete:
   - a service-worker op: `SW_OPS` + a `dispatchSw` case in `src/apps/extension/src/lib/background/dispatch.ts`;
   - a page op: `PAGE_OPS` (`src/apps/extension/src/lib/shared/page-ops.ts`) + cases in `src/apps/extension/src/lib/content/handle.ts` and `src/apps/extension/src/lib/background/backends/cdp.ts`;
   - its UI label: `tools.<op>` in `src/apps/extension/src/locales/*.yml`; the key-parity test fails until every locale has it.
4. Give it a risk row in the [tool risk matrix](docs/security/tool-risk-matrix.md).
5. Extend `tests/protocol/e2e.py` (and `dom_test.ts` for DOM ops).

## Versioning

`Cargo.toml` is the source of truth. Release-please bumps it (and the extension `package.json`) in the rolling release PR and writes `CHANGELOG.md`; after a manual bump, run `moon run sync-version` to propagate it. CI fails if the crate and extension versions drift.

## License

By contributing you agree your contributions are licensed under the [Individual and Small Organization License 1.0.0](./LICENSE.md).
