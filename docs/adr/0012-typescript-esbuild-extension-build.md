# ADR-0012: Extension written in TypeScript, bundled with esbuild into dist/

- **Status**: Accepted
- **Date**: 2026-07-10
- **Deciders**: user + AI assistant

## Context

The v0.1/v0.2 MV3 extension was four hand-written plain `.js` files (`background.js` / `content.js` / `options.js` / `popup.js`), loaded unpacked straight from the `src/apps/extension/` directory. That was fast enough for the prototype phase, but as ADR-0008 (page_eval), ADR-0009 (page_snapshot_precise), ADR-0010 (cookie/storage), and ADR-0011 (Options page) landed, the extension-side code volume and complexity grew, and several problems surfaced:

- **No types**: the `chrome.*` APIs and the bridge messages' `op`/`args`/response shapes lived on memory and comment conventions; refactors and new tools easily dropped fields or passed wrong types, caught only by runtime errors.
- **No static checks**: unused variables, misspelled branches, and implicit `any` went unchallenged.
- **Cross-file sync was entirely manual**: `op` strings and the `DEFAULTS` constants are mirrored across background/content/options (see ADR-0011) with no compile-time guarantee whatsoever.
- **Maintainability**: files kept growing, and without modularity or type constraints the bar for new contributors rose.

The engineering-standards cleanup needed to give the extension types, lint, and one reproducible build pipeline. Introducing types means the sources are no longer `.js` the browser can eat directly; a build step must strip the types and package the sources into something the extension can load.

## Decision

**Rewrite the extension sources in TypeScript (`src/apps/extension/src/*.ts`, strict mode), bundle with esbuild into IIFE files under `src/apps/extension/dist/`, and make dist/ the new load-unpacked target.**

- The four entries `src/{background,content,options,popup}.ts` each bundle into `dist/*.js`.
- Static assets (`manifest.json`, `popup.html`, `options.html`, `toast.css`, `icons/`) are copied into dist/ verbatim by the build script (`build.mjs`).
- Output is **IIFE format, unminified (`minify: false`)** so the unpacked extension stays readable and debuggable; `target: chrome116`.
- Type checking (`tsc --noEmit`), lint (ESLint), and formatting (Prettier) are decoupled from bundling; esbuild only strips types and bundles, with no type validation (see ADR-0013's CI gates).

## Alternatives considered

### Option A: keep hand-writing plain JS (status quo)
- **Pros**: zero build, zero dependencies, edit and reload directly.
- **Cons**: no types, no static checks, cross-file sync by comments alone; the extension's complexity had reached the point of needing a type net.
- **Not chosen**: the core goal of the cleanup is exactly types and checks.

### Option B: compile with tsc directly (no bundler)
- **Pros**: the official toolchain, no extra bundler dependency.
- **Cons**: `tsc` only transpiles file by file, it does not bundle; if shared modules are split out later (a unified `DEFAULTS`/type definitions), ESM/import loads differently in each MV3 context (SW, content script, and page scripts have different rules), so tsc output is hard to run directly; an asset-copy script would still be needed.
- **Not chosen**: either give up modularity or bolt on bundling logic; going straight to a bundler is better.

### Option C: webpack
- **Pros**: mature ecosystem, plenty of MV3 plugins.
- **Cons**: heavy configuration (a whole loader/plugin/mode apparatus), a large dependency tree, slow cold starts; overkill for "four entries plus copying a few static files."
- **Rejected**: conflicts with the project's standing preference for minimal dependencies and auditable artifacts.

### Option D: rollup
- **Pros**: clean output, good tree-shaking.
- **Cons**: TS support hangs off plugins (`@rollup/plugin-typescript` and friends), configuration is scattered; slower than esbuild.
- **Not chosen**: esbuild covers TS plus bundling in a single dependency, which is leaner.

### Option E: esbuild (adopted)
- **Pros**: **one fast dependency** covers both "strip TS types" and "bundle"; the configuration is a single `build.mjs` with no config sprawl; `format: "iife"` directly produces self-contained scripts each context can load; `--watch` iterates quickly.
- **Cons**: esbuild itself does no type checking (which is exactly why `tsc --noEmit` is a separate gate); tree-shaking/optimization is less thorough than rollup, but this project neither minifies nor chases minimal size, so it does not matter.
- **Adopted**.

## Verifying the migration was behavior-neutral

The conversion ran in two steps, pipeline first, types second (see git history Phase 2a/2b/2c). The point was to prove that "introducing a build step" by itself changes no runtime behavior:

- **Phase 2a** built only the pipeline: `background.js -> src/background.ts` and friends moved via git rename (preserving history), **with no type annotations added**. At that point all esbuild does to these "pure JS files with a changed extension" is "zero types to strip + IIFE wrapping", so the produced `dist/*.js` is semantically equivalent to the originals; it can be treated as a near byte-level move, isolating the "build pipeline" variable from the "typing" variable.
- The existing test suites locked the behavior: `dom_test` 77/77 (unchanged), smoke 4/4, protocol e2e 45/45, all green, proving the build step behavior-neutral.
- **Phase 2b/2c** then added strict types file by file on the verified pipeline, added ESLint/Prettier, and deleted dead code.

`tests/browser/dom_test.ts` reads the **build artifact** `src/apps/extension/dist/content.js` (not the `.ts` sources) for its DOM-level assertions; it tests the code the browser actually loads, and in passing puts "esbuild output works" under test protection.

## Consequences

### Positive
- **Type safety**: `chrome.*` (`@types/chrome`), the bridge messages, and DEFAULTS all get compile-time constraints; adding tools and refactoring no longer rely on runtime trial and error.
- **Static checks**: strict plus ESLint stop implicit any, unused variables, and misspelled branches.
- **Maintainable**: sources live under `src/`, modular and extensible.
- **A simple pipeline**: one `build.mjs` plus the single esbuild dependency, no config sprawl.

### Negative
- **The install/load flow changed**: the load-unpacked target moved from `src/apps/extension/` to **`src/apps/extension/dist/`**, and dist/ is a build artifact (gitignored). **After changing code you must run `npm run build` (or `just ext-build`) before reloading the extension**; editing `.js` in place no longer takes effect. `install.sh` also now builds first and loads from dist/.
- **One more build-layer dependency**: extension development needs Node plus `npm ci`; esbuild/typescript/eslint and friends enter devDependencies.
- **Artifacts are not committed**: dist/ is untracked; a fresh clone must build before it can load.

### Neutral
- esbuild does no type checking; types/lint/format exist as separate CI gates (see ADR-0013), which keeps responsibilities clear but means running them separately.

## Implementation

- `src/apps/extension/src/{background,content,options,popup}.ts`: strict TypeScript sources.
- `src/apps/extension/build.mjs`: the esbuild driver; bundles the four entries into IIFE files in dist/ and copies static assets; `--watch` for incremental builds.
- `src/apps/extension/tsconfig.json`: `strict`, `noEmit`, `types: ["chrome"]`, `moduleResolution: bundler`.
- `src/apps/extension/package.json`: `build` / `watch` / `typecheck` / `lint` / `format` scripts; devDependencies include esbuild, typescript, @types/chrome, eslint, prettier, typescript-eslint.
- `.gitignore`: exclude `src/apps/extension/dist` and `src/apps/extension/node_modules`.
- `tests/browser/dom_test.ts`: reads `src/apps/extension/dist/content.js` (the build artifact).
- `install.sh` / `README`: build the extension and load-unpacked from dist/.

## Relationship to other ADRs

- **[ADR-0001](./0001-use-rust-single-binary.md)**: that ADR covers only the Rust backend's "single binary, zero runtime dependencies"; the extension gaining a build step is a parallel artifact chain and does not affect how the backend is distributed.
- **[ADR-0013](./0013-ci-and-toolchain.md)**: the typecheck/lint/format/build this ADR establishes is gated uniformly by CI's extension job.
