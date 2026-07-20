# chromium-bridge developer tasks. `just` (no args) lists them.
# Requires: cargo (+ cargo-nextest), bun, python3. Optional: Chrome for the
# browser suites, typos + cargo-machete for the hygiene checks.
# Every recipe is a plain command you can also run by hand (see docs/development.md).
#
# Naming convention: verb first, project second - `<verb>-<project>`, as in
# dev-web, build-ext, or dmg-app. Verbs can be compound (fmt-check-rust) and
# a recipe may add a trailing qualifier (check-app-signing). Project
# shorthands: web (the Astro site in src/apps/web), app (the Tauri desktop
# app), app-ui (the desktop app's web UI), ext (the MV3 extension), shared
# (src/packages/shared), rust (the cargo workspace), ts (all TS/JS/JSON).
# Recipes that span the whole repo (ci, gen, typecheck, ...) and the
# machine-level Touch ID runbooks (touchid-proof, touchid-gates) take no
# project suffix.
#
# `just --list` shows only the top-level verbs. Recipes marked [private] are
# internal sub-steps (CI sub-checks, build/test sub-targets, `bun run <verb>`
# delegates) - hidden from the list but still runnable by name.

# List available recipes
default:
    @just --list

# Build everything: shared typecheck -> extension -> desktop UI -> scripts typecheck -> cargo workspace -> web app
[group('main')]
build:
    bun scripts/gen-icons.ts
    bun run --cwd src/packages/shared typecheck
    bun run --cwd src/apps/extension build
    bun run --cwd src/apps/desktop/ui build
    bunx tsc -p scripts
    cargo build --workspace
    bun run --cwd src/apps/web build

# Build the release binary
[private]
build-release:
    cargo build --release

# Deterministic release build (path-remapped, --locked)
[private]
build-repro:
    bun scripts/build-repro.ts

# Build + sign the Tauri desktop app with the bundled host + extension (macOS, ADR-0026/0029)
[private]
bundle-app:
    bun scripts/desktop-bundle.ts

# Verify the signed desktop bundle's entitlement chain (app + nested host)
[private]
check-app-signing:
    bun scripts/check-desktop-signing.ts

# Dev everything at once: extension (WXT dev browser) + web app (Astro) +
# desktop app (tauri dev). Ctrl-C stops all three; see scripts/dev.ts.
[group('main')]
[doc('Dev everything: extension (WXT) + web app (Astro) + desktop app (tauri) together')]
dev:
    bun scripts/dev.ts

# Desktop app dev loop ONLY: Vite dev server + tauri dev (unsigned; Enclave
# ops need the built host as a sibling, hence the cargo build). `just dev`
# supersets this.
[private]
dev-app:
    #!/usr/bin/env sh
    set -eu
    bun scripts/gen-icons.ts desktop
    cargo build
    bun run --cwd src/apps/extension build
    cd src/apps/desktop && bunx tauri dev

# Build, sign, verify, then launch the desktop app (USER-RUN: the GUI)
[group('app')]
run-app: bundle-app
    open "build/app/Chromium Bridge.app"

# Build + sign the app and wrap it in a signed, verified .dmg
# (build/dmg/; the app inside the image is re-verified)
[group('app')]
[doc('Build + sign the app and wrap it in a signed, verified .dmg (build/dmg/)')]
dmg-app:
    bun scripts/desktop-bundle.ts --dmg

# Copy the built, signed app into /Applications (run bundle-app or
# dmg-app first; replaces any existing install)
[group('app')]
[doc('Copy the built, signed app into /Applications (run dmg-app or bundle-app first)')]
install-app:
    #!/usr/bin/env sh
    set -eu
    APP="build/app/Chromium Bridge.app"
    if [ ! -d "$APP" ]; then
        echo "error: $APP not found; build it first: just bundle-app (or just dmg-app)" >&2
        exit 1
    fi
    rm -rf "/Applications/Chromium Bridge.app"
    ditto "$APP" "/Applications/Chromium Bridge.app"
    echo "installed /Applications/Chromium Bridge.app"

# Desktop UI: production build (also what `bunx tauri build` runs first)
[private]
build-app-ui:
    bun run --cwd src/apps/desktop/ui build

# Desktop UI unit tests (locale coverage, i18n resolution; no browser)
[private]
test-app-ui:
    bun run --cwd src/apps/desktop/ui test

# Desktop Rust crate: clippy + tests, plus the commands.gen.ts staleness gate
# (check-gen-app). Needs the UI dist (tauri's generate_context! embeds it) and
# the generated app icon (tauri-build reads icons/icon.png at compile time),
# hence the dependencies. Clippy runs with --features ts-export so the
# gen-only derive code is linted too. Not part of `just ci`: the crate is
# deliberately not a default workspace member, and compiling Tauri needs
# platform GUI toolchains (WebKitGTK on Linux); CI runs this on macOS in the
# dedicated desktop job.
[private]
check-app-rust: build-app-ui gen-icons check-gen-app
    cargo clippy -p chromium-bridge-desktop --all-targets --features ts-export -- -D warnings
    cargo test -p chromium-bridge-desktop

# Touch ID proof for the bundled host (USER-RUN: raises a real Touch ID
# prompt). Builds + verifies the bundle, then enrolls the enclave key via the
# BUNDLED host binary; on success the machine is genuinely enrolled. Undo
# with the same binary's `revoke` subcommand.
[private]
touchid-proof: bundle-app
    "build/app/Chromium Bridge.app/Contents/Helpers/chromium-bridge.app/Contents/MacOS/chromium-bridge" pair

# Touch ID gate demo (USER-RUN, macOS: raises a REAL Touch ID prompt). Runs
# the per-action presence gate - the one page_eval / page_upload use - so you
# can watch the Enclave sign under Touch ID, then prints the two
# capability-grant commands (pair-client, unkill) for you to run in your own
# terminal: those require a real interactive TTY by design (anti tap-phishing),
# which a just recipe cannot provide. Needs an enrolled Enclave key (run
# `just touchid-proof` first) and uses the SIGNED BUNDLED host, since
# the enclave key lives in an entitled keychain group the plain release binary
# cannot reach.
# Demo the Touch ID presence gates (runs the per-action gate; prints the rest).
[private]
touchid-gates: bundle-app
    #!/usr/bin/env bash
    set -euo pipefail
    BIN="build/app/Chromium Bridge.app/Contents/Helpers/chromium-bridge.app/Contents/MacOS/chromium-bridge"
    echo "== 1/3 per-action presence (page_eval / page_upload gate) =="
    echo "   expect a Touch ID prompt now:"
    "$BIN" presence-selftest
    echo
    echo "== 2/3 client pairing  +  3/3 kill-switch release =="
    echo "   These GRANT or RESTORE capability, so from the CLI they require a"
    echo "   real interactive terminal (a background or piped process must not be"
    echo "   able to raise that Touch ID sheet). A just recipe has no TTY, so run"
    echo "   these yourself in this terminal - each raises a Touch ID prompt:"
    echo
    echo "     BIN=\"$BIN\""
    echo "     \"\$BIN\" pair-client --name touchid-demo --hash \$(printf 'ab%.0s' {1..32})   # Touch ID"
    echo "     \"\$BIN\" revoke-client --name touchid-demo                                    # instant, no prompt"
    echo "     \"\$BIN\" kill && \"\$BIN\" unkill                                              # kill instant; unkill = Touch ID"
    echo
    echo "touchid-gates: the per-action gate above raised a live Touch ID prompt;"
    echo "the two capability-grant gates need a real terminal - commands printed above."

# Format everything in place: Rust (cargo fmt) + TS/JS/JSON (Biome)
[group('quality')]
fmt:
    cargo fmt
    bunx biome format --write .

# Verify Rust formatting (CI gate)
[private]
fmt-check-rust:
    cargo fmt --check

# Lint everything, denying warnings: Rust (clippy) + TS/JS/JSON (Biome)
[group('quality')]
lint: lint-rust lint-ts

# Lint Rust, denying all warnings (the CI gate; `lint` adds Biome on top)
[private]
lint-rust:
    cargo clippy --all-targets -- -D warnings

# Source-code spell check (CI gate; config in typos.toml)
[private]
typos:
    typos

# Detect unused Cargo dependencies (CI gate)
[private]
machete:
    cargo machete

# Supply-chain checks (needs cargo-deny, cargo-audit)
[private]
audit:
    cargo deny check
    cargo audit

# Regenerate ALL generated TS from Rust: the shared contract modules and the
# desktop UI's Tauri command types (the latter compiles the desktop crate)
[private]
gen: gen-shared gen-app-types

# Regenerate the TS contract modules from the Rust core (src/packages/shared/src/*.gen.ts)
[private]
gen-shared:
    bun scripts/gen-ops.ts
    bunx biome format --write src/packages/shared/src/ops.gen.ts src/packages/shared/src/identity.gen.ts src/packages/shared/src/errors.gen.ts src/packages/shared/src/protocol.gen.ts

# Regenerate the desktop UI's Tauri command types from the desktop crate's
# command DTOs (src/apps/desktop/ui/src/lib/commands.gen.ts). ts-rs writes
# bindings by executing generated code, so the export runs as a cargo test
# (src/apps/desktop/src/ts_export.rs) behind the gen-only ts-export feature;
# the file is deleted first and must be recreated, so a renamed or missing
# export test fails here instead of silently leaving a stale file. Compiling
# the desktop crate needs the UI dist and the generated icon, hence the
# dependencies - and the platform GUI toolchain, like check-app-rust.
[private]
gen-app-types: build-app-ui gen-icons
    rm -f src/apps/desktop/ui/src/lib/commands.gen.ts
    cargo test -p chromium-bridge-desktop --features ts-export export_commands_gen_ts
    test -f src/apps/desktop/ui/src/lib/commands.gen.ts
    bunx biome format --write src/apps/desktop/ui/src/lib/commands.gen.ts

# The checked-in generated TS must match what the Rust core emits today
# (part of `just ci`; commands.gen.ts has its own macOS-side gate, check-gen-app)
[private]
check-gen: gen-shared
    git diff --exit-code -- src/packages/shared/src/ops.gen.ts src/packages/shared/src/identity.gen.ts src/packages/shared/src/errors.gen.ts src/packages/shared/src/protocol.gen.ts

# Staleness gate for the desktop command types. Not part of `just ci` for the
# same reason as check-app-rust (compiling Tauri needs the platform GUI
# toolchain); CI's macOS desktop job runs it.
[private]
check-gen-app: gen-app-types
    git diff --exit-code -- src/apps/desktop/ui/src/lib/commands.gen.ts

# Envelope double-derivation gate: Rust schemars vs Zod z.toJSONSchema
[private]
check-envelope:
    bun scripts/check-envelope-parity.ts

# Gen-only tooling (schemars, ts-rs) must never enter a shipped binary's
# graph. The desktop crate is checked for ts-rs only: Tauri's macro stack
# carries its own schemars 0.8 - Tauri's dependency, not our gen feature
# (schemars 1, off by default, asserted out of the host binary below).
[private]
check-gen-isolation:
    #!/usr/bin/env sh
    set -eu
    tree="$(cargo tree -e normal -p chromium-bridge --locked)"
    for crate in schemars ts-rs; do
        if printf '%s\n' "$tree" | grep -q "$crate"; then
            echo "$crate leaked into the chromium-bridge binary dependency graph" >&2
            exit 1
        fi
    done
    tree="$(cargo tree -e normal -p chromium-bridge-desktop --locked)"
    if printf '%s\n' "$tree" | grep -q ts-rs; then
        echo "ts-rs leaked into the chromium-bridge-desktop binary dependency graph" >&2
        exit 1
    fi

# Rust unit + integration tests (cargo-nextest, plus doctests)
[private]
test-rust:
    cargo nextest run
    cargo test --doc

# Protocol-layer e2e tests (drives the real release binary)
[private]
test-e2e: build-release
    python3 tests/protocol/e2e.py

# Render the extension + desktop icon rasters from the assets/icon/ SVGs
# (build artifacts, gitignored; the extension and desktop builds run this
# themselves via scripts/gen-icons.ts)
[private]
gen-icons:
    bun scripts/gen-icons.ts

# Build the extension bundle (src/ -> build/extension/; generates icons first)
[private]
build-ext:
    bun run --cwd src/apps/extension build

# Type-check every TS project (extension, desktop UI, tests, scripts, src/packages/shared)
[private]
typecheck:
    bunx tsc -p src/apps/extension
    bunx tsc -p src/apps/desktop/ui
    bunx tsc -p tests/browser
    bunx tsc -p scripts
    bunx tsc -p src/packages/shared

# Lint + format-check all TS/JS/JSON (Biome; what `bun run check` delegates to)
[private]
check-ts:
    bunx biome ci .

# Lint TS/JS/JSON (Biome; what `bun run lint` delegates to)
[private]
lint-ts:
    bunx biome lint .

# Format TS/JS/JSON in place (Biome; what `bun run format` delegates to)
[private]
fmt-ts:
    bunx biome format --write .

# Verify TS/JS/JSON formatting (Biome; what `bun run format:check` delegates to)
[private]
fmt-check-ts:
    bunx biome format .

# Auto-fix everything: Biome lint+format fixes, then cargo fmt
[group('quality')]
fix:
    bunx biome check --write .
    cargo fmt

# Unit-test the extension's shared modules (bun; no browser)
[private]
test-ext:
    bun run --cwd src/apps/extension test

# Unit-test src/packages/shared: generated catalogue, boundary validators
[private]
test-shared:
    bun run --cwd src/packages/shared test

# Unit-test shared + extension (the `bun run test` set; the desktop UI's suite is test-app-ui)
[private]
test-ts: test-shared test-ext

# DOM + smoke + security proofs (needs bun + isolated Chrome; builds first)
[private]
test-browser: build-ext
    cd tests/browser && bun dom_test.ts
    bun tests/browser/ext_test.ts
    bun tests/browser/security_browser_test.ts

# Real E2E integration (opt-in; real binary + Chrome + extension)
[private]
test-integration: build-release build-ext
    BB_REAL_E2E=1 bun tests/browser/integration_e2e.ts

# All tests that run without a browser
[group('main')]
test: test-rust test-e2e

# Depends on lint-rust, not lint: check-ts (biome ci) already covers biome lint,
# so the lint meta-recipe would pay for the same Biome pass twice.
# Everything CI runs (except the macOS-only desktop Rust job: check-app-rust)
[group('main')]
ci: fmt-check-rust lint-rust typos machete test-rust typecheck check-ts test-shared test-ext test-app-ui build-ext test-e2e check-extension-id check-cjk check-typography check-all-green check-gen check-envelope check-gen-isolation

# Register this checkout's release binary with your browsers (build + doctor --fix)
[group('main')]
install: build-release
    ./target/release/chromium-bridge doctor --fix

# Build the web app (src/apps/web: Astro over the repo's markdown docs)
[private]
build-web:
    bun run --cwd src/apps/web build

# Docs site dev server only; replaces any already-running astro dev (`just dev` supersets this)
[private]
dev-web:
    bun run --cwd src/apps/web dev

# Propagate the Cargo.toml version into the extension files
[private]
sync-version:
    bun scripts/sync-version.ts

# Verify the crate and extension versions agree
[private]
check-version:
    bun scripts/check-version.ts

# Verify the pinned key, extension ID, and built manifest agree
[private]
check-extension-id:
    bun scripts/check-extension-id.ts

# Verify CJK text stays inside the zh locale files and translated docs
[private]
check-cjk:
    bun scripts/check-cjk.ts

# Every ci.yml job must be required by the all-green merge gate (or exempted
# with a reason in the script)
[private]
check-all-green:
    bun scripts/check-all-green.ts
    bun test scripts/check-all-green.test.ts

# No typographic look-alike characters (curly quotes, em-dashes, invisible
# unicode) in any tracked file; exact-path exemptions in .typography-allow
[private]
check-typography:
    bun scripts/check-typography.ts
    bun test scripts/check-typography.test.ts

# Pre-release gate: versions consistent + full CI green
[group('main')]
release: check-version check-extension-id ci
    @echo "Release checks passed. Now tag the release, e.g.: git tag v$(bun scripts/check-version.ts | awk '/Cargo.toml/{print $2}')"
