# chromium-bridge developer tasks. `just` (no args) lists them.
# Requires: cargo (+ cargo-nextest), bun, python3. Optional: Chrome for the
# browser suites, typos + cargo-machete for the hygiene checks, shellcheck.
# Every recipe is a plain command you can also run by hand (see docs/development.md).

# List available recipes
default:
    @just --list --unsorted

# Build everything (mirror of `bun run build`): shared typecheck -> extension
# bundle -> scripts typecheck -> cargo build --workspace
build:
    bun run build

# Build the release binary
build-release:
    cargo build --release

# Deterministic release build (path-remapped, --locked)
build-repro:
    ./scripts/build-repro.sh

# Build + sign the Tauri desktop app with the bundled host + extension (macOS, ADR-0026/0029)
desktop-bundle:
    bun scripts/desktop-bundle.ts

# Verify the signed desktop bundle's entitlement chain (app + nested host)
desktop-check:
    bun scripts/check-desktop-signing.ts

# Desktop app dev loop: Vite dev server + tauri dev (unsigned; Enclave ops
# need the built host as a sibling: run `cargo build` first)
app-dev:
    #!/usr/bin/env sh
    set -eu
    bun scripts/gen-icons.ts desktop
    cargo build
    cd src/apps/desktop && bunx tauri dev

# Build, sign, verify, then launch the desktop app (USER-RUN: the GUI)
app-run: desktop-bundle
    open "target/release/bundle/macos/Chromium Bridge.app"

# Build + sign the app and wrap it in a signed, verified .dmg
# (target/release/bundle/dmg/; the app inside the image is re-verified)
app-dmg:
    bun scripts/desktop-bundle.ts --dmg

# Copy the built, signed app into /Applications (run desktop-bundle or
# app-dmg first; replaces any existing install)
app-install:
    #!/usr/bin/env sh
    set -eu
    APP="target/release/bundle/macos/Chromium Bridge.app"
    if [ ! -d "$APP" ]; then
        echo "error: $APP not found; build it first: just desktop-bundle (or just app-dmg)" >&2
        exit 1
    fi
    rm -rf "/Applications/Chromium Bridge.app"
    ditto "$APP" "/Applications/Chromium Bridge.app"
    echo "installed /Applications/Chromium Bridge.app"

# Desktop UI: production build (also what `bunx tauri build` runs first)
desktop-ui-build:
    bun run --cwd src/apps/desktop/ui build

# Desktop UI unit tests (locale coverage, i18n resolution; no browser)
desktop-ui-test:
    bun run --cwd src/apps/desktop/ui test

# Desktop Rust crate: clippy + tests. Needs the UI dist (tauri's
# generate_context! embeds it) and the generated app icon (tauri-build reads
# icons/icon.png at compile time), hence the dependencies. Not part of
# `just ci`: the crate is deliberately not a default workspace member, and
# compiling Tauri needs platform GUI toolchains (WebKitGTK on Linux); CI runs
# this on macOS in the dedicated desktop job.
desktop-check-rust: desktop-ui-build gen-icons
    cargo clippy -p chromium-bridge-desktop --all-targets -- -D warnings
    cargo test -p chromium-bridge-desktop

# Touch ID proof for the bundled host (USER-RUN: raises a real Touch ID
# prompt). Builds + verifies the bundle, then enrolls the enclave key via the
# BUNDLED host binary; on success the machine is genuinely enrolled. Undo
# with the same binary's `revoke` subcommand.
desktop-touchid-proof: desktop-bundle
    "target/release/bundle/macos/Chromium Bridge.app/Contents/Helpers/chromium-bridge.app/Contents/MacOS/chromium-bridge" pair

# Touch ID gate demo (USER-RUN, macOS: raises a REAL Touch ID prompt). Runs
# the per-action presence gate - the one page_eval / page_upload use - so you
# can watch the Enclave sign under Touch ID, then prints the two
# capability-grant commands (pair-client, unkill) for you to run in your own
# terminal: those require a real interactive TTY by design (anti tap-phishing),
# which a just recipe cannot provide. Needs an enrolled Enclave key (run
# `just desktop-touchid-proof` first) and uses the SIGNED BUNDLED host, since
# the enclave key lives in an entitled keychain group the plain release binary
# cannot reach.
# Demo the Touch ID presence gates (runs the per-action gate; prints the rest).
touchid-gates: desktop-bundle
    #!/usr/bin/env bash
    set -euo pipefail
    BIN="target/release/bundle/macos/Chromium Bridge.app/Contents/Helpers/chromium-bridge.app/Contents/MacOS/chromium-bridge"
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

# Format Rust sources
fmt:
    cargo fmt

# Verify Rust formatting (CI gate)
fmt-check:
    cargo fmt --check

# Lint Rust, denying all warnings (CI gate)
lint:
    cargo clippy --all-targets -- -D warnings

# Lint the remaining standalone shell scripts (needs shellcheck)
lint-scripts:
    shellcheck scripts/build-repro.sh scripts/fuzz_smoke.sh

# Source-code spell check (CI gate; config in typos.toml)
typos:
    typos

# Detect unused Cargo dependencies (CI gate)
machete:
    cargo machete

# Supply-chain checks (needs cargo-deny, cargo-audit)
audit:
    cargo deny check
    cargo audit

# Regenerate the TS contract modules from the Rust core (src/packages/shared/src/*.gen.ts)
gen:
    bun scripts/gen-ops.ts
    bunx biome format --write src/packages/shared/src/ops.gen.ts src/packages/shared/src/identity.gen.ts src/packages/shared/src/errors.gen.ts src/packages/shared/src/protocol.gen.ts

# The checked-in generated TS must match what the Rust core emits today
check-gen: gen
    git diff --exit-code -- src/packages/shared/src/ops.gen.ts src/packages/shared/src/identity.gen.ts src/packages/shared/src/errors.gen.ts src/packages/shared/src/protocol.gen.ts

# Envelope double-derivation gate: Rust schemars vs Zod z.toJSONSchema
check-envelope:
    bun scripts/check-envelope-parity.ts

# schemars is gen-only tooling: it must never enter a shipped binary's graph
check-schemars-isolation:
    #!/usr/bin/env sh
    set -eu
    tree="$(cargo tree -e normal -p chromium-bridge --locked)"
    if printf '%s\n' "$tree" | grep -q schemars; then
        echo "schemars leaked into the chromium-bridge binary dependency graph" >&2
        exit 1
    fi

# Rust unit + integration tests (cargo-nextest, plus doctests)
test-rust:
    cargo nextest run
    cargo test --doc

# Protocol-layer e2e tests (drives the real release binary)
test-e2e: build-release
    python3 tests/protocol/e2e.py

# Install JS workspace dev dependencies (bun)
js-deps:
    bun install

# Render the extension + desktop icon rasters from the assets/icon/ SVGs
# (build artifacts, gitignored; the extension and desktop builds run this
# themselves via scripts/gen-icons.ts)
gen-icons:
    bun scripts/gen-icons.ts

# Build the extension bundle (src/ -> dist/; generates icons first)
ext-build:
    bun run --cwd src/apps/extension build

# Type-check every TS project (extension, tests, scripts, src/packages/shared)
typecheck:
    bun run typecheck

# Lint + format-check all TS/JS/JSON (Biome)
check-ts:
    bunx biome ci .

# Auto-fix lint + format across the workspace (Biome)
fix-ts:
    bunx biome check --write .

# Unit-test the extension's shared modules (bun; no browser)
ext-test:
    bun run --cwd src/apps/extension test

# Unit-test src/packages/shared: generated catalogue, boundary validators
shared-test:
    bun run --cwd src/packages/shared test

# DOM + smoke + security proofs (needs bun + isolated Chrome; builds first)
test-browser: ext-build
    cd tests/browser && bun dom_test.ts
    bun tests/browser/ext_test.ts
    bun tests/browser/security_browser_test.ts

# Real E2E integration (opt-in; real binary + Chrome + extension)
test-integration: build-release ext-build
    BB_REAL_E2E=1 bun tests/browser/integration_e2e.ts

# All tests that run without a browser
test: test-rust test-e2e

# Everything CI runs (except the macOS-only desktop Rust job: desktop-check-rust)
ci: fmt-check lint lint-scripts typos machete test-rust typecheck check-ts shared-test ext-test desktop-ui-test ext-build test-e2e check-extension-id check-cjk check-all-green check-gen check-envelope check-schemars-isolation

# Register this checkout's release binary with your browsers (build + doctor --fix)
install: build-release
    ./target/release/chromium-bridge doctor --fix

# Build the docs site (docs/site: Astro over the repo's markdown docs)
docs-site-build:
    bun run --cwd docs/site build

# Docs site dev server
docs-site-dev:
    bun run --cwd docs/site dev

# Propagate the Cargo.toml version into the extension files
sync-version:
    bun scripts/sync-version.ts

# Verify the crate and extension versions agree
check-version:
    bun scripts/check-version.ts

# Verify the pinned key, extension ID, and built manifest agree
check-extension-id:
    bun scripts/check-extension-id.ts

# Verify CJK text stays inside the zh locale files and translated docs
check-cjk:
    bun scripts/check-cjk.ts

# Every ci.yml job must be required by the all-green merge gate (or exempted
# with a reason in the script)
check-all-green:
    bun scripts/check-all-green.ts
    bun test scripts/check-all-green.test.ts

# Pre-release gate: versions consistent + full CI green
release: check-version check-extension-id ci
    @echo "Release checks passed. Now tag the release, e.g.: git tag v$(bun scripts/check-version.ts | awk '/Cargo.toml/{print $2}')"
