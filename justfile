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
    shellcheck install/install.sh scripts/build-repro.sh scripts/install_verify_test.sh scripts/fuzz_smoke.sh

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

# Regenerate code from contracts/ (ops.gen.ts + identity.gen.ts into src/packages/shared)
gen:
    bun scripts/gen-ops.ts
    bunx biome format --write src/packages/shared/src/ops.gen.ts src/packages/shared/src/identity.gen.ts

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

# Build the extension bundle (src/ -> dist/)
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

# Unit-test src/packages/shared: contract equivalence, parity, boundary validators
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

# Everything CI runs
ci: fmt-check lint lint-scripts typos machete test-rust typecheck check-ts shared-test ext-test ext-build test-e2e check-extension-id

# Install locally (build + copy binary + host manifest)
install:
    ./install/install.sh

# Propagate the Cargo.toml version into the extension files
sync-version:
    bun scripts/sync-version.ts

# Verify the crate and extension versions agree
check-version:
    bun scripts/check-version.ts

# Verify the manifest key and installer extension IDs agree
check-extension-id:
    bun scripts/check-extension-id.ts

# Pre-release gate: versions consistent + full CI green
release: check-version check-extension-id ci
    @echo "Release checks passed. Now tag the release, e.g.: git tag v$(bun scripts/check-version.ts | awk '/Cargo.toml/{print $2}')"
