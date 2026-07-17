#!/usr/bin/env bash
# Fuzz smoke test for the wire parsers (chromium-bridge).
#
# Builds every cargo-fuzz target and runs each for a short, bounded number of
# iterations, purely to prove the harnesses build and survive a quick blast of
# random input. This is a smoke check, NOT a real fuzzing campaign: continuous
# fuzzing (long runs, corpus, OSS-Fuzz) is a separate, nightly/CI concern.
#
# Requirements: a nightly toolchain and cargo-fuzz (libFuzzer). If either is
# missing the script SKIPS (exit 0) rather than failing, so it can sit in a
# stable-only gate harmlessly; wire it into a nightly job to make it load-bearing.
#
# Usage: scripts/fuzz_smoke.sh [runs]   (default 4096 iterations per target)
set -euo pipefail

RUNS="${1:-4096}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
# cargo-fuzz resolves the fuzz workspace from the crate that contains fuzz/,
# so run from the core package, not the repo root.
cd "$REPO/src/packages/core"

if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
  echo "[fuzz-smoke] SKIP: no nightly toolchain (install with: rustup toolchain install nightly)"
  exit 0
fi
if ! cargo +nightly fuzz --help >/dev/null 2>&1; then
  echo "[fuzz-smoke] SKIP: cargo-fuzz not installed (install with: cargo install cargo-fuzz)"
  exit 0
fi

TARGETS=(nm_frame mcp_jsonrpc bridge_envelope handshake attach)
for t in "${TARGETS[@]}"; do
  echo "[fuzz-smoke] $t: ${RUNS} runs"
  cargo +nightly fuzz run "$t" -- -runs="$RUNS" -max_total_time=30
done
echo "[fuzz-smoke] all targets survived ${RUNS} runs each"
