#!/usr/bin/env bash
# Run all browser-bridge tests: protocol layer (e2e.py) + DOM layer (dom_test.ts).
# Exits 0 only if ALL tests pass.
#
# Requirements:
#   - Rust toolchain (cargo) for building the release binary
#   - Python 3 for tests/e2e.py
#   - bun + Chrome for tests/dom_test.ts (set CHROME_BIN to override the path)
#
# Each layer is independent; failures in one still let the others run so you
# see all problems in one pass.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
FAILED=0

# ── locate cargo (PATH, then Homebrew) ─────────────────────────────────────
CARGO=""
for c in cargo /opt/homebrew/bin/cargo "$HOME/.cargo/bin/cargo"; do
  if command -v "$c" >/dev/null 2>&1; then CARGO="$(command -v "$c")"; break; fi
done
if [[ -z "$CARGO" ]]; then
  echo "error: cargo not found" >&2; exit 2
fi
# Make rustc discoverable to cargo subprocesses.
export PATH="$(dirname "$CARGO"):$PATH"

echo "═══ browser-bridge test suite ═══"
echo "(1/3) build release binary"
"$CARGO" build --release --manifest-path "$REPO/Cargo.toml" || { echo "BUILD FAILED"; exit 1; }

echo ""
echo "(2/3) protocol-layer tests (tests/e2e.py)"
python3 "$HERE/e2e.py" || { echo "PROTOCOL TESTS FAILED"; FAILED=1; }

echo ""
echo "(3/3) DOM-layer tests (tests/dom_test.ts)"
if command -v bun >/dev/null 2>&1; then
  # Locate Chrome (env override, then macOS default).
  : "${CHROME_BIN:=/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
  export CHROME_BIN
  if [[ ! -x "$CHROME_BIN" ]]; then
    echo "  SKIP  Chrome not found at $CHROME_BIN (set CHROME_BIN)"
    echo "  (DOM tests require Chrome headless)"
  else
    bun "$HERE/dom_test.ts" || { echo "DOM TESTS FAILED"; FAILED=1; }
  fi
else
  echo "  SKIP  bun not found (install: https://bun.sh)"
  echo "  (DOM tests require bun + Chrome)"
fi

echo ""
if [[ "$FAILED" -eq 0 ]]; then
  echo "═══ ALL TESTS PASSED ═══"
else
  echo "═══ SOME TESTS FAILED ═══"
fi
exit "$FAILED"
