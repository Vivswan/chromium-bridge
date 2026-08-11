#!/usr/bin/env bash
# Container-side driver, invoked by scripts/run-browser-tests-container.sh.
# Copies the READ-ONLY mounted repo into a scratch dir (installs and build
# outputs never touch the host checkout), builds the extension, runs the
# requested suites exactly like CI's browser job (checks.yml), and requires
# the per-suite RAN canary at the end.
set -euo pipefail

SRC=/repo
WORK=/work

# Copy the checkout minus heavy/derived trees. GNU tar matches bare patterns
# anywhere in the path, so nested node_modules are excluded too.
(cd "$SRC" && tar cf - \
  --exclude=node_modules --exclude=.git --exclude=.claude --exclude=.worktrees \
  --exclude=./build --exclude=./target --exclude=./.moon/cache \
  .) | (cd "$WORK" && tar xf -)
cd "$WORK"

bun install --frozen-lockfile
bun run --cwd src/apps/extension build

export BB_REQUIRE_BROWSER=1
export BB_BROWSER_CANARY_DIR=/tmp/browser-canary
mkdir -p "$BB_BROWSER_CANARY_DIR"

suites="${BB_SUITES:-dom smoke security}"
markers=""
for s in $suites; do
  case "$s" in
    dom)
      echo "=== dom_test (headless) ==="
      time bun tests/browser/dom_test.ts
      markers="$markers dom_test"
      ;;
    smoke)
      echo "=== ext_test (xvfb) ==="
      xvfb-run -a bun tests/browser/ext_test.ts
      markers="$markers ext_test"
      ;;
    security)
      echo "=== security_browser_test (xvfb) ==="
      xvfb-run -a bun tests/browser/security_browser_test.ts
      markers="$markers security_browser_test"
      ;;
    *)
      echo "unknown suite '$s' (dom|smoke|security)" >&2
      exit 2
      ;;
  esac
done

# The CI canary, mirrored: every requested suite must have left a real RAN
# marker (a silent skip or a zero-pass run fails the whole container run).
status=0
for m in $markers; do
  marker="$BB_BROWSER_CANARY_DIR/$m"
  if [ ! -f "$marker" ]; then
    echo "ERROR: $m left no RAN marker - it finished no real browser run" >&2
    status=1
  elif grep -q ': 0 passed' "$marker"; then
    echo "ERROR: $m ran vacuously: $(cat "$marker")" >&2
    status=1
  else
    cat "$marker"
  fi
done
exit "$status"
