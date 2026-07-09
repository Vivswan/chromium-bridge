#!/usr/bin/env bash
# Verify the version is consistent across the crate and the extension.
#
# Cargo.toml is the single source of truth. This checks that
# extension/manifest.json and extension/package.json agree with it, and fails
# (exit 1) on any mismatch. `scripts/sync-version.sh` propagates the Cargo
# version to the others.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cargo_ver() { grep -m1 '^version' "$ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/'; }
json_ver() { grep -m1 '"version"' "$1" | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'; }

CARGO="$(cargo_ver)"
MANIFEST="$(json_ver "$ROOT/extension/manifest.json")"
PKG="$(json_ver "$ROOT/extension/package.json")"

printf 'Cargo.toml            %s\n' "$CARGO"
printf 'extension/manifest.json  %s\n' "$MANIFEST"
printf 'extension/package.json   %s\n' "$PKG"

fail=0
[[ "$MANIFEST" == "$CARGO" ]] || { echo "MISMATCH: manifest.json ($MANIFEST) != Cargo.toml ($CARGO)" >&2; fail=1; }
[[ "$PKG" == "$CARGO" ]] || { echo "MISMATCH: package.json ($PKG) != Cargo.toml ($CARGO)" >&2; fail=1; }

if [[ "$fail" -eq 0 ]]; then
  echo "versions consistent ✓"
fi
exit "$fail"
