#!/usr/bin/env bash
# Propagate the crate version (Cargo.toml, the source of truth) into the
# extension manifest and package files, then verify consistency.
#
# Usage: bump the version in Cargo.toml, then run `just sync-version`
# (or ./scripts/sync-version.sh) and commit the result.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO="$(grep -m1 '^version' "$ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
echo "Cargo.toml version: $CARGO"

# extension/manifest.json — replace the "version": "..." string in place.
# ("manifest_version" is a distinct key and is not matched by "version".)
MANIFEST="$ROOT/extension/manifest.json"
tmp="$(mktemp)"
sed -E "s/(\"version\"[[:space:]]*:[[:space:]]*\")[^\"]+(\")/\1${CARGO}\2/" "$MANIFEST" >"$tmp"
mv "$tmp" "$MANIFEST"
echo "updated extension/manifest.json"

# extension/package.json + package-lock.json — npm keeps both in sync.
( cd "$ROOT/extension" && npm version "$CARGO" --no-git-tag-version --allow-same-version >/dev/null )
echo "updated extension/package.json + package-lock.json"

"$ROOT/scripts/check-version.sh"
