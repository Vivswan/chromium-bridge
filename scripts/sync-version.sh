#!/usr/bin/env bash
# Propagate the crate version (Cargo.toml, the source of truth) into the
# extension manifest and package files, then verify consistency.
#
# Usage: bump the version in Cargo.toml, then run `make sync-version`
# (or ./scripts/sync-version.sh) and commit the result.
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

CARGO="$(bb_cargo_version)"
echo "Cargo.toml version: $CARGO"

# extension/manifest.json — replace the "version": "..." string in place.
# ("manifest_version" is a distinct key and is not matched by "version".)
MANIFEST="$BB_ROOT/extension/manifest.json"
tmp="$(mktemp)"
sed -E "s/(\"version\"[[:space:]]*:[[:space:]]*\")[^\"]+(\")/\1${CARGO}\2/" "$MANIFEST" >"$tmp"
mv "$tmp" "$MANIFEST"
echo "updated extension/manifest.json"

# extension/package.json + package-lock.json — npm keeps both in sync.
(cd "$BB_ROOT/extension" && npm version "$CARGO" --no-git-tag-version --allow-same-version >/dev/null)
echo "updated extension/package.json + package-lock.json"

"$BB_ROOT/scripts/check-version.sh"
