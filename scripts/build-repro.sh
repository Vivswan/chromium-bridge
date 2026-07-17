#!/usr/bin/env bash
# build-repro.sh - deterministic release build of the chromium-bridge binary.
#
# Wraps `cargo build --release --locked` with the environment that makes the
# binary build deterministically: verified byte-identical across clean
# rebuilds and different checkout paths on one machine; matching a hash
# built elsewhere additionally requires the same rustup toolchain
# (rust-toolchain.toml) and platform SDK/linker.
#
#   - --remap-path-prefix rewrites the absolute checkout, CARGO_HOME, and home
#     directory paths that rustc embeds (panic locations, debug metadata) to
#     fixed placeholders, so the checkout location leaves no trace
#   - SOURCE_DATE_EPOCH is pinned to the last commit's timestamp (unless the
#     caller already set it), so nothing can derive from the build wall clock
#   - --locked refuses to build if Cargo.lock would change
#
# The release workflow builds with this script. To reproduce a published
# binary: check out the released tag, install the exact toolchain from
# rust-toolchain.toml via rustup (a distro/Homebrew rustc embeds different
# standard-library paths and will NOT match), run this script, and compare
# sha256 hashes. See README.md "Verifying your binary".
#
# Not covered yet: once release binaries are signed with a real Apple
# identity, the embedded signature will differ from a local rebuild and
# macOS verification will move to comparing cdhashes; today the arm64 macOS
# ad-hoc signature is linker-derived from the (identical) content, so the
# whole file still matches byte for byte.

set -euo pipefail

# shellcheck source=SCRIPTDIR/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
bb_find_cargo # sets BB_CARGO + puts its dir on PATH (plain call, not subshell)

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -C "$BB_ROOT" log -1 --pretty=%ct)" \
    || bb_die "not a git checkout and SOURCE_DATE_EPOCH is unset"
fi
export SOURCE_DATE_EPOCH

# Order matters: remap the most specific prefixes first, then $HOME as a
# catch-all so no user-identifying absolute path survives in the binary.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$BB_ROOT=/build"
RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$CARGO_HOME_DIR=/cargo-home"
RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$HOME=/home"
export RUSTFLAGS

echo "[build-repro] SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" >&2
echo "[build-repro] RUSTFLAGS=$RUSTFLAGS" >&2
exec "$BB_CARGO" build --release --locked --manifest-path "$BB_ROOT/Cargo.toml" "$@"
