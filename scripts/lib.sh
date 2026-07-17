#!/usr/bin/env bash
# Shared helpers for the chromium-bridge shell scripts. Source it, don't run it:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"   # from scripts/
#
# Every function is prefixed `bb_` to avoid clashing with the caller's names.

# Repo root, derived from this file's location (scripts/ is a direct child).
BB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export BB_ROOT

# Print an error to stderr and exit. Usage: bb_die "message" [exit_code]
bb_die() {
  echo "error: $1" >&2
  exit "${2:-1}"
}

# Locate a cargo binary (PATH, then the common Homebrew / rustup spots), set the
# global BB_CARGO to its absolute path, and prepend its directory to PATH so the
# rustc it shells out to is discoverable. Exits via bb_die if cargo is missing.
#
# Call it as a plain statement (NOT `$(bb_find_cargo)`) — the PATH export must
# happen in the caller's shell, not a command-substitution subshell. Read the
# result from $BB_CARGO afterwards.
bb_find_cargo() {
  local candidate
  BB_CARGO=""
  for candidate in cargo /opt/homebrew/bin/cargo "$HOME/.cargo/bin/cargo"; do
    if command -v "$candidate" >/dev/null 2>&1; then
      BB_CARGO="$(command -v "$candidate")"
      break
    fi
  done
  [[ -n "$BB_CARGO" ]] || bb_die "cargo not found. Install Rust (https://rustup.rs) or fix PATH." 2
  export BB_CARGO
  local dir
  dir="$(dirname "$BB_CARGO")"
  if [[ ":$PATH:" != *":$dir:"* ]]; then
    export PATH="$dir:$PATH"
  fi
}

# Echo the crate version from Cargo.toml (the single source of truth).
bb_cargo_version() {
  grep -m1 '^version' "$BB_ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/'
}

# Echo the "version" string from a JSON file. ("manifest_version" is a distinct
# key and is not matched.)
bb_json_version() {
  grep -m1 '"version"' "$1" | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
}
