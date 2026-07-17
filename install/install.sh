#!/usr/bin/env bash
# install.sh - build chromium-bridge and register the native messaging host for
# any Chromium-based browser.
#
# Usage:
#   ./install.sh                        Build + install everything. The
#                                       extension ID is fixed (pinned by the
#                                       `key` in extension/manifest.json), so no
#                                       ID copy-paste is needed.
#   ./install.sh --extension-id ID      Override the pinned extension ID.
#   ./install.sh --browser LIST         Which browsers to target. LIST is
#                                       `auto` (every known browser whose config
#                                       dir exists; the default), `all` (every
#                                       known browser), or a comma-separated set
#                                       of keys chrome,chromium,brave,edge,
#                                       vivaldi,opera (`both`=chrome,chromium).
#   ./install.sh --nm-dir DIR           Escape hatch: install into this exact
#                                       NativeMessagingHosts dir (repeatable).
#                                       Targets any Chromium browser not in the
#                                       table above; overrides --browser. Pass
#                                       the same --nm-dir to --uninstall to
#                                       remove this registration.
#   ./install.sh --skip-extension-build Reuse an existing extension/dist. Useful
#                                       in WSL when only the Rust toolchain is
#                                       installed in Linux.
#   ./install.sh --register-claude-code Also run `claude mcp add` to register the
#                                       server with Claude Code (needs the claude
#                                       CLI on PATH). Off by default; other clients
#                                       get ready-to-paste config printed instead.
#   ./install.sh --uninstall            Remove what this installer placed (binary,
#                                       run-host wrappers, run.lock, and the
#                                       native-host manifest for every known
#                                       browser). Re-pass any --nm-dir target to
#                                       clear it too. Leaves the browser and the
#                                       loaded extension untouched.
#   ./install.sh --expected-sha256 HASH Prebuilt mode only: verify the shipped
#                                       binary against this SHA-256 (64 hex
#                                       chars) obtained out of band. The offline
#                                       trust anchor: replaces the online gh
#                                       provenance check. Get it from the
#                                       release's .binary.sha256 asset.
#   ./install.sh --release-repo OWNER/REPO
#                                       Prebuilt mode only: trust this GitHub
#                                       repository's published checksums and
#                                       attestations instead of the pinned
#                                       canonical repository. Only for installing
#                                       a fork's release you already trust.
#
# Two modes, auto-detected:
#   - source checkout (Cargo.toml present): builds the binary (Rust) + the
#     extension (bun), then installs.
#   - prebuilt release tarball (no Cargo.toml): installs the shipped binary +
#     extension/dist directly - no Rust or bun needed. The shipped binary is
#     verified against the release's published SHA-256 (and, when an
#     authenticated `gh` is available, its build provenance attestation)
#     before anything is installed; on any mismatch the install refuses.
# macOS/Linux + any Chromium-based browser.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Project root. In a release tarball the installer sits at the archive root next
# to extension/ (ROOT == HERE); in the source tree it lives in install/ with the
# project one level up (ROOT == HERE/..). Detect by which layout is beside us.
if [[ -d "$HERE/extension" || -f "$HERE/Cargo.toml" ]]; then
  ROOT="$HERE"
else
  ROOT="$(cd "$HERE/.." && pwd)"
fi
HOST_NAME="com.vivswan.chromium_bridge.host"
BINARY_NAME="chromium-bridge"

# Deterministic extension ID, derived from the public `key` in
# extension/manifest.json (same for everyone, regardless of load path). If you
# ever change that key, update this to match (or pass --extension-id).
PINNED_EXTENSION_ID="mkjjlmjbcljpcfkfadfmhblmmddkdihf"

# The only GitHub repository whose published checksums and attestations the
# prebuilt-mode verification will trust. Pinned in code, like the extension
# ID above, so nothing inside a downloaded archive can redirect verification
# to a repository an attacker controls. Installing a fork's release requires
# the user to say so explicitly with --release-repo.
PINNED_RELEASE_REPO="Vivswan/chromium-bridge"

# ---- platform + args ------------------------------------------------------

EXTENSION_ID="$PINNED_EXTENSION_ID"
BROWSER="auto"
declare -a NM_DIRS_EXPLICIT=()
SKIP_EXTENSION_BUILD="${BB_SKIP_EXTENSION_BUILD:-0}"
UNINSTALL=0
REGISTER_CLAUDE=0
EXPECTED_SHA256=""
RELEASE_REPO="$PINNED_RELEASE_REPO"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --extension-id)
      EXTENSION_ID="${2:-}"
      [[ -n "$EXTENSION_ID" ]] || { echo "error: --extension-id requires a value" >&2; exit 1; }
      shift 2
      ;;
    --browser)
      BROWSER="${2:-}"
      [[ -n "$BROWSER" ]] || { echo "error: --browser requires auto, all, both, or a comma-separated list of browser keys" >&2; exit 1; }
      shift 2
      ;;
    --nm-dir)
      [[ -n "${2:-}" ]] || { echo "error: --nm-dir requires a directory path" >&2; exit 1; }
      NM_DIRS_EXPLICIT+=("$2")
      shift 2
      ;;
    --skip-extension-build)
      SKIP_EXTENSION_BUILD=1
      shift
      ;;
    --register-claude-code)
      REGISTER_CLAUDE=1
      shift
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    --expected-sha256)
      EXPECTED_SHA256="$(printf '%s' "${2:-}" | tr '[:upper:]' '[:lower:]')"
      [[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
        echo "error: --expected-sha256 requires a 64-character hex SHA-256 digest" >&2
        exit 1
      }
      shift 2
      ;;
    --release-repo)
      RELEASE_REPO="${2:-}"
      [[ "$RELEASE_REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || {
        echo "error: --release-repo requires OWNER/REPO" >&2
        exit 1
      }
      shift 2
      ;;
    -h|--help)
      sed -n '2,47p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

[[ "$EXTENSION_ID" =~ ^[a-p]{32}$ ]] || {
  echo "error: extension id must be 32 characters in the range a-p" >&2
  exit 1
}

OS="$(uname -s)"
declare -a NM_DIRS=()
# Install targets as parallel arrays (bash 3.2 has no associative arrays):
# TARGET_KEYS[i] is the browser key whose label the wrapper bakes in ("" for an
# explicit --nm-dir whose browser is unknown), TARGET_DIRS[i] the matching
# NativeMessagingHosts dir.
declare -a TARGET_KEYS=()
declare -a TARGET_DIRS=()
# Candidate per-user runtime/data dirs where the MCP server may have written its
# run.lock (mirrors LockFile::path() in src/ipc.rs). Only used by --uninstall,
# and only the exact file "run.lock" is ever removed from them.
declare -a LOCK_DIRS=()
case "$OS" in
  Darwin)
    INSTALL_DIR="${BB_INSTALL_DIR:-$HOME/.chromium-bridge}"
    [[ -n "${XDG_RUNTIME_DIR:-}" ]] && LOCK_DIRS+=("$XDG_RUNTIME_DIR/chromium-bridge")
    LOCK_DIRS+=("$HOME/Library/Application Support/chromium-bridge")
    ;;
  Linux)
    INSTALL_DIR="${BB_INSTALL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/chromium-bridge}"
    CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
    [[ -n "${XDG_RUNTIME_DIR:-}" ]] && LOCK_DIRS+=("$XDG_RUNTIME_DIR/chromium-bridge")
    [[ -n "${XDG_CACHE_HOME:-}" ]] && LOCK_DIRS+=("$XDG_CACHE_HOME/chromium-bridge")
    LOCK_DIRS+=("$HOME/.cache/chromium-bridge")
    ;;
  *)
    echo "error: unsupported platform: $OS (use install.ps1 on Windows)" >&2
    exit 1
    ;;
esac

# ---- Chromium browser table ----------------------------------------------
# Every Chromium build reads an identical native-messaging manifest (same pinned
# extension ID + allowed_origins); only the per-user NativeMessagingHosts dir
# differs. This table is the single source of truth for the browsers we know by
# name; the --nm-dir escape hatch targets any Chromium browser not listed here.
BB_BROWSER_KEYS="chrome chromium brave edge vivaldi opera"

# Echo the NativeMessagingHosts dir for browser $1 on this OS, or return 1 for an
# unknown key. macOS and Linux entries stay in the same order as BB_BROWSER_KEYS.
bb_nm_dir_for() {
  case "$OS" in
    Darwin)
      case "$1" in
        chrome)   echo "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts" ;;
        chromium) echo "$HOME/Library/Application Support/Chromium/NativeMessagingHosts" ;;
        brave)    echo "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts" ;;
        edge)     echo "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts" ;;
        vivaldi)  echo "$HOME/Library/Application Support/Vivaldi/NativeMessagingHosts" ;;
        opera)    echo "$HOME/Library/Application Support/com.operasoftware.Opera/NativeMessagingHosts" ;;
        *) return 1 ;;
      esac
      ;;
    Linux)
      case "$1" in
        chrome)   echo "$CONFIG_HOME/google-chrome/NativeMessagingHosts" ;;
        chromium) echo "$CONFIG_HOME/chromium/NativeMessagingHosts" ;;
        brave)    echo "$CONFIG_HOME/BraveSoftware/Brave-Browser/NativeMessagingHosts" ;;
        edge)     echo "$CONFIG_HOME/microsoft-edge/NativeMessagingHosts" ;;
        vivaldi)  echo "$CONFIG_HOME/vivaldi/NativeMessagingHosts" ;;
        opera)    echo "$CONFIG_HOME/opera/NativeMessagingHosts" ;;
        *) return 1 ;;
      esac
      ;;
  esac
}

# Resolve a --browser selector into a space-separated list of table keys:
#   all  -> every known browser
#   both -> chrome chromium (backward-compatible alias)
#   auto -> browsers whose config dir (the parent of the NM dir) already exists;
#           falls back to chrome so a fresh machine still gets a working manifest
#   else -> a comma-separated list of table keys, each validated
# Prints the keys on stdout; on an unknown key prints an error and returns 1.
bb_resolve_selection() {
  case "$1" in
    all)  echo "$BB_BROWSER_KEYS" ;;
    both) echo "chrome chromium" ;;
    auto)
      local key found=""
      for key in $BB_BROWSER_KEYS; do
        [[ -d "$(dirname "$(bb_nm_dir_for "$key")")" ]] && found="$found $key"
      done
      if [[ -n "$found" ]]; then
        echo "$found"
      else
        echo "[install] no Chromium browser config dir found; defaulting to Google Chrome" >&2
        echo chrome
      fi
      ;;
    *)
      local IFS=', ' key out=""
      for key in $1; do
        [[ -n "$key" ]] || continue
        bb_nm_dir_for "$key" >/dev/null 2>&1 || { echo "error: unknown --browser key: '$key'" >&2; return 1; }
        out="$out $key"
      done
      [[ -n "$out" ]] || { echo "error: --browser selected no known browser: '$1'" >&2; return 1; }
      echo "$out"
      ;;
  esac
}

# Collect explicit target dirs: --nm-dir (repeatable) and the BB_NM_DIR env
# override. These are the escape hatch for a Chromium browser not in the table.
declare -a EXPLICIT_DIRS=()
[[ -n "${BB_NM_DIR:-}" ]] && EXPLICIT_DIRS+=("$BB_NM_DIR")
if [[ ${#NM_DIRS_EXPLICIT[@]} -gt 0 ]]; then
  EXPLICIT_DIRS+=("${NM_DIRS_EXPLICIT[@]}")
fi

if [[ "$UNINSTALL" == "1" ]]; then
  # Uninstall removes the shared binary + wrappers, so every manifest that could
  # point at them must go: every known browser dir plus any explicit dir. The
  # manifest is uniquely named for this project, so scanning all of them is safe.
  read -ra ALL_KEYS <<< "$BB_BROWSER_KEYS"
  for key in "${ALL_KEYS[@]}"; do NM_DIRS+=("$(bb_nm_dir_for "$key")"); done
  if [[ ${#EXPLICIT_DIRS[@]} -gt 0 ]]; then
    NM_DIRS+=("${EXPLICIT_DIRS[@]}")
  fi
elif [[ ${#EXPLICIT_DIRS[@]} -gt 0 ]]; then
  # Explicit dirs take over install selection; --browser is ignored. The
  # browser behind an explicit dir is unknown, so these registrations use the
  # unlabeled wrapper (the MCP server files that connection under "default").
  for dir in "${EXPLICIT_DIRS[@]}"; do
    TARGET_KEYS+=("")
    TARGET_DIRS+=("$dir")
  done
else
  SELECTION="$(bb_resolve_selection "$BROWSER")" || exit 1
  read -ra SELECTED_KEYS <<< "$SELECTION"
  for key in "${SELECTED_KEYS[@]}"; do
    TARGET_KEYS+=("$key")
    TARGET_DIRS+=("$(bb_nm_dir_for "$key")")
  done
fi

# ---- uninstall ------------------------------------------------------------
# Reverses exactly what the install path above lays down: the binary and
# run-host wrappers in INSTALL_DIR, the native-host manifest in each NM_DIR,
# and the run.lock the server writes. Idempotent, prints every removal, never
# uses wildcards, never touches a process or the browser, and never removes
# anything this project did not create.

if [[ "$UNINSTALL" == "1" ]]; then
  echo "[uninstall] removing chromium-bridge artifacts on $OS"
  removed=0

  # Native-host manifest(s) - the file we wrote, named uniquely for this project.
  for NM_DIR in "${NM_DIRS[@]}"; do
    MANIFEST="$NM_DIR/$HOST_NAME.json"
    if [[ -f "$MANIFEST" ]]; then
      rm -f "$MANIFEST"
      echo "[uninstall] removed host manifest: $MANIFEST"
      removed=1
    else
      echo "[uninstall] not present: $MANIFEST"
    fi
  done

  # Binary + native-host wrappers we placed in INSTALL_DIR: the unlabeled
  # run-host.sh plus one run-host-<browser>.sh per known browser key. Exact,
  # project-unique names only, never a glob; -L catches a dangling symlink
  # left at a managed name.
  declare -a INSTALL_ARTIFACTS=("$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/run-host.sh")
  for key in $BB_BROWSER_KEYS; do
    INSTALL_ARTIFACTS+=("$INSTALL_DIR/run-host-$key.sh")
  done
  for artifact in "${INSTALL_ARTIFACTS[@]}"; do
    if [[ -e "$artifact" || -L "$artifact" ]]; then
      rm -f "$artifact"
      echo "[uninstall] removed: $artifact"
      removed=1
    else
      echo "[uninstall] not present: $artifact"
    fi
  done
  # INSTALL_DIR is created by this installer; drop it only when now empty. rmdir
  # (never rm -r) guarantees we never delete unrelated files a user may have put
  # there.
  if [[ -d "$INSTALL_DIR" ]]; then
    if rmdir "$INSTALL_DIR" 2>/dev/null; then
      echo "[uninstall] removed empty dir: $INSTALL_DIR"
    fi
  fi

  # Runtime lock file the MCP server writes. Remove the exact file "run.lock"
  # from each candidate dir (no globbing), then drop the dir if it is now empty.
  for LOCK_DIR in "${LOCK_DIRS[@]}"; do
    LOCK="$LOCK_DIR/run.lock"
    if [[ -f "$LOCK" ]]; then
      rm -f "$LOCK"
      echo "[uninstall] removed lock file: $LOCK"
      removed=1
    fi
    if [[ -d "$LOCK_DIR" ]]; then
      rmdir "$LOCK_DIR" 2>/dev/null || true
    fi
  done

  if [[ "$removed" == "0" ]]; then
    echo "[uninstall] nothing to remove - already clean"
  fi
  echo "[uninstall] done. Your browser and the loaded extension were left untouched;"
  echo "[uninstall] if you loaded the unpacked extension, remove it yourself via"
  echo "[uninstall] chrome://extensions."
  exit 0
fi

# ---- prebuilt binary verification ------------------------------------------
# Prebuilt mode installs a binary this script did not just build, so prove it
# is byte-identical to what the release pipeline published BEFORE it is
# installed (and before the macOS quarantine attribute is cleared).
# Verification is mandatory in prebuilt mode and fails closed: no reference
# checksum, no install. The reference hash comes from one of
#   - --expected-sha256: supplied by the user, obtained out of band, or
#   - the release's published <name>.binary.sha256 asset, fetched over HTTPS
#     from the repo/tag recorded in RELEASE.txt inside the archive.
# RELEASE.txt is untrusted input: it names the tag/platform/arch so the right
# published checksum can be fetched, and its repo field is cross-checked
# against the pinned canonical repository (or an explicit --release-repo),
# never used as a trust anchor itself. A tampered archive cannot redirect
# verification to a repository it controls; its binary has to hash to a value
# the TRUSTED repository serves for that release. When gh is installed and
# authenticated, the binary's build provenance attestation is verified as
# well, and a failed attestation aborts the install. What this cannot defend
# against: an archive whose install.sh was itself replaced (verify the
# archive's published .sha256 or attestation yourself before running it; see
# README "Verifying your binary"), or a hostile process already running as
# this user. Full signature/cdhash verification arrives with the code-signing
# pipeline (see SECURITY.md).

bb_sha256() { # $1 = file; prints the lowercase hex digest
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    echo "error: neither shasum nor sha256sum found; cannot verify the prebuilt binary" >&2
    return 1
  fi
}

bb_release_field() { # $1 = key, $2 = anchored allowed-value regex; prints value
  local value
  value="$(sed -n "s/^$1=//p" "$ROOT/RELEASE.txt" | head -n 1)"
  [[ "$value" =~ $2 ]] || {
    echo "error: RELEASE.txt is missing a valid '$1' field; refusing to install an unverifiable binary" >&2
    return 1
  }
  printf '%s\n' "$value"
}

bb_verify_prebuilt() { # $1 = the exact file that will be installed
  local file="$1" actual expected reference repo tag platform arch name url tmp
  actual="$(bb_sha256 "$file")" || return 1

  if [[ -n "$EXPECTED_SHA256" ]]; then
    expected="$EXPECTED_SHA256"
    reference="--expected-sha256 (supplied by you)"
  else
    if [[ ! -f "$ROOT/RELEASE.txt" ]]; then
      cat >&2 <<'EOF'
error: cannot verify the prebuilt binary: RELEASE.txt not found in the archive.
This archive predates published per-binary checksums (or was repacked).
Either:
  - verify the downloaded archive against its published .sha256 yourself,
    compute the binary's hash, and re-run with --expected-sha256 <hash>, or
  - build from source instead (git clone, then ./install/install.sh).
Refusing to install an unverified binary.
EOF
      return 1
    fi
    repo="$(bb_release_field repo '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$')" || return 1
    tag="$(bb_release_field tag '^v[0-9A-Za-z._-]+$')" || return 1
    platform="$(bb_release_field platform '^[a-z0-9]+$')" || return 1
    arch="$(bb_release_field arch '^[a-z0-9]+$')" || return 1
    # The archive's repo field must match the repository we trust; it never
    # gets to pick one. Mismatch means this archive was published by a fork
    # (or tampered with) - installing it requires an explicit opt-in.
    if [[ "$repo" != "$RELEASE_REPO" ]]; then
      echo "error: this archive says it was published by '$repo', but checksums are" >&2
      echo "error: only trusted from '$RELEASE_REPO'. If you deliberately downloaded" >&2
      echo "error: that repository's release and trust it, re-run with:" >&2
      echo "error:   --release-repo $repo" >&2
      echo "error: Refusing to install." >&2
      return 1
    fi
    name="chromium-bridge-$tag-$platform-$arch"

    command -v curl >/dev/null 2>&1 || {
      echo "error: curl is required to fetch the published checksum (or pass --expected-sha256)" >&2
      return 1
    }
    url="https://github.com/$RELEASE_REPO/releases/download/$tag/$name.binary.sha256"
    tmp="$(mktemp)"
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp" "$url"; then
      rm -f "$tmp"
      echo "error: could not download the published checksum from $url" >&2
      echo "error: refusing to install without verification. Retry with network access," >&2
      echo "error: or pass --expected-sha256 with a hash you verified out of band." >&2
      return 1
    fi
    expected="$(awk 'NR==1{print tolower($1)}' "$tmp")"
    rm -f "$tmp"
    reference="$url"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || {
      echo "error: the downloaded checksum file is not a SHA-256 digest; refusing to install" >&2
      return 1
    }
  fi

  if [[ "$actual" != "$expected" ]]; then
    echo "error: CHECKSUM MISMATCH for the prebuilt binary - REFUSING TO INSTALL." >&2
    echo "error:   file:      $BIN_SRC" >&2
    echo "error:   actual:    $actual" >&2
    echo "error:   expected:  $expected" >&2
    echo "error:   reference: $reference" >&2
    echo "error: The binary is not the one the release published. Re-download the" >&2
    echo "error: archive from the official release page; if this persists, report it." >&2
    return 1
  fi
  echo "[verify] binary sha256 OK: $actual"
  echo "[verify]   reference: $reference"

  # Build provenance is the INDEPENDENT trust anchor for the online path. The
  # checksum matched just above was fetched from the SAME GitHub Release as the
  # binary, so an attacker who can swap the release asset can swap its published
  # checksum too: the checksum alone is a corruption check, never proof of
  # origin. When no out-of-band --expected-sha256 was supplied, a SUCCESSFUL gh
  # attestation verify is therefore REQUIRED. It checks GitHub's signed build
  # provenance (Sigstore-backed, in a transparency log), which a release-asset
  # swap cannot forge. Fail closed if gh is missing, unauthenticated, or the
  # attestation does not verify. The out-of-band --expected-sha256 path stays
  # gh-free because that hash is itself the independent anchor.
  if [[ -z "$EXPECTED_SHA256" ]]; then
    if ! command -v gh >/dev/null 2>&1 \
      || ! gh attestation --help >/dev/null 2>&1 \
      || ! gh auth status >/dev/null 2>&1; then
      echo "error: cannot independently verify this binary. The release checksum shares" >&2
      echo "error: its origin with the binary, so on its own it is not proof of authenticity." >&2
      echo "error: Install and authenticate the GitHub CLI (gh) so its build-provenance" >&2
      echo "error: attestation can be checked, OR re-run with --expected-sha256 <hash from" >&2
      echo "error: the release notes, obtained out of band>. Refusing to install." >&2
      return 1
    fi
    echo "[verify] checking build provenance attestation via gh..."
    if gh attestation verify "$file" --repo "$RELEASE_REPO" >&2; then
      echo "[verify] build provenance attestation OK"
    else
      echo "error: build provenance attestation FAILED for this binary (repo $RELEASE_REPO)." >&2
      echo "error: GitHub has no valid attestation for these bytes. Refusing to install." >&2
      return 1
    fi
  fi
}

# ---- source vs prebuilt ---------------------------------------------------
# Source checkout (Cargo.toml present) → build the binary + extension.
# Prebuilt release tarball (no Cargo.toml) → use the shipped chromium-bridge and
# extension/dist as-is; no Rust/Node needed.

# Locate a cargo binary (PATH, then the common Homebrew / rustup spots), set
# BB_CARGO to its absolute path, and prepend its directory to PATH so the
# rustc it shells out to is discoverable. Call it as a plain statement (NOT
# `$(bb_find_cargo)`) - the PATH export must happen in this shell, not a
# command-substitution subshell.
bb_find_cargo() {
  local candidate
  BB_CARGO=""
  for candidate in cargo /opt/homebrew/bin/cargo "$HOME/.cargo/bin/cargo"; do
    if command -v "$candidate" >/dev/null 2>&1; then
      BB_CARGO="$(command -v "$candidate")"
      break
    fi
  done
  [[ -n "$BB_CARGO" ]] || {
    echo "error: cargo not found. Install Rust (https://rustup.rs) or fix PATH." >&2
    exit 2
  }
  export BB_CARGO
  local dir
  dir="$(dirname "$BB_CARGO")"
  if [[ ":$PATH:" != *":$dir:"* ]]; then
    export PATH="$dir:$PATH"
  fi
}

if [[ -f "$ROOT/Cargo.toml" ]]; then
  PREBUILT=0
  [[ -z "$EXPECTED_SHA256" ]] || {
    echo "error: --expected-sha256 only applies to a prebuilt release archive (this is a source checkout)" >&2
    exit 1
  }
  bb_find_cargo # sets BB_CARGO + puts its dir on PATH (plain call, not subshell)
  echo "[install] source mode - building with $BB_CARGO"
  "$BB_CARGO" build --release --manifest-path "$ROOT/Cargo.toml"
  BIN_SRC="$ROOT/target/release/$BINARY_NAME"

  if [[ "$SKIP_EXTENSION_BUILD" == "1" ]]; then
    DIST_DIR="$ROOT/extension/dist"
    [[ -d "$DIST_DIR" ]] || {
      echo "error: --skip-extension-build requires an existing $DIST_DIR" >&2
      exit 1
    }
    echo "[install] reusing existing extension bundle at $DIST_DIR"
  else
    if ! command -v bun >/dev/null 2>&1; then
      echo "error: bun is needed to build the extension (https://bun.sh)." >&2
      echo "       Install bun, or build extension/dist elsewhere and pass --skip-extension-build." >&2
      exit 1
    fi
    echo "[install] building extension bundle (esbuild)..."
    [[ -d "$ROOT/node_modules" ]] || (cd "$ROOT" && bun install --frozen-lockfile)
    (cd "$ROOT/extension" && bun run build)
    DIST_DIR="$ROOT/extension/dist"
  fi
else
  PREBUILT=1
  echo "[install] prebuilt mode - using shipped binary + extension (no build)"
  BIN_SRC="$ROOT/$BINARY_NAME"
  DIST_DIR="$ROOT/extension/dist"
  [[ -f "$BIN_SRC" ]] || { echo "error: prebuilt binary not found at $BIN_SRC" >&2; exit 1; }
  [[ -d "$DIST_DIR" ]] || { echo "error: extension/dist not found at $DIST_DIR" >&2; exit 1; }
fi

# ---- install binary -------------------------------------------------------

mkdir -p "$INSTALL_DIR"
# Owner-only, enforced rather than left to umask: this dir holds the binary and
# the run-host wrappers the browser launches, so a group- or world-writable mode
# would let another account swap them out. Matches ensure_private_dir (0700) in
# src/ipc.rs. The browser runs as this same user, so it can still traverse here.
chmod 0700 "$INSTALL_DIR"
TMP_BIN="$INSTALL_DIR/$BINARY_NAME.tmp.$$"
cp "$BIN_SRC" "$TMP_BIN"
chmod 0755 "$TMP_BIN"
# Verify the private copy, not the source file: the bytes checked are exactly
# the bytes installed, so nothing can swap the source between check and use.
if [[ "$PREBUILT" == "1" ]]; then
  bb_verify_prebuilt "$TMP_BIN" || { rm -f "$TMP_BIN"; exit 1; }
fi
mv -f "$TMP_BIN" "$INSTALL_DIR/$BINARY_NAME"
echo "[install] binary installed at $INSTALL_DIR/$BINARY_NAME"

# macOS: a browser-downloaded prebuilt binary carries the com.apple.quarantine
# xattr, which the copy above inherits. Chrome spawns this binary via the native
# messaging host, and Gatekeeper can then silently block the (unsigned,
# not-yet-notarized) launch. Clear the attribute on the installed copy so the
# host starts. This point is only reached AFTER bb_verify_prebuilt has passed:
# online, a matching published checksum AND a successful build-provenance
# attestation; offline, the out-of-band --expected-sha256. So the attribute is
# never cleared on unverified bytes. Best-effort: the source-built binary has
# no such attribute, and `xattr` may be absent, so never fail the install on
# this. This is a stopgap until the release binary is notarized.
if [[ "$OS" == "Darwin" ]] && command -v xattr >/dev/null 2>&1; then
  if xattr -p com.apple.quarantine "$INSTALL_DIR/$BINARY_NAME" >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null \
      && echo "[install] cleared com.apple.quarantine (Gatekeeper) on the binary"
  fi
fi

# ---- host manifest --------------------------------------------------------

# Chrome native-messaging manifests have no `args` field, so Unix installs use
# a tiny wrapper to select the binary's native-host mode. Each browser gets its
# OWN wrapper (run-host-<browser>.sh) baking in `--label <browser>`: the label
# rides in the authenticated bridge handshake, letting one MCP server keep
# every browser attached at once and address them by name (see the
# list_browsers tool). Explicit --nm-dir targets (browser unknown) get the
# unlabeled run-host.sh, which the server files under its "default" slot.
bb_write_wrapper() { # $1 = wrapper path, $2 = label ("" = no label)
  # %q-escape everything baked into executable text. Write via mktemp (0600,
  # exclusive create - never follows a planted symlink) + chmod + atomic mv,
  # so the final path is replaced, never written through.
  local exec_line tmp
  exec_line="exec $(printf '%q' "$INSTALL_DIR/$BINARY_NAME") --native-host"
  if [[ -n "$2" ]]; then
    exec_line="$exec_line --label $(printf '%q' "$2")"
  fi
  tmp="$(mktemp "$1.tmp.XXXXXX")"
  printf '#!/usr/bin/env bash\n%s\n' "$exec_line" > "$tmp" || { rm -f "$tmp"; return 1; }
  chmod 0755 "$tmp"
  mv -f "$tmp" "$1"
}

# allowed_origins pins the extension ID (fixed via the manifest key).
ORIGINS="[\"chrome-extension://$EXTENSION_ID/\"]"

for i in "${!TARGET_DIRS[@]}"; do
  KEY="${TARGET_KEYS[$i]}"
  NM_DIR="${TARGET_DIRS[$i]}"
  if [[ -n "$KEY" ]]; then
    WRAPPER="$INSTALL_DIR/run-host-$KEY.sh"
  else
    WRAPPER="$INSTALL_DIR/run-host.sh"
  fi
  bb_write_wrapper "$WRAPPER" "$KEY"
  mkdir -p "$NM_DIR"
  MANIFEST="$NM_DIR/$HOST_NAME.json"
  cat > "$MANIFEST" <<EOF
{
  "name": "$HOST_NAME",
  "description": "Chromium Bridge native messaging host",
  "path": "$WRAPPER",
  "type": "stdio",
  "allowed_origins": $ORIGINS
}
EOF
  chmod 0644 "$MANIFEST"
  echo "[install] host manifest written to $MANIFEST"
  echo "[install]   launches: $WRAPPER${KEY:+ (label: $KEY)}"
done
echo "[install]   allowed_origins: $ORIGINS"

# The MCP server command every client points at (absolute; no PATH/~ needed).
SERVER_CMD="$INSTALL_DIR/$BINARY_NAME"

# Optionally register with Claude Code through its official CLI - the only safe
# auto-writer. We never hand-edit a client's JSON/TOML config; for the other
# clients we print a ready-to-paste block with the path already filled in.
CLAUDE_HINT="(re-run with --register-claude-code to add this automatically)"
if command -v claude >/dev/null 2>&1; then
  if [[ "$REGISTER_CLAUDE" == "1" ]]; then
    if claude mcp list 2>/dev/null | grep -q 'chromium-bridge'; then
      echo "[install] Claude Code already has 'chromium-bridge' - left as is"
      CLAUDE_HINT="(already registered ✓)"
    elif claude mcp add chromium-bridge -- "$SERVER_CMD" >/dev/null 2>&1; then
      echo "[install] registered 'chromium-bridge' with Claude Code"
      CLAUDE_HINT="(added automatically ✓)"
    else
      echo "[install] warning: 'claude mcp add' failed - add it by hand (below)" >&2
      CLAUDE_HINT="(auto-add failed - run the command below)"
    fi
  fi
else
  CLAUDE_HINT="(install the claude CLI to use --register-claude-code)"
fi

cat <<TIP

────────────────────────────────────────────────────────────────────
NEXT STEPS  (no extension-ID copying - it's pinned to $EXTENSION_ID)
────────────────────────────────────────────────────────────────────
1. Load the extension:
   - Open chrome://extensions → enable "Developer mode" (top right)
   - "Load unpacked" → select: $DIST_DIR
   (Verify the ID under the name is $EXTENSION_ID - the manifest already
    trusts it, so nothing to patch.)

2. Register the MCP server with your client. The binary is at:
     $SERVER_CMD
   (run with no arguments; speaks MCP over stdio). Config below already has the
   absolute path filled in - just paste:

   • Claude Code (CLI):
       claude mcp add chromium-bridge -- "$SERVER_CMD"
       $CLAUDE_HINT

   • Claude Desktop / generic MCP client (mcpServers JSON):
       "chromium-bridge": { "command": "$SERVER_CMD", "args": [] }

   • Codex (~/.codex/config.toml):
       [mcp_servers.chromium-bridge]
       command = "$SERVER_CMD"
       args = []

3. Restart Chrome (so it picks up the native messaging host manifest).

4. In your MCP client, try "list my browser tabs". Approve new sites via the
   Chromium Bridge toolbar icon when prompted.
TIP
