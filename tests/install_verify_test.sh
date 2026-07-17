#!/usr/bin/env bash
# install_verify_test.sh - prove install.sh's prebuilt-mode verification
# passes on a matching checksum and FAILS CLOSED on everything else.
#
# Fully isolated: runs against a fake release layout in a temp dir with HOME,
# BB_INSTALL_DIR, and --nm-dir all pointed inside it, and the network replaced
# by PATH stubs (a `curl` that serves local fixture files and records the URL
# it was asked for, and a controllable `gh` driven by $GH_MODE so the mandatory
# online attestation check can be made to pass, fail, or be unavailable). No
# real network, no real browser profile, no real ~/.browser-bridge is touched.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_SH="$REPO_ROOT/install/install.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

TAG="v9.9.9"
PLATFORM="testos"
ARCH="testarch"
NAME="browser-bridge-$TAG-$PLATFORM-$ARCH"
# The repo the fake archives claim to come from. It differs from the repo
# pinned in install.sh, so tests must opt in with --release-repo, and one
# case below proves that omitting the opt-in fails closed.
FAKE_REPO="example-org/browser-bridge-test"

# ---- network stubs ----------------------------------------------------------
# `curl`: serves $CURL_STUB_DIR/<url basename> into the -o target and records
# the requested URL in $CURL_STUB_DIR/last-url; exits 22 (like --fail on 404)
# when the fixture is missing. `gh`: a controllable stub driven by $GH_MODE -
# "ok" (available, attestation verifies), "attest-fail" (available, attestation
# verify fails), or "unavailable" (every call fails, as if gh is not installed).
mkdir -p "$TMP/bin"
cat > "$TMP/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
out="" url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--proto) [[ "$1" == "-o" ]] && out="$2" || true; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" > "$CURL_STUB_DIR/last-url"
fixture="$CURL_STUB_DIR/$(basename "$url")"
[[ -f "$fixture" ]] || exit 22
cp "$fixture" "$out"
STUB
cat > "$TMP/bin/gh" <<'STUB'
#!/usr/bin/env bash
# Controllable gh stub. $GH_MODE selects behavior:
#   ok           availability probes succeed AND `attestation verify` succeeds
#   attest-fail  probes succeed but `attestation verify` fails (bad provenance)
#   unavailable  every call fails, as if gh were not usable
case "${GH_MODE:-unavailable}" in
  ok)
    exit 0 ;;
  attest-fail)
    [[ "${1:-}" == "attestation" && "${2:-}" == "verify" ]] && exit 1
    exit 0 ;;
  *) exit 1 ;;
esac
STUB
chmod 0755 "$TMP/bin/curl" "$TMP/bin/gh"

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

# Lay out a fake extracted release archive in $1.
make_pkg() {
  local dir="$1"
  mkdir -p "$dir/extension/dist"
  echo "fake extension bundle" > "$dir/extension/dist/marker.js"
  # Unique content per test run so a stale artifact can never match.
  printf 'fake-binary %s %s\n' "$RANDOM" "$(date +%s%N 2>/dev/null || date +%s)" > "$dir/browser-bridge"
  chmod 0755 "$dir/browser-bridge"
  {
    echo "repo=$FAKE_REPO"
    echo "tag=$TAG"
    echo "platform=$PLATFORM"
    echo "arch=$ARCH"
  } > "$dir/RELEASE.txt"
  cp "$INSTALL_SH" "$dir/install.sh"
  chmod 0755 "$dir/install.sh"
}

# Run the installer in prebuilt mode inside an isolated environment.
# $1 = case dir (fresh per case), remaining args are passed to install.sh.
run_install() {
  local case_dir="$1"
  shift
  mkdir -p "$case_dir/home" "$case_dir/nm" "$case_dir/assets"
  (
    cd "$case_dir/pkg"
    PATH="$TMP/bin:$PATH" \
    CURL_STUB_DIR="$case_dir/assets" \
    GH_MODE="${GH_MODE:-ok}" \
    HOME="$case_dir/home" \
    BB_INSTALL_DIR="$case_dir/install" \
    XDG_DATA_HOME="$case_dir/home/.local/share" \
    XDG_CONFIG_HOME="$case_dir/home/.config" \
      ./install.sh --nm-dir "$case_dir/nm" --skip-extension-build "$@"
  )
}

installed_binary() { echo "$1/install/browser-bridge"; }

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

pass() { echo "PASS: $1"; }

new_case() { # $1 = case name; prints the case dir
  local dir="$TMP/$1"
  mkdir -p "$dir"
  make_pkg "$dir/pkg"
  echo "$dir"
}

publish_checksum() { # $1 = case dir, $2 = hash to publish
  mkdir -p "$1/assets"
  printf '%s  browser-bridge\n' "$2" > "$1/assets/$NAME.binary.sha256"
}

# ---- 1. matching published checksum installs (and hits the right URL) -------
# Online path (no --expected-sha256): the same-origin checksum matches AND the
# mandatory build-provenance attestation verifies (GH_MODE=ok), so it installs.
dir="$(new_case match)"
hash="$(sha256_of "$dir/pkg/browser-bridge")"
publish_checksum "$dir" "$hash"
out="$(run_install "$dir" --release-repo "$FAKE_REPO" 2>&1)" \
  || fail "matching checksum: installer exited nonzero: $out"
[[ -x "$(installed_binary "$dir")" ]] || fail "matching checksum: binary not installed"
[[ "$(sha256_of "$(installed_binary "$dir")")" == "$hash" ]] \
  || fail "matching checksum: installed bytes differ from verified bytes"
[[ -f "$dir/nm/com.browser_bridge.host.json" ]] || fail "matching checksum: host manifest missing"
grep -q "binary sha256 OK" <<< "$out" || fail "matching checksum: no verification line in output"
grep -q "build provenance attestation OK" <<< "$out" \
  || fail "matching checksum: attestation was not enforced on the online path"
want_url="https://github.com/$FAKE_REPO/releases/download/$TAG/$NAME.binary.sha256"
[[ "$(cat "$dir/assets/last-url")" == "$want_url" ]] \
  || fail "matching checksum: fetched $(cat "$dir/assets/last-url"), wanted $want_url"
pass "matching published checksum + attestation installs, fetched from the pinned release URL"

# ---- 2. mismatching published checksum refuses ------------------------------
dir="$(new_case mismatch)"
publish_checksum "$dir" "0000000000000000000000000000000000000000000000000000000000000000"
if out="$(run_install "$dir" --release-repo "$FAKE_REPO" 2>&1)"; then
  fail "mismatch: installer succeeded on a wrong checksum"
fi
grep -q "CHECKSUM MISMATCH" <<< "$out" || fail "mismatch: no mismatch error: $out"
[[ ! -e "$(installed_binary "$dir")" ]] || fail "mismatch: binary was installed anyway"
[[ ! -e "$dir/nm/com.browser_bridge.host.json" ]] || fail "mismatch: host manifest written anyway"
pass "mismatching checksum fails closed (nothing installed)"

# ---- 3. archive from an unpinned repo refuses without --release-repo --------
dir="$(new_case fork-repo)"
hash="$(sha256_of "$dir/pkg/browser-bridge")"
publish_checksum "$dir" "$hash" # even a matching checksum must not save it
if out="$(run_install "$dir" 2>&1)"; then
  fail "fork repo: installer trusted a repo not pinned in install.sh"
fi
grep -q "only trusted from" <<< "$out" || fail "fork repo: wrong error: $out"
[[ ! -e "$(installed_binary "$dir")" ]] || fail "fork repo: binary installed anyway"
pass "archive naming an unpinned repo fails closed without --release-repo"

# ---- 4. missing RELEASE.txt refuses -----------------------------------------
dir="$(new_case no-meta)"
rm "$dir/pkg/RELEASE.txt"
if out="$(run_install "$dir" 2>&1)"; then
  fail "no RELEASE.txt: installer succeeded without any reference checksum"
fi
grep -q "RELEASE.txt not found" <<< "$out" || fail "no RELEASE.txt: wrong error: $out"
[[ ! -e "$(installed_binary "$dir")" ]] || fail "no RELEASE.txt: binary installed anyway"
pass "missing RELEASE.txt fails closed"

# ---- 5. malformed RELEASE.txt field refuses ---------------------------------
dir="$(new_case bad-meta)"
sed -i.bak 's|^repo=.*|repo=../../evil|' "$dir/pkg/RELEASE.txt" && rm -f "$dir/pkg/RELEASE.txt.bak"
if out="$(run_install "$dir" 2>&1)"; then
  fail "bad repo field: installer succeeded"
fi
grep -q "missing a valid 'repo' field" <<< "$out" || fail "bad repo field: wrong error: $out"
pass "malformed RELEASE.txt repo field fails closed"

# ---- 6. unreachable checksum URL refuses ------------------------------------
dir="$(new_case no-asset)"
# assets dir exists (created by run_install) but the checksum fixture does not
if out="$(run_install "$dir" --release-repo "$FAKE_REPO" 2>&1)"; then
  fail "missing checksum asset: installer succeeded"
fi
grep -q "could not download the published checksum" <<< "$out" \
  || fail "missing checksum asset: wrong error: $out"
[[ ! -e "$(installed_binary "$dir")" ]] || fail "missing checksum asset: binary installed anyway"
pass "unreachable published checksum fails closed"

# ---- 7. --expected-sha256 works offline -------------------------------------
dir="$(new_case expected-ok)"
rm "$dir/pkg/RELEASE.txt" # prove no metadata/network is needed on this path
hash="$(sha256_of "$dir/pkg/browser-bridge")"
out="$(run_install "$dir" --expected-sha256 "$hash" 2>&1)" \
  || fail "--expected-sha256 match: installer exited nonzero: $out"
[[ -x "$(installed_binary "$dir")" ]] || fail "--expected-sha256 match: binary not installed"
[[ ! -e "$dir/assets/last-url" ]] || fail "--expected-sha256 match: unexpected download attempt"
pass "--expected-sha256 (offline) verifies and installs without fetching"

# ---- 8. --expected-sha256 mismatch refuses ----------------------------------
dir="$(new_case expected-bad)"
if out="$(run_install "$dir" --expected-sha256 \
  "1111111111111111111111111111111111111111111111111111111111111111" 2>&1)"; then
  fail "--expected-sha256 mismatch: installer succeeded"
fi
grep -q "CHECKSUM MISMATCH" <<< "$out" || fail "--expected-sha256 mismatch: wrong error: $out"
[[ ! -e "$(installed_binary "$dir")" ]] || fail "--expected-sha256 mismatch: binary installed anyway"
pass "--expected-sha256 mismatch fails closed"

# ---- 9. malformed --expected-sha256 rejected at parse time -------------------
dir="$(new_case expected-malformed)"
if out="$(run_install "$dir" --expected-sha256 "not-a-hash" 2>&1)"; then
  fail "malformed --expected-sha256: installer succeeded"
fi
grep -q "64-character hex" <<< "$out" || fail "malformed --expected-sha256: wrong error: $out"
pass "malformed --expected-sha256 rejected"

# ---- 10. malformed --release-repo rejected at parse time ---------------------
dir="$(new_case repo-malformed)"
if out="$(run_install "$dir" --release-repo "https://evil.example/x" 2>&1)"; then
  fail "malformed --release-repo: installer succeeded"
fi
grep -q "requires OWNER/REPO" <<< "$out" || fail "malformed --release-repo: wrong error: $out"
pass "malformed --release-repo rejected"

# ---- 11. --help still renders the full usage block ---------------------------
help_out="$("$INSTALL_SH" --help)"
grep -q -- "--expected-sha256" <<< "$help_out" || fail "--help does not mention --expected-sha256"
grep -q -- "--release-repo" <<< "$help_out" || fail "--help does not mention --release-repo"
grep -q "loaded extension untouched" <<< "$help_out" || fail "--help lost the --uninstall text"
grep -q "a fork's release you already trust" <<< "$help_out" || fail "--help truncates the --release-repo text"
pass "--help covers the new flags"

# ---- 12. online install with a FAILED attestation aborts --------------------
# The same-origin checksum matches, but the mandatory provenance check fails
# (GH_MODE=attest-fail): a matching-but-unattested binary must not install.
dir="$(new_case attest-fail)"
hash="$(sha256_of "$dir/pkg/browser-bridge")"
publish_checksum "$dir" "$hash"
if out="$(GH_MODE=attest-fail run_install "$dir" --release-repo "$FAKE_REPO" 2>&1)"; then
  fail "attestation failed: installer succeeded on an unattested binary"
fi
grep -q "attestation FAILED" <<< "$out" || fail "attestation failed: wrong error: $out"
[[ ! -e "$(installed_binary "$dir")" ]] || fail "attestation failed: binary installed anyway"
[[ ! -e "$dir/nm/com.browser_bridge.host.json" ]] || fail "attestation failed: host manifest written anyway"
pass "online install with a failed attestation fails closed"

# ---- 13. online install with gh unavailable aborts (no --expected-sha256) ---
# Without an out-of-band hash, the same-origin checksum is not an independent
# anchor, so gh attestation is required; if gh cannot run, refuse rather than
# trust the checksum alone.
dir="$(new_case gh-unavailable)"
hash="$(sha256_of "$dir/pkg/browser-bridge")"
publish_checksum "$dir" "$hash"
if out="$(GH_MODE=unavailable run_install "$dir" --release-repo "$FAKE_REPO" 2>&1)"; then
  fail "gh unavailable: installer trusted the same-origin checksum alone"
fi
grep -q "cannot independently verify" <<< "$out" || fail "gh unavailable: wrong error: $out"
[[ ! -e "$(installed_binary "$dir")" ]] || fail "gh unavailable: binary installed anyway"
pass "online install with gh unavailable fails closed (checksum alone is not trusted)"

echo "ALL PASS (13/13 install verification cases)"
