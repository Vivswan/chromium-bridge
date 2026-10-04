#!/usr/bin/env bash
# The one reader of a tool pin for the two consumers that run before bun or proto exist: the composite
# action .github/actions/setup-moon on a bare runner, and the Containerfile at image build (it copies
# this script and both pin files into /tmp/pins). Each tool is pinned in exactly one file, and a pin
# found in both, twice, or nowhere fails here instead of one consumer quietly picking a copy.
#
#   .prototools    proto = "0.58.2"                 -> pin.sh proto
#   Containerfile  ARG CARGO_MACHETE_VERSION=0.9.2   -> pin.sh cargo-machete
set -euo pipefail

tool="${1:?usage: scripts/pin.sh <tool>}"
root="$(dirname "${BASH_SOURCE[0]}")/.."
arg="$(tr 'a-z-' 'A-Z_' <<<"$tool")_VERSION"

# A reader that cannot open one owner file must not certify the other's pin as the only one (a failing
# sed inside the substitution below would otherwise pass unnoticed).
for file in .prototools Containerfile; do
  [ -r "$root/$file" ] || { echo "pin.sh: cannot read $root/$file" >&2; exit 1; }
done

# Leading whitespace is legal before a TOML key or table header and before a Dockerfile instruction, so
# the scan allows it everywhere, or an indented duplicate would slip past the one-owner check.
versions="$(
  sed -nE "/^[[:space:]]*\[/q; s/^[[:space:]]*${tool}[[:space:]]*=[[:space:]]*\"([^\"]+)\".*$/\1/p" "$root/.prototools"
  sed -nE "s/^[[:space:]]*ARG[[:space:]]+${arg}=([^[:space:]]+)[[:space:]]*$/\1/p" "$root/Containerfile"
)"

case "$versions" in
  "") echo "pin.sh: ${tool} is pinned in neither .prototools nor the Containerfile" >&2; exit 1 ;;
  *$'\n'*) echo "pin.sh: ${tool} is pinned more than once (one owner per pin): ${versions//$'\n'/, }" >&2; exit 1 ;;
esac
printf '%s\n' "$versions"
