#!/usr/bin/env bash
# Run the browser suites inside a Linux container mirroring CI's browser job,
# so no test Chrome or bun process ever runs with real-machine permissions.
#
#   scripts/run-browser-tests-container.sh                 # dom + smoke + security
#   scripts/run-browser-tests-container.sh dom             # just the DOM suite
#   scripts/run-browser-tests-container.sh dom security    # any subset
#   moon run test-browser-container                        # the moon wrapper
#
# Engine: podman if present, else docker; CONTAINER_ENGINE=<name> overrides.
# The repo is mounted READ-ONLY; the container copies it to a scratch dir and
# installs/builds there, so nothing browser-shaped touches the host checkout.
# This is a local-verification convenience - CI's browser job stays canonical.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=chromium-bridge-browser-tests

engine="${CONTAINER_ENGINE:-}"
if [ -z "$engine" ]; then
  if command -v podman >/dev/null 2>&1; then
    engine=podman
  elif command -v docker >/dev/null 2>&1; then
    engine=docker
  else
    echo "error: neither podman nor docker found; set CONTAINER_ENGINE" >&2
    exit 2
  fi
fi

for s in "$@"; do
  case "$s" in
    dom | smoke | security) ;;
    *)
      echo "error: unknown suite '$s' (dom|smoke|security)" >&2
      exit 2
      ;;
  esac
done

# The image pins bun to the repo's packageManager version, same source of
# truth as CI's setup-bun (bun-version-file: package.json).
BUN_VERSION="$(sed -n 's/.*"packageManager": *"bun@\([^"]*\)".*/\1/p' "$REPO/package.json")"
if [ -z "$BUN_VERSION" ]; then
  echo "error: could not read the pinned bun version from package.json" >&2
  exit 2
fi

# Chrome for Testing ships Linux builds ONLY as x86_64, so the image is
# linux/amd64 everywhere; on Apple Silicon the engine runs it under
# Rosetta/qemu (slower, still isolated). Override with CONTAINER_PLATFORM.
PLATFORM="${CONTAINER_PLATFORM:-linux/amd64}"

"$engine" build \
  --platform "$PLATFORM" \
  --build-arg "BUN_VERSION=$BUN_VERSION" \
  -t "$IMAGE" \
  -f "$REPO/scripts/browser-container/Containerfile" \
  "$REPO/scripts/browser-container"

# --shm-size: Chrome needs more than the 64MB container default even with
# --disable-dev-shm-usage as belt-and-braces. Suites default to all three.
exec "$engine" run --rm \
  --platform "$PLATFORM" \
  --shm-size=1g \
  -v "$REPO:/repo:ro" \
  -e "BB_SUITES=${*:-dom smoke security}" \
  "$IMAGE" \
  bash /repo/scripts/browser-container/run-suites.sh
