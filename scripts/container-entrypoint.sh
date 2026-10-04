#!/usr/bin/env bash
# Image entrypoint: the node_modules named volume starts empty and holds the Linux install, which the
# host's macOS or Windows install cannot stand in for, so every service installs before its command.
set -euo pipefail
bun install --frozen-lockfile
exec "$@"
