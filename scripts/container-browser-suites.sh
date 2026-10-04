#!/usr/bin/env bash
# The browser service's command (compose.yaml): the suite runner under a virtual display, since the smoke
# and security suites load the extension non-headless. tests/browser/run_all.ts owns the suite list, the
# strict-mode verdict, and the RAN-marker canary.
set -euo pipefail

exec xvfb-run -a moon run test-browser
