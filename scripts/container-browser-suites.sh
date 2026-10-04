#!/usr/bin/env bash
# The browser service's command: the suites under a virtual display, then the suite-ran canary CI's
# browser job also keeps (checks.yml): every suite must have left a fresh RAN marker that is not a
# zero-pass run. BB_REQUIRE_BROWSER=1 already fails a skip inside the guard; the marker check is the
# independent backstop for the day an env var name drifts and the guard's skip goes unnoticed.
set -euo pipefail

rm -rf "${BB_BROWSER_CANARY_DIR}"
xvfb-run -a moon run test-browser

status=0
for suite in dom_test ext_test security_browser_test; do
  marker="${BB_BROWSER_CANARY_DIR}/${suite}"
  if [ ! -f "${marker}" ]; then
    echo "ERROR: ${suite} left no RAN marker - it finished no real browser run" >&2
    status=1
  elif grep -q ': 0 passed' "${marker}"; then
    echo "ERROR: ${suite} ran vacuously: $(cat "${marker}")" >&2
    status=1
  else
    cat "${marker}"
  fi
done
exit "${status}"
