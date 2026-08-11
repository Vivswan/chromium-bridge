# Tests

The test suites span two languages: `protocol/` (python) and the
TypeScript suites (bun workspace members), with shared pages in
`fixtures/`. The language split is deliberate, not historical accident:

| Suite | File | Runtime | Why this language |
|-------|------|---------|-------------------|
| **Protocol** | `protocol/e2e.py` | `uv run` (stdlib only) | Drives the real release binary as a subprocess and speaks the wire protocols (Native-Messaging framing, MCP JSON-RPC, the TCP bridge) *from the outside*. A second, independent implementation of the protocols - in a different language with no deps - is what makes it good at catching framing/encoding bugs the Rust code and its own types would miss. |
| **DOM** | `browser/dom_test.ts` | `bun` + Chrome (CDP) | Injects the built `build/extension/chrome-mv3` content script into a real headless Chrome page and exercises every content-script op (snapshot, click, fill, eval, storage, toast). Needs a real browser DOM; TypeScript shares the extension's toolchain. |
| **Smoke** | `browser/ext_test.ts` | `bun` + puppeteer-core | Launches Chrome with `build/extension/chrome-mv3` loaded and checks the MV3 service worker boots with its APIs. |
| **Integration** (opt-in) | `browser/integration_e2e.ts` | `bun` or Node 22.12+ + puppeteer-core | The full real chain with nothing mocked - MCP client → real MCP server → native host → real extension → `chrome.tabs` → back. Closes the seam `e2e.py` mocks. |
| **SDK interop** | `interop/sdk-client.test.ts` | `bun test` (`moon run test-interop`) | Drives the release binary with the OFFICIAL TypeScript MCP client SDK v2, pinned to the modern era (no legacy fallback): proves a real third-party 2026-07-28 client negotiates, lists, and calls against the served protocol. No browser: the empty-bridge `tools/call` asserts the typed in-result error. |
| **Harness smoke** | `harness/run.ts` | `bun` + harness CLIs (`moon run harness-smoke`) | Real agent-harness CLIs (Claude Code, Codex) connect to the stdio MCP server via ISOLATED config dirs, with every frame captured; prints the ADR-0034 opening-method canary that decides when legacy-era support can be deleted. The `*-live-fakellm` entries drive a FULL model-driven tool call through each CLI against a local fake LLM backend (`harness/fake-llm.ts`) - zero credentials, zero model spend. Nightly workflow: `harness-smoke.yml`. |

The two browser suites are TypeScript run under bun (matching the
extension). The protocol suite stays Python on purpose - rewriting it in
TS/JS would remove the independent-implementation value and add nothing.
It runs via [`uv`](https://docs.astral.sh/uv/), which provisions the exact
interpreter pinned in the repo-root `.python-version` - the same version
locally and in CI (an unpinned PATH `python3` once let a 3.12/3.14
`subprocess` difference slip through). Two properties are deliberate and
must stay: the suite is **stdlib-only** (never add dependencies - the
no-deps independence is part of the testing strategy, and uv is here to pin
the interpreter, not to open the door to packages), and it runs with
`uv run --no-project --isolated`, staying a plain script that no stray
project or virtualenv can leak into.

The protocol suites and the integration test's MCP leg track the MCP
2026-07-28 migration: modern-era cases speak the stateless protocol
(per-request `_meta` protocol-version + client-capabilities keys,
`server/discover` discovery), while bare requests on initialize-opened
connections still exercise the temporary legacy era (pinned at the
`2025-06-18` shapes) until it is removed.

## ⚠ Safety - never point browser tests at your daily Chrome

The smoke and integration tests launch a **non-headless Chrome with
`--load-extension`**. Driving your everyday Google Chrome this way can **capture
and then close your real browser session** (all tabs/windows) on cleanup. So:

- Browser tests require **`CHROME_BIN` set to an isolated browser** - a
  [Chrome for Testing](https://developer.chrome.com/blog/chrome-for-testing) or
  Chromium binary that is **not** your daily browser.
- If `CHROME_BIN` is unset (or points at the standard `Google Chrome.app` /
  `chrome.exe`), the tests and `run_all.ts` **skip** instead of running - they
  will not touch your daily Chrome.
- The tests only ever terminate the browser instance they launched - never a
  broad/pattern process kill.
- In CI that local skip must never turn the required browser job silently
  green, so two variables harden it there (`browser-safety.ts`; unit tests in
  `browser-safety.test.ts`): `BB_REQUIRE_BROWSER=1` makes the skip a hard
  failure, and `BB_BROWSER_CANARY_DIR` makes every finished suite drop a RAN
  marker that a final job step requires - a suite that skipped, or passed
  zero checks, fails the job. Neither variable is needed locally.

```sh
export CHROME_BIN="/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
```

## Running

```sh
# Everything (builds the binary + extension first; skips browser tests if
# Chrome is missing). This is what CI runs.
bun browser/run_all.ts
CHROME_BIN="/path/to/chrome" bun browser/run_all.ts   # override Chrome location

# Individually:
uv run --no-project --isolated protocol/e2e.py   # protocol - no browser needed
# (or: moon run test-e2e / test-adversarial / test-chaos - CI's three python jobs)
bun run --cwd browser test:dom              # DOM     - bun + Chrome
bun run --cwd browser test:smoke            # smoke   - bun + Chrome (BB_EXT_DIR overrides the loaded dir)
```

The browser suites read the **built** bundle, so build the extension first
(`bun run --cwd ../src/apps/extension build`); `run_all.ts` and `moon run test-browser` do
this for you.

## Types

The `.ts` suites are type-checked (`bun`, `chrome`, and DOM types):

```sh
bun install            # workspace install (puppeteer-core + type packages)
moon run typecheck     # tsc --noEmit (CI gates this)
```

## Fixtures

`fixtures/*.html` are static pages the DOM suite navigates to (plain DOM,
shadow DOM, iframes, dynamic insertion) - see `dom_test.ts` for what each
exercises.

## Real integration test (opt-in)

`integration_e2e.ts` closes the one seam the others can't: the **real** MCP
server ↔ **real** extension round-trip over native messaging. It spawns the
release binary as the MCP server, launches Chrome (puppeteer) with a unique
copy of the extension, registers a native-messaging host manifest, and drives
a `tab_list` call all the way to `chrome.tabs.query` and back.

On macOS the manifest goes inside the throwaway `--user-data-dir` profile,
which Chrome for Testing and Chromium resolve for user-level host manifests
(the fixed `~/Library/.../Google/Chrome/NativeMessagingHosts` directory is
not read under a custom profile dir; verified with Chrome for Testing 151 and
Chromium 1663645), so a real installation's registration is never touched. On
Windows the registration is an HKCU registry value shared by every Chrome
instance of the account; the test backs it up and restores it.

```sh
BB_REAL_E2E=1 bun browser/integration_e2e.ts     # macOS/Linux shell
$env:BB_REAL_E2E='1'; node browser/integration_e2e.ts  # Windows PowerShell, Node 22.12+
```

- **Opt-in** (skips unless `BB_REAL_E2E=1`), **Windows-only** since
  ADR-0032 phase 5, and pops a non-headless window. Not in the default suite
  or CI. Use Chrome for Testing or Chromium: official Google Chrome 137+
  ignores `--load-extension`.
- **macOS is skipped by the preflight, deliberately**: phase 5 retired the
  `requireEnrollment` opt-out the test used to write, so on a Mac the
  enrollment gate is unconditional and satisfying it takes a genuine pairing
  ceremony (interactive Touch ID) a throwaway profile cannot perform - the
  bridge would refuse `tab_list` at the gate. This is intentional
  fail-closed behavior, not a break; browser suites on a Mac that need
  bridge ops past the gate now require genuine pairing. On Windows the
  browser's platform probe reports no Secure Enclave, enrollment is
  unavailable rather than unsatisfied, and the round-trip still runs.
- On Windows it proves the round-trip (native host connects, `tab_list`
  returns real structured `chrome.tabs` data). One **extra** assertion - that
  the reply came from *our* throwaway profile - only holds when the launch is
  isolated. Set `CHROME_BIN` to the Chrome for Testing/Chromium executable.

(Historical note: the smoke test's comment claimed Chrome *forbids*
`nativeMessaging` under automated launches - that was a misdiagnosis of a
puppeteer `worker.evaluate` quirk. This test demonstrates it works.)
