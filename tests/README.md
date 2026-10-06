# Tests

The test suites span two languages: `protocol/` (python) and the TypeScript suites (bun workspace members), with shared pages in `fixtures/`. The language split is deliberate, not historical accident:

| Suite | File | Runtime | Why this language |
|-------|------|---------|-------------------|
| **Protocol** | `protocol/e2e.py`, `protocol/adversarial.py`, `protocol/chaos.py` (shared `protocol/harness.py`) | `uv run` + stdlib `unittest` | Drives the real release binary as a subprocess and speaks the wire protocols (Native-Messaging framing, MCP JSON-RPC, the bridge socket) *from the outside*. A second, independent implementation of the protocols - in a different language with no deps - is what makes it good at catching framing/encoding bugs the Rust code and its own types would miss. |
| **DOM** | `browser/dom_test.ts` | `bun` + Chrome (CDP) | Injects the built `build/extension/chrome-mv3` content script into a real headless Chrome page and exercises every content-script op (snapshot, click, fill, eval, storage, toast). Needs a real browser DOM; TypeScript shares the extension's toolchain. |
| **Smoke** | `browser/ext_test.ts` | `bun` + puppeteer-core | Launches Chrome with `build/extension/chrome-mv3` loaded and checks the MV3 service worker boots with its APIs. |
| **WebAuthn** | `browser/webauthn_test.ts` | `bun` + puppeteer-core (CDP virtual authenticator) | Runs `navigator.credentials.create` / `.get` in the options page against a virtual platform authenticator and pins the facts the host's verifier assumes about Chrome's WebAuthn client (the RP ID is the `chrome-extension://` origin, attestation `none`, ES256, the authenticatorData layout). |
| **Cancel** | `browser/cancel_test.ts` (stand-in host `browser/fake_host.ts`) | `bun` + puppeteer-core | Registers a stand-in native host in the throwaway profile and proves, through Chrome's real native messaging, that the server's `cancel` frame is consumed by the extension and never answered while the request after it is. |
| **Integration** (opt-in) | `browser/integration_e2e.ts` | `bun` + puppeteer-core | The real chain with nothing mocked - MCP client -> real MCP server -> native host -> real extension -> its enrollment gate -> back. Closes the seam `e2e.py` mocks. |
| **SDK interop** | `interop/sdk-client.test.ts` | `bun test` (`moon run test-interop`) | Drives the release binary with the OFFICIAL TypeScript MCP client SDK v2, pinned to the modern era (no legacy fallback): proves a real third-party 2026-07-28 client negotiates, lists, and calls against the served protocol. No browser: the empty-bridge `tools/call` asserts the typed in-result error. |
| **Harness smoke** | `harness/run.ts` | `bun` + harness CLIs (`moon run harness-smoke`) | Real agent-harness CLIs (Claude Code, Codex) connect to the stdio MCP server via ISOLATED config dirs, with every frame captured; prints the opening-method canary that decides when legacy-era support can be deleted. The `*-live-fakellm` entries drive a FULL model-driven tool call through each CLI against a local fake LLM backend (`harness/fake-llm.ts`) - zero credentials, zero model spend. Nightly workflow: the `harness-smoke` job in `nightly.yml`. |

The two browser suites are TypeScript under bun, matching the extension. The protocol suites stay Python on purpose: a rewrite in TS would remove the independent-implementation value and add nothing. How they run:

- **Stdlib `unittest`, discovered.** Each suite is a module of `TestCase` classes run with `python -m unittest discover`, so a new test cannot be left out of a hand-kept list. `protocol/harness.py` holds the shared isolation, spawners, wire helpers, and whole-reply expectations.
- **Under [`uv`](https://docs.astral.sh/uv/)**, which provisions the interpreter pinned in the repo-root `.python-version`, the same locally and in CI (an unpinned PATH `python3` once let a 3.12/3.14 `subprocess` difference slip through).
- **Stdlib-only; never add dependencies.** The no-deps independence is part of the strategy, and uv pins the interpreter without opening the door to packages. `uv run --no-project --isolated` keeps the run a plain script that no stray project or virtualenv can leak into.
- **Isolated runtime dir.** Every server a suite spawns runs in a private per-run `XDG_RUNTIME_DIR` under the OS temp dir (`bb-<suite>-XXXXXXXX`, holding a `harness.pid` that names the run), so the lock, socket, and pairing state never touch the developer's real bridge. The suite refuses to run unless the binary's own `doctor --paths` reports its lock inside that dir.
- **Removed on every exit path.** The suite removes its dirs at teardown (a pass, a failure, SIGTERM, SIGINT) and fails on one that survives. At startup it sweeps its prefix's dirs whose recorded pid is dead, printing each removal; a live recorded pid is never touched, and a dir with no owner record older than 60 s is removed.
- **Short `TMPDIR`.** The socket path `$TMPDIR/bb-adversarial-XXXXXXXX/chromium-bridge/run.sock` must fit `sun_path` (103 bytes on macOS, 107 on Linux), so `TMPDIR` can be at most 54 bytes (58 on Linux). Past that the binary refuses the runtime dir by name (`runtime dir refused: ... over the 103-byte sun_path limit`), its `doctor --paths` probe fails, and the harness refuses to run. Point `TMPDIR` at a short directory.
- **Re-pinning `protocol/tools_list.json`** (the whole tools/list the catalogue test asserts) after a catalogue change: `uv run --no-project --isolated python protocol/harness.py --capture-tools-list`, then `moon run fmt-ts`. Review the diff: it is the contract change.

The protocol suites and the integration test's MCP leg track the MCP 2026-07-28 migration: modern-era cases speak the stateless protocol (per-request `_meta` protocol-version + client-capabilities keys, `server/discover` discovery), while bare requests on initialize-opened connections still exercise the temporary legacy era (pinned at the `2025-06-18` shapes) until it is removed.

## ⚠ Safety - never point browser tests at your daily Chrome

The smoke and integration tests launch a **non-headless Chrome with `--load-extension`**. Driving your everyday Google Chrome this way can **capture and then close your real browser session** (all tabs/windows) on cleanup. So:

- Browser tests require **`CHROME_BIN` set to an isolated browser** - a [Chrome for Testing](https://developer.chrome.com/blog/chrome-for-testing) or Chromium binary that is **not** your daily browser.
- Inside a container (an engine marker file such as `/.dockerenv` or `/run/.containerenv` is present) the guard also accepts the distro Chromium the CI image carries; on the host it never does.
- If `CHROME_BIN` is unset (or points at the standard `Google Chrome.app` / `chrome.exe`), the tests and `run_all.ts` **skip** instead of running - they will not touch your daily Chrome.
- The tests only ever terminate the browser instance they launched - never a broad/pattern process kill.
- In CI that local skip must never turn the required browser job silently green, so `browser.yml` sets two independent switches for `browser/run_all.ts` (`browser-safety.ts`; unit tests in `browser-safety.test.ts`): `BB_REQUIRE_BROWSER=1` makes the guard's skip a hard failure, and a named `BB_BROWSER_CANARY_DIR` makes the runner require every suite's RAN marker and fail on its own skip. Neither variable is needed locally.

```sh
export CHROME_BIN="/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
```

## Running

```sh
# The three browser suites (builds the extension first; skips without an
# isolated CHROME_BIN). CI's browser.yml and the container run this runner.
bun browser/run_all.ts
CHROME_BIN="/path/to/chrome" bun browser/run_all.ts   # override Chrome location

# Individually:
moon run test-e2e            # protocol - no browser needed (also test-adversarial, test-chaos: CI's protocol matrix)
uv run --no-project --isolated python -m unittest discover -s protocol -p e2e.py -v   # the same suite by hand
uv run --no-project --isolated python -m unittest discover -s protocol -p e2e.py -k KillSwitch   # one class or test
bun run --cwd browser test:dom              # DOM      - bun + Chrome
bun run --cwd browser test:smoke            # smoke    - bun + Chrome (BB_EXT_DIR overrides the loaded dir)
bun run --cwd browser test:security         # security - bun + Chrome
```

The browser suites read the **built** bundle, so build the extension first (`bun run --cwd ../src/apps/extension build`); `run_all.ts` and `moon run test-browser` do this for you.

## Types

The `.ts` suites are type-checked (`bun`, `chrome`, and DOM types):

```sh
bun install            # workspace install (puppeteer-core + type packages)
moon run typecheck     # tsc --noEmit (CI gates this)
```

## Fixtures

`fixtures/*.html` are static pages the DOM suite navigates to (plain DOM, shadow DOM, iframes, dynamic insertion) - see `dom_test.ts` for what each exercises.

## Real integration test (opt-in)

`integration_e2e.ts` closes the one seam the others can't: the **real** MCP server <-> **real** extension chain over native messaging. It spawns the release binary as the MCP server, launches Chrome (puppeteer) with a unique copy of the extension, registers a native-messaging host manifest, and drives a `tab_list` call to the extension's enrollment gate and back.

On macOS the manifest goes inside the throwaway `--user-data-dir` profile, which Chrome for Testing and Chromium resolve for user-level host manifests (the fixed `~/Library/.../Google/Chrome/NativeMessagingHosts` directory is not read under a custom profile dir), so a real installation's registration is never touched.

On Windows the registration is an HKCU registry value shared by every Chrome instance of the account, so the test runs only where none exists (a real install's Chrome must never be pointed at the test host) and removes the one it wrote.

```sh
BB_REAL_E2E=1 bun browser/integration_e2e.ts     # macOS/Linux shell
$env:BB_REAL_E2E='1'; bun browser/integration_e2e.ts   # Windows PowerShell
```

- **Opt-in** (skips unless `BB_REAL_E2E=1`), macOS and Windows, and pops a non-headless window. Not in the default suite or CI. Use Chrome for Testing or Chromium: official Google Chrome 137+ ignores `--load-extension`.
- **Isolated runtime dir, proved by the binary**: the MCP server and the host wrapper run with a throwaway `XDG_RUNTIME_DIR`/`HOME` (`LOCALAPPDATA` on Windows), and the suite asks `chromium-bridge doctor --paths` where the lock resolves under that environment; a lock outside the throwaway dir refuses the run, so the user's live broker, lock and socket are never touched.
- **What it proves**: the chain reaches the extension's enrollment gate. Enrollment is required on every platform and a throwaway profile holds no pinned host key, so `tab_list` comes back refused with the enrollment reason; a served reply would mean the gate is gone and fails the test.

(Historical note: the smoke test's comment claimed Chrome *forbids* `nativeMessaging` under automated launches - that was a misdiagnosis of a puppeteer `worker.evaluate` quirk. This test demonstrates it works.)
