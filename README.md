# chromium-bridge

[![CI](https://github.com/Vivswan/chromium-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/Vivswan/chromium-bridge/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Individual%20and%20Small%20Organization%201.1.0-blue)](./LICENSE.md)

English | [Simplified Chinese](./README.zh-cn.md) | [Traditional Chinese](./README.zh-tw.md)

A program you installed cannot use your browser without you noticing. Under that bar, chromium-bridge lets any MCP client (Claude Code, Claude Desktop, Codex, or anything that speaks the Model Context Protocol) drive your real Chromium browser: your tabs, your logged-in sessions, your cookies, through a browser extension and a native-messaging host. No second browser, no CDP debug port, no `--remote-debugging` flag.

Because it operates the browser you are already signed into, an agent can read a page behind your auth, click through an app you are logged into, or pull a token your framework stashed in `localStorage`. That power is also the risk, so read [Security first](#security-first) before you install. Where the bar stops is stated on [the security page](./docs/security.md).

## Features

- **Your real browser, not a headless one:** 26 tools over tabs, pages, cookies, and storage, each with a stated risk level and gate ([below](#what-you-can-do-26-tools)).
- **Guardrails on by default:** per-site approval, confirmation of the dangerous actions in a window no page can reach, presence by WebAuthn, a kill switch, an audit trail ([Security first](#security-first)).
- **An authenticated, attested bridge** between the MCP server and the browser's host, with no listening port ([How it works](#how-it-works)).
- **Several clients at once,** each attested and individually revocable.
- **One binary, three roles:** the MCP server, the native-messaging host, and the CLI that installs, pairs, kills, and audits.

## Security first

chromium-bridge drives a real, authenticated browser. It can read page content, cookies (including `httpOnly`), and web storage, and can run JavaScript in your pages. The guardrails:

- **Approve every site.** A new origin triggers a prompt; nothing runs on a site you have not approved.
- **Confirm high-risk actions.** Submit clicks, key presses, tab close, file uploads, and every `page_eval` confirm on an extension-owned window the page cannot see or click. `page_eval` and `page_upload` reconfirm on every call. What a same-user program can still do around that window is in the [trust boundaries ledger](./docs/security/trust-boundaries.md#boundary-4-extension---web-page--chrome-api--content-script--dom).
- **Prove presence with WebAuthn.** Releasing the kill switch needs a tap from an authenticator enrolled under that browser, and enrolling another browser needs a tap from any authenticator already enrolled on the machine; the host verifies both. The confirmation window stands in only where no enrolled authenticator could answer.
- **Gates are on by default.** Each is a documented setting, and relaxing one is an explicit, informed choice ([SECURITY.md](./.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe)).
- **Read-only credentials.** Cookies and storage can be read (always masked: JWTs, long hex, long digit runs), never written. There is no `cookie_set` or `storage_set` by design.
- **Authenticated, attested bridge.** On macOS and Linux the host processes talk over a private Unix-domain socket (no listening port). Every connection must pass a kernel peer-UID check, kernel-attested executable identity, and an HMAC challenge over a per-run secret.
- **Trusted-client allowlist.** MCP clients are admitted against an allowlist keyed on attested code identity, and any side can revoke trust at any time.
- **A global kill switch.** One action from the CLI or the extension halts everything until you release it with proof of presence (a tap, the confirmation window where that browser enrolled no authenticator, or the typed phrase on a terminal). Every security decision lands in an on-disk audit trail.

The bridge guarantees hold on macOS, Linux, and Windows; the mechanism behind each differs per OS ([SECURITY.md](./.github/SECURITY.md#platform-support)).

| Platform | Bridge transport | What gates a connection |
|---|---|---|
| macOS, Linux | private Unix-domain socket, no listening port | peer-UID check, kernel attestation, HMAC challenge |
| Windows | named pipe only your user can open, no listening port | the pipe's descriptor (kernel-enforced), mutual attestation, HMAC challenge |

Full details: [SECURITY.md](./.github/SECURITY.md), [security page](./docs/security.md), [trust boundaries](./docs/security/trust-boundaries.md), [per-tool risk matrix](./docs/security/tool-risk-matrix.md).

## Requirements

| | Supported |
|---|---|
| macOS | Apple Silicon (arm64) prebuilt; Intel builds from source |
| Linux | x64 prebuilt; any Chromium-based browser |
| Windows | x64 prebuilt (native, no admin); a user-only named pipe with mutual attestation ([SECURITY.md](./.github/SECURITY.md#platform-support)) |
| Browser | any Chromium-based browser, Manifest V3: `chrome`, `chromium`, `brave`, `edge`, `vivaldi`, `opera` are the known `--browser` keys; on macOS and Linux another variant registers through `doctor --fix --manifest-dir <dir>`, while Windows registration is an HKCU key for the known browsers |
| MCP client | any client speaking MCP protocol `2026-07-28` over stdio |
| Internal bridge protocol | `1` (`BRIDGE_PROTOCOL_VERSION` in [src/packages/core/src/protocol.rs](./src/packages/core/src/protocol.rs)) |

Pre-1.0 ([Cargo.toml](./Cargo.toml)): the protocol layers are covered by end-to-end, adversarial, and chaos tests, and the wire parsers are fuzzed ([CHANGELOG.md](./CHANGELOG.md)).

## Quick start

The CLI needs nothing beyond the binary itself, on desktops, headless machines, and CI alike. The steps in full, with the install channels and what each does for you, are in [the quickstart](./docs/quickstart.md); the short form:

1. Install from the [latest release](https://github.com/Vivswan/chromium-bridge/releases/latest): the `.pkg`, the `.msi`, the `.deb`, Homebrew (once [the tap](./docs/release.md#homebrew-tap) exists), or the archive. To verify a download first, the commands are in [SECURITY.md](./.github/SECURITY.md#release-artifact-integrity).

2. Register the binary with your browsers, unless the installer did (the `.pkg`, the `.msi`, and Homebrew do). Registration is idempotent, so the same command is the fresh install, the repair, and the re-register after moving the binary:

   ```sh
   chromium-bridge doctor --fix          # every detected browser
   chromium-bridge doctor --fix --browser chrome,brave
   ```

   From the archive, run the extracted binary with a `./` prefix and keep it at a stable path (it is registered in place). `chromium-bridge uninstall` reverses exactly what was registered.

3. Load the extension: the archive's `extension/dist` directory via `chrome://extensions`, Developer mode, "Load unpacked". Restart the browser. The extension needs Chrome 134 or later; an older browser refuses to load it.

4. Pair, then enroll (recommended): `chromium-bridge pair` prints the host key's fingerprint; approve it on the extension's options page ([docs/cli.md](./docs/cli.md#enrollment-pair--revoke--enclave-status)). Enrolling your browser's authenticator from the same page is recommended, not required; [the quickstart's hardening section](./docs/quickstart.md#recommended-hardening) says what it adds.

5. Connect your MCP client to the binary's absolute path (most clients do not expand `~`). Run with no arguments, the binary speaks MCP over stdio.

   ```sh
   claude mcp add chromium-bridge -- /absolute/path/to/chromium-bridge
   ```

   Claude Desktop and other `mcpServers` JSON clients take `"command": "/ABSOLUTE/PATH/TO/chromium-bridge"` with `"args": []`; Codex takes the same two keys under `[mcp_servers.chromium-bridge]` in `~/.codex/config.toml`.

Building from source instead: `cargo build --release`, then run the same `doctor --fix` from `target/release/chromium-bridge` ([docs/development.md](./docs/development.md)). On WSL, install where the browser runs ([running under WSL](./docs/troubleshooting.md#running-under-wsl)).

## What you can do: 26 tools

Grouped from the single source of truth, the Rust tool catalogue ([`src/packages/core/src/tools/catalogue.rs`](./src/packages/core/src/tools/catalogue.rs)); the blast radius and the gate of every tool are in the [tool risk matrix](./docs/security/tool-risk-matrix.md).

| Group | Tools | Risk |
|---|---|---|
| Browsers | `list_browsers` | low |
| Tabs | `tab_list`, `tab_focus`, `tab_open`; `tab_close` confirms | low to high |
| Navigate | `page_navigate`, `page_back`, `page_forward`, `page_reload` | low to medium |
| Inspect a page | `page_snapshot`, `page_snapshot_precise`, `page_text`, `page_screenshot`, `console_get` | low to medium |
| Drive a page | `page_click`, `page_fill`, `page_press`, `page_select`, `page_hover`, `page_scroll`, `page_wait_for`, `page_handle_dialog`; submit and link clicks, key presses, and selects confirm, and dialog handling is off by default | low to high |
| Run code and upload | `page_eval` (off by default; every call confirms, showing the full code), `page_upload` (off by default; every call confirms with the path) | critical |
| Read credentials | `cookie_get` (including `httpOnly`, allowlisted hosts only), `storage_get` (same-origin); read-only, always masked | high |

Several browsers can be connected at once; on macOS and Linux each gets its own native host and label (for example `chrome` and `brave`), every other tool takes an optional `browser` argument, and an unaddressed call with several connected fails with a clear error rather than guessing. No write tools exist by design: a forged `httpOnly` cookie is a session-fixation risk.

## How it works

One Rust binary, two modes, joined by an authenticated local socket; the CLI manages the state.

```text
MCP client A --stdio--> chromium-bridge (broker: first MCP server instance)
MCP client B --stdio--> chromium-bridge ----attach----^   |
(each client attested against the trusted-client         | bridge socket
 allowlist before it is served)                          | (Unix-domain socket,
                                                          | or a user-only named pipe
                                                          | on Windows; attestation + HMAC)
                                                          v
                             chromium-bridge --native-host   <-- spawned by
                                       |                         each browser
                                       | chrome.runtime.connectNative
                                       v
                             Chromium Bridge extension (MV3) --> your page
```

- **MCP server (default mode):** launched by your MCP client over stdio; JSON-RPC 2.0, MCP protocol `2026-07-28`, stateless, with temporary legacy compatibility for older harnesses. The first instance owns the socket and becomes the broker; later instances attach as relays.
- **`--native-host`:** launched by the browser via the host manifest, one per browser, with its own label on macOS and Linux; a thin bridge from Chrome's native-messaging frames to NDJSON on the socket.
- **CLI:** the management surface over the same core (registration, pairing, revocation, kill switch, audit). It is not a trust root; capability-granting acts end in a user-presence gate.

The browser spawns the native host and the MCP client spawns the server, so they are not parent and child and need an IPC; the host stays thin so that MV3 service-worker recycling (about every 5 minutes) and host restarts lose no session state. The deep dive is [docs/architecture.md](./docs/architecture.md).

## Configuration

Environment variables read at launch:

| Var | Values | Default | Effect |
|-----|--------|---------|--------|
| `BB_LOG` | `error` \| `warn` \| `info` \| `debug` | `info` | stderr log / audit threshold |
| `BB_LOG_FORMAT` | `text` \| `json` | `text` | Audit-line format; `json` emits one object per line |

The durable audit trail (`chromium-bridge audit`) records independently of these ([docs/cli.md](./docs/cli.md#logging-and-audit-bb_log--bb_log_format)).

## Documentation

The docs are served at <https://vivswan.github.io/chromium-bridge/docs/>, in English, Simplified Chinese, and Traditional Chinese; the same pages live under [docs/](./docs/README.md).

| I want to | Page |
|---|---|
| Install and connect a client | [Quickstart](https://vivswan.github.io/chromium-bridge/docs/quickstart) |
| Understand what a tool may do | [Tool risk matrix](https://vivswan.github.io/chromium-bridge/docs/security/tool-risk-matrix) |
| Run the CLI: doctor, pairing, trusted clients, kill switch, policy, audit | [CLI](https://vivswan.github.io/chromium-bridge/docs/cli) |
| Fix a symptom | `chromium-bridge doctor` first, then [Troubleshooting](https://vivswan.github.io/chromium-bridge/docs/troubleshooting); if both are clean, your MCP client's server UI (`/mcp` in Claude Code) and the extension's service-worker console at `chrome://extensions` (`[bb]` logs) |
| Know what is trusted, and what is not | [Security](https://vivswan.github.io/chromium-bridge/docs/security), [trust boundaries](https://vivswan.github.io/chromium-bridge/docs/security/trust-boundaries), [rationale](https://vivswan.github.io/chromium-bridge/docs/security/rationale) |
| See how the pieces fit | [Architecture](https://vivswan.github.io/chromium-bridge/docs/architecture) |
| Build, test, or release it | [Development](https://vivswan.github.io/chromium-bridge/docs/development), [Releasing](https://vivswan.github.io/chromium-bridge/docs/release) |

## Contributing and governance

[CONTRIBUTING.md](./CONTRIBUTING.md) is the workflow, [GOVERNANCE.md](./GOVERNANCE.md) how changes get made, [SECURITY.md](./.github/SECURITY.md) the reporting channel and the review bar, and [tests/README.md](./tests/README.md) the suites and the browser-safety rule.

## License

[Individual and Small Organization License 1.1.0](./LICENSE.md). Incorporates code from [browser-bridge](https://github.com/whg517/browser-bridge) under Apache-2.0; see [LICENSE-APACHE](./LICENSE-APACHE) and [NOTICE](./NOTICE).
