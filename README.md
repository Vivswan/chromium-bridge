# Genkan

Your AI waits at the genkan.

[![CI](https://github.com/Vivswan/genkan/actions/workflows/ci.yml/badge.svg)](https://github.com/Vivswan/genkan/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Individual%20and%20Small%20Organization%201.1.0-blue)](./LICENSE.md)

English | [Simplified Chinese](./README.zh-cn.md) | [Traditional Chinese](./README.zh-tw.md)

A program you installed cannot use your browser without you noticing. Under that bar, genkan lets any MCP client (Claude Code, Claude Desktop, Codex, or anything that speaks the Model Context Protocol) drive your real Chromium browser: your tabs, your logged-in sessions, your cookies, through a browser extension and a native-messaging host. No second browser, no CDP debug port, no `--remote-debugging` flag.

Because it operates the browser you are already signed into, an agent can read a page behind your auth, click through an app you are logged into, or pull a token your framework stashed in `localStorage`. That power is also the risk, so read [Security first](#security-first) before you install. Where the bar stops is stated on [the security page](./docs/security.md).

## Features

- **Your real browser, not a headless one:** 26 tools over tabs, pages, cookies, and storage, each with a stated risk level and gate ([below](#what-you-can-do-26-tools)).
- **Guardrails on by default:** per-site approval, confirmation of the dangerous actions in a window no page can reach, presence by WebAuthn, a kill switch, an audit trail ([Security first](#security-first)).
- **An authenticated, attested bridge** between the MCP server and the browser's host, with no listening port ([How it works](#how-it-works)).
- **Several clients at once,** each attested and individually revocable.
- **One binary, three roles:** the MCP server, the native-messaging host, and the CLI that installs, pairs, kills, and audits.

## Security first

genkan drives a real, authenticated browser. It can read page content, cookies (including `httpOnly`), and web storage, and can run JavaScript in your pages. The guardrails:

- **Approve every site.** Page-level tools run only on origins you approved, and a new origin prompts you; tab titles and URLs alone need no approval ([the matrix](./docs/security/tool-risk-matrix.md#cross-cutting-protections), [the bar](./docs/security.md#the-bar-in-one-line)).
- **Confirm high-risk actions.** Submit and link clicks, key presses, selects, tab close, file uploads, and every `page_eval` confirm on an extension-owned window the page cannot see or click; `page_eval` and `page_upload` reconfirm on every call ([what you confirm](./docs/security.md#what-you-confirm-and-what-counts-as-presence)). What a same-user program can still do around that window is in the [trust boundaries ledger](./docs/security/trust-boundaries.md#boundary-4-extension---web-page--chrome-api--content-script--dom).
- **Prove presence with WebAuthn.** Releasing the kill switch needs a tap from an authenticator enrolled under that browser, and enrolling another browser needs a tap from any authenticator already enrolled on the machine; the host verifies both. The confirmation window stands in only where no enrolled authenticator could answer ([what counts as presence](./docs/security.md#what-you-confirm-and-what-counts-as-presence)).
- **Gates are on by default.** Each is a documented setting, and relaxing one is an explicit, informed choice ([SECURITY.md](./.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe)).
- **Cookies and web storage are read-only.** `cookie_get` and `storage_get` return masked values and never write ([the matrix](./docs/security/tool-risk-matrix.md#cross-cutting-protections)); what the mask catches and misses is [SECURITY.md's](./.github/SECURITY.md#masking-is-heuristic-and-best-effort).
- **Authenticated, attested bridge.** No listening port on any OS: a private Unix-domain socket on macOS and Linux, a named pipe only your user can open on Windows. Every connection passes a same-user check, mutual executable attestation, and an HMAC challenge over a per-run secret; the per-OS mechanism is [SECURITY.md's platform table](./.github/SECURITY.md#platform-support).
- **Trusted-client allowlist, once you create it.** `genkan pair-client` creates it; from then on only MCP clients whose attested code identity you approved are served, and any surface can revoke one at any time ([cli.md](./docs/cli.md#trusted-clients-pair-client--revoke-client--list-clients)).
- **A global kill switch.** One action from the CLI or the extension halts everything until you release it with proof of presence (a tap, the confirmation window where that browser enrolled no authenticator, or the typed phrase on a terminal; [cli.md](./docs/cli.md#kill-switch-kill--unkill)). Security decisions land in an on-disk audit trail ([cli.md](./docs/cli.md#logging-and-audit-genkan_log--genkan_log_format) owns the event list and its two exceptions).

Full details: [SECURITY.md](./.github/SECURITY.md), [security page](./docs/security.md), [trust boundaries](./docs/security/trust-boundaries.md), [per-tool risk matrix](./docs/security/tool-risk-matrix.md).

## Requirements

| | Supported |
|---|---|
| macOS | Apple Silicon (arm64) prebuilt; Intel builds from source ([the build matrix](./docs/release.md#build-matrix-and-prebuilt-archives)) |
| Linux | x64 prebuilt; any Chromium-based browser |
| Windows | x64 prebuilt (native, no admin); a user-only named pipe with mutual attestation ([SECURITY.md](./.github/SECURITY.md#platform-support)) |
| Browser | any Chromium-based browser, Manifest V3: `chrome`, `chromium`, `brave`, `edge`, `vivaldi`, `opera` are the known `--browser` keys; on macOS and Linux another variant registers through `doctor --fix --manifest-dir <dir>`, while Windows registration is an HKCU key for the known browsers ([cli.md](./docs/cli.md#doctor---fix--uninstall-native-messaging-registration)) |
| MCP client | any client speaking MCP protocol `2026-07-28` over stdio |
| Internal bridge protocol | `1` (`BRIDGE_PROTOCOL_VERSION` in [src/packages/core/src/protocol.rs](./src/packages/core/src/protocol.rs)) |

Pre-1.0 ([Cargo.toml](./Cargo.toml)): the protocol layers are covered by end-to-end, adversarial, and chaos tests, and the wire parsers are fuzzed ([CHANGELOG.md](./CHANGELOG.md)).

## Quick start

The CLI needs nothing beyond the binary itself, on desktops, headless machines, and CI alike. The steps in full, with the install channels and what each does for you, are in [the quickstart](./docs/quickstart.md); the short form:

1. Install from the [latest release](https://github.com/Vivswan/genkan/releases/latest): the `.pkg`, the `.msi`, the `.deb`, Homebrew (once [the tap](./docs/release.md#homebrew-tap) exists), or the archive. To verify a download first, the commands are in [SECURITY.md](./.github/SECURITY.md#release-artifact-integrity).

2. Register the binary with your browsers, unless the installer did: `.pkg`, `.msi`, and Homebrew do, and the `.deb` does for browsers installed at the time ([quickstart step 3](./docs/quickstart.md#the-cli-macos-linux-windows)). The command is idempotent: fresh install, repair, and re-register after moving the binary:

   ```sh
   genkan doctor --fix          # every detected browser
   genkan doctor --fix --browser chrome,brave
   ```

   From the archive, run the extracted binary with a `./` prefix from a stable path: it is registered in place, and `genkan uninstall` reverses exactly what was registered.

3. Load the extension: the archive's `extension/dist` directory via `chrome://extensions`, Developer mode, "Load unpacked". Restart the browser. The extension needs Chrome 134 or later; an older browser refuses to load it.

4. Pair, then enroll (recommended): `genkan pair` prints the host key's fingerprint; approve it on the extension's options page ([docs/cli.md](./docs/cli.md#enrollment-pair--revoke--enclave-status)). Enrolling your browser's authenticator from the same page is recommended, not required; [the quickstart's hardening section](./docs/quickstart.md#recommended-hardening) says what it adds.

5. Connect your MCP client to the binary's absolute path. Run with no arguments, the binary speaks MCP over stdio.

   ```sh
   claude mcp add genkan -- /absolute/path/to/genkan
   ```

   Claude Desktop and other `mcpServers` JSON clients take `"command": "/ABSOLUTE/PATH/TO/genkan"` with `"args": []`; Codex takes the same two keys under `[mcp_servers.genkan]` in `~/.codex/config.toml`.

Building from source instead: `cargo build --release`, then run the same `doctor --fix` from `target/release/genkan` ([docs/development.md](./docs/development.md)). On WSL, install where the browser runs ([running under WSL](./docs/troubleshooting.md#running-under-wsl)).

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

Several browsers can be connected at once. A browser that alone launches its manifest connects under its own label, while browsers sharing one manifest share the broker's default slot ([cli.md](./docs/cli.md#doctor---fix--uninstall-native-messaging-registration) says which share); every other tool takes an optional `browser` argument, and an unaddressed call with several connected fails rather than guessing ([the matrix](./docs/security/tool-risk-matrix.md#cross-cutting-protections)).

Cookies and web storage are read-only by design: there is no `cookie_set` or `storage_set`, since a forged `httpOnly` cookie is a session-fixation risk ([the matrix](./docs/security/tool-risk-matrix.md#cross-cutting-protections)).

## How it works

One Rust binary, two modes, joined by an authenticated local socket; the CLI manages the state.

```text
MCP client A --stdio--> genkan (broker: first MCP server instance)
MCP client B --stdio--> genkan ----attach----^   |
(each client attested against the trusted-client         | bridge socket
 allowlist before it is served)                          | (Unix-domain socket,
                                                          | or a user-only named pipe
                                                          | on Windows; attestation + HMAC)
                                                          v
                             genkan --native-host   <-- spawned by
                                       |                         each browser
                                       | chrome.runtime.connectNative
                                       v
                             Genkan extension (MV3) --> your page
```

- **MCP server (default mode):** launched by your MCP client over stdio; JSON-RPC 2.0, MCP protocol `2026-07-28`, stateless, with temporary legacy compatibility for older harnesses ([architecture.md 3.2](./docs/architecture.md#32-mcp-json-rpc-mcp-server---mcp-client)). The first instance owns the socket and becomes the broker; later instances attach as relays ([5.3](./docs/architecture.md#53-a-second-mcp-client-attaches)).
- **`--native-host`:** launched by the browser via the host manifest, one per browser, under the label [cli.md](./docs/cli.md#doctor---fix--uninstall-native-messaging-registration) gives that manifest; a thin bridge from Chrome's native-messaging frames to NDJSON on the socket.
- **CLI:** the management surface over the same core (registration, pairing, revocation, kill switch, audit). It is not a trust root; capability-granting acts end in a user-presence gate.

The browser spawns the native host and the MCP client spawns the server, so they are not parent and child and need an IPC; the host stays thin so that MV3 service-worker recycling (about every 5 minutes) and host restarts lose no session state. The deep dive is [docs/architecture.md](./docs/architecture.md).

## Configuration

Environment variables read at launch:

| Var | Values | Default | Effect |
|-----|--------|---------|--------|
| `GENKAN_LOG` | `error` \| `warn` \| `info` \| `debug` | `info` | stderr log / audit threshold |
| `GENKAN_LOG_FORMAT` | `text` \| `json` | `text` | Audit-line format; `json` emits one object per line |

The durable audit trail (`genkan audit`) records independently of these ([docs/cli.md](./docs/cli.md#logging-and-audit-genkan_log--genkan_log_format)).

## Documentation

The docs are served at <https://vivswan.github.io/genkan/docs/>, in English, Simplified Chinese, and Traditional Chinese; the same pages live under [docs/](./docs/README.md).

| I want to | Page |
|---|---|
| Install and connect a client | [Quickstart](https://vivswan.github.io/genkan/docs/quickstart) |
| Understand what a tool may do | [Tool risk matrix](https://vivswan.github.io/genkan/docs/security/tool-risk-matrix) |
| Run the CLI: doctor, pairing, trusted clients, kill switch, policy, audit | [CLI](https://vivswan.github.io/genkan/docs/cli) |
| Fix a symptom | `genkan doctor` first, then [Troubleshooting](https://vivswan.github.io/genkan/docs/troubleshooting); if both are clean, your MCP client's server UI (`/mcp` in Claude Code) and the extension's service-worker console at `chrome://extensions` (`[genkan]` logs) |
| Know what is trusted, and what is not | [Security](https://vivswan.github.io/genkan/docs/security), [trust boundaries](https://vivswan.github.io/genkan/docs/security/trust-boundaries), [rationale](https://vivswan.github.io/genkan/docs/security/rationale) |
| See how the pieces fit | [Architecture](https://vivswan.github.io/genkan/docs/architecture) |
| Build, test, or release it | [Development](https://vivswan.github.io/genkan/docs/development), [Releasing](https://vivswan.github.io/genkan/docs/release) |

## Contributing and governance

[CONTRIBUTING.md](./CONTRIBUTING.md) is the workflow, [GOVERNANCE.md](./GOVERNANCE.md) how changes get made, [SECURITY.md](./.github/SECURITY.md) the reporting channel and the review bar, and [tests/README.md](./tests/README.md) the suites and the browser-safety rule.

## License

[Individual and Small Organization License 1.1.0](./LICENSE.md). Incorporates code from [browser-bridge](https://github.com/whg517/browser-bridge) under Apache-2.0; see [LICENSE-APACHE](./LICENSE-APACHE) and [NOTICE](./NOTICE).
