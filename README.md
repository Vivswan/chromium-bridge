# chromium-bridge

Let any MCP client (Claude Code, Claude Desktop, Codex, or anything that
speaks the Model Context Protocol) drive your real Chromium browser: your
tabs, your logged-in sessions, your cookies, through a browser extension and
a native-messaging host. No second browser, no CDP debug port, no
`--remote-debugging` flag.

Because it operates the browser you are already signed into, an agent can do
things a fresh headless browser cannot: read a page behind your auth, click
through an app you are logged into, pull a token your framework stashed in
`localStorage`. That power is also the risk. Read the security section before
you install.

Translations: [Simplified Chinese](./README.zh_CN.md),
[Traditional Chinese](./README.zh_TW.md).

## Security first

chromium-bridge drives a real, authenticated browser. It can read page
content, cookies (including `httpOnly`), and web storage, and can run
JavaScript in your pages. The guardrails:

- **Approve every site.** A new origin triggers a prompt; nothing runs on a
  site you have not approved.
- **Confirm high-risk actions.** Submit clicks, key presses, tab close, file
  uploads, and every `page_eval` confirm on an extension-owned window the
  page cannot see or click. On a Mac enrolled via Touch ID, `page_eval` and
  `page_upload` approval is a Secure Enclave user-presence check (Touch ID
  or the login password) that no page or program can forge
  ([ADR-0031](./docs/adr/0031-touch-id-confirmations-and-presence-grants.md)).
  These gates are on by default; each is a documented setting, and relaxing
  one is an explicit, informed choice
  ([SECURITY.md](./SECURITY.md#page_eval-and-confirmation-defaults-fail-safe)).
- **Read-only credentials.** Cookies and storage can be read (always masked:
  JWTs, long hex, long digit runs), never written. There is no `cookie_set`
  or `storage_set` by design.
- **Authenticated, attested bridge.** On macOS and Linux the bridge between
  the host processes is a private Unix-domain socket (no listening port).
  Every connection must pass a kernel peer-UID check, kernel-attested
  executable identity, and an HMAC challenge over a per-run secret. MCP
  clients themselves are admitted against a trusted-client allowlist keyed on
  attested code identity, and any side can revoke trust at any time
  ([ADR-0024](./docs/adr/0024-multi-client-attested-pairing-and-broker.md),
  [ADR-0025](./docs/adr/0025-any-side-revocation-epoch.md)).
- **A global kill switch.** One action from the CLI, the extension, or the
  app halts everything until you release it with proof of presence
  ([ADR-0030](./docs/adr/0030-global-kill-switch-and-audit.md)). Every
  security decision lands in an on-disk audit trail.

Platform honesty: the strong bridge guarantees (portless socket, peer-UID
check, attestation) exist on macOS and Linux only. On Windows the bridge is a
loopback TCP socket gated only by the HMAC secret, and the server warns about
this at startup. Windows support is best-effort. Details in
[SECURITY.md](./SECURITY.md#platform-support).

Full details: [SECURITY.md](./SECURITY.md),
[threat model](./docs/security/threat-model.md),
[trust boundaries](./docs/security/trust-boundaries.md),
[per-tool risk matrix](./docs/security/tool-risk-matrix.md).

## Quickstart with the app (macOS)

The Chromium Bridge desktop app is the primary install path. It bundles the
signed host binary and the extension, and the only command in this path is
the one that registers the server with your MCP client.

> App downloads are not published yet: releases carry the CLI archive and
> extension zip, and the release pipeline's desktop job stays dormant until
> its signing secrets are configured and the publish hold is lifted (see
> [docs/release.md](./docs/release.md)). Until then, build the app from a
> source checkout: `moon run dmg-app` produces a signed disk image,
> `moon run install-app` puts the built app in /Applications, and `moon run run-app`
> builds and launches it in place. A build signed with the free development
> certificate runs only on Macs its provisioning profile lists, and public
> distribution also needs a paid Developer ID for notarization; both remain
> open. Or use the CLI path below.

1. **Install the app.** Get `Chromium Bridge.app` (see the note above) and
   open it. On first launch it registers the native-messaging host with
   every Chromium browser it detects (Chrome, Brave, Edge, ...) and shows
   what it wrote.
2. **Load the extension.** On the app's Setup page, click "Reveal folder" to
   open the bundled extension, then in your browser open `chrome://extensions`,
   enable Developer mode, click "Load unpacked", and select that folder.
   Restart the browser so it picks up the registration.
3. **Pair with Touch ID.** On the app's Pairing page, click Pair (a Touch ID
   prompt appears), then approve the key fingerprint on the extension's
   options page. On macOS the extension requires this enrollment by default
   and refuses to act until the fingerprints match
   ([ADR-0021](./docs/adr/0021-enrollment-ceremony.md)).
4. **Connect your MCP client.** On the Setup page, click Install to put the
   `chromium-bridge` command at `~/.local/bin`. Then register it with your
   client. For Claude Code:

   ```sh
   claude mcp add chromium-bridge -- "$HOME/.local/bin/chromium-bridge"
   ```

   Other clients take the same binary as an `mcpServers` entry; see
   [Connect your MCP client](#connect-your-mcp-client).

Ask your client to "list my browser tabs". The first time you target a new
site, click the Chromium Bridge toolbar icon and approve it.

The app is also the ongoing control panel: pairing, trusted clients, the kill
switch, and the audit trail, with the dangerous acts gated by Touch ID on an
enrolled Mac. See [docs/desktop-app.md](./docs/desktop-app.md).

## Quickstart with the CLI (macOS, Linux, Windows)

The CLI is co-equal: everything the app does, from a terminal, with no
dependency beyond the binary itself. It is the natural path on Linux and
Windows, on headless machines, and in CI.

1. Download the archive for your platform from the
   [latest release](https://github.com/Vivswan/chromium-bridge/releases/latest)
   and extract it. Optionally verify it first; on macOS/Linux (Windows
   archives are `.zip`, checked with your own sha256 tooling):

   ```sh
   shasum -a 256 -c chromium-bridge-<tag>-<platform>-<arch>.tar.gz.sha256
   gh attestation verify chromium-bridge-<tag>-<platform>-<arch>.tar.gz --repo Vivswan/chromium-bridge
   ```

   The full verification story is in
   [SECURITY.md](./SECURITY.md#release-artifact-integrity).

2. Register the extracted binary with your browsers. Registration is
   idempotent, so the same command is the fresh install, the repair, and the
   re-register after moving the binary:

   ```sh
   ./chromium-bridge doctor --fix          # every detected browser
   ./chromium-bridge doctor --fix --browser chrome,brave
   ```

   Keep the binary at a stable path (it is registered in place). On Linux,
   `~/.local/lib/chromium-bridge/` is a good home. `chromium-bridge uninstall`
   reverses exactly what was registered.

3. Load the extension: the archive's `extension/dist/` directory via
   `chrome://extensions`, Developer mode, "Load unpacked". Restart the
   browser.

4. On macOS, pair: `chromium-bridge pair` (Touch ID), then approve the
   fingerprint on the extension's options page; the extension requires
   enrollment there by default. Linux and Windows skip this step.

5. Connect your MCP client to the extracted binary (absolute path), as below.

Building from source instead: `cargo build --release`, then run the same
`doctor --fix` from `target/release/chromium-bridge`
(see [docs/development.md](./docs/development.md)).

The full CLI (doctor, pairing, revocation, kill switch, audit) is documented
in [docs/cli.md](./docs/cli.md).

## Connect your MCP client

Point your client at the installed binary. Run with no arguments, it speaks
MCP over stdio. Use an absolute path; most clients do not expand `~`.

Claude Code:

```sh
claude mcp add chromium-bridge -- "$HOME/.local/bin/chromium-bridge"
```

Claude Desktop and other `mcpServers` JSON clients:

```json
{
  "mcpServers": {
    "chromium-bridge": {
      "command": "/ABSOLUTE/PATH/TO/chromium-bridge",
      "args": []
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.chromium-bridge]
command = "/absolute/path/to/chromium-bridge"
args = []
```

Several clients can be connected at once: the first server instance becomes a
broker and later instances attach to it, each one attested and individually
revocable ([ADR-0024](./docs/adr/0024-multi-client-attested-pairing-and-broker.md)).

On WSL: if your everyday browser is Windows Chrome, install on Windows and
point the WSL client at the `.exe` via `/mnt/c`; do not install a Linux host.
If Chrome runs under WSLg, install natively in Linux. See the
[WSL guide](./docs/wsl.md).

## What you can do: 26 tools

Grouped from the single source of truth, the Rust tool catalogue
([`src/packages/core/src/tools/catalogue.rs`](./src/packages/core/src/tools/catalogue.rs)).
Full blast-radius detail per tool is in the
[tool risk matrix](./docs/security/tool-risk-matrix.md).

### Browsers

| Tool | Does | Risk |
|------|------|------|
| `list_browsers` | List the browsers connected to the bridge (label + open-tab count) | low |

Several browsers can be connected at once (on macOS/Linux each gets its own
native host and label, e.g. `chrome` and `brave`). Every other tool takes an
optional `browser` argument to pick one; with several connected, an
unaddressed call fails with a clear error rather than guessing which
logged-in browser to act in. See
[ADR-0022](./docs/adr/0022-multi-browser-label-routing.md).

### Tabs

| Tool | Does | Risk |
|------|------|------|
| `tab_list` | List open tabs (id, title, url, active) | low |
| `tab_focus` | Bring a tab to the foreground | low |
| `tab_open` | Open a URL in a new tab (host must be allowlisted) | medium |
| `tab_close` | Close a tab (confirmation window) | high |

### Navigate

| Tool | Does | Risk |
|------|------|------|
| `page_navigate` | Load an http(s) URL in the active tab | medium |
| `page_back` / `page_forward` | Step through history | low |
| `page_reload` | Reload the active tab | low |

### Inspect a page

| Tool | Does | Risk |
|------|------|------|
| `page_snapshot` | Accessibility-style tree of interactive elements, each with a stable `ref` | low |
| `page_snapshot_precise` | Authoritative a11y tree via `chrome.debugger` (shadow DOM / complex ARIA); refs use a `p` prefix | medium |
| `page_text` | Visible page text (passwords and card-like numbers masked) | medium |
| `page_screenshot` | Visible viewport as a PNG | medium |
| `console_get` | Recent console output, masked | medium |

### Drive a page

| Tool | Does | Risk |
|------|------|------|
| `page_click` | Click by `ref` or `selector`; submit/link clicks require confirmation | high |
| `page_fill` | Type into a field (native setter, so React/Vue detect it) | high |
| `page_press` | Send a key or combo (confirmation) | high |
| `page_select` | Choose an option in a `<select>` (confirmation) | high |
| `page_hover` | Move the pointer over an element | low |
| `page_scroll` | Up / down / top / bottom / N pixels | low |
| `page_wait_for` | Wait for a selector, text, or navigation | low |
| `page_handle_dialog` | Accept or dismiss a JS dialog (off by default) | high |

### Run code and upload (highest risk)

| Tool | Does | Risk |
|------|------|------|
| `page_eval` | Execute arbitrary JS. Every call confirms, showing the full code; Touch ID on an enrolled Mac. Return value masked by default. Prefer the tools above. | critical |
| `page_upload` | Attach a named local file to a file input (off by default; every call confirms with the path) | critical |

### Read credentials (read-only, always masked)

| Tool | Does | Risk |
|------|------|------|
| `cookie_get` | Read cookies for the active tab, incl. `httpOnly`; allowlisted hosts only | high |
| `storage_get` | Read the page's `localStorage` / `sessionStorage` (same-origin) | high |

No write tools by design; cookie/storage writes are out of scope
([ADR-0010](./docs/adr/0010-cookie-storage-readonly.md)).

## How it works

One Rust binary, two modes, joined by an authenticated local socket. A
desktop app and the CLI manage the same state.

```
MCP client A --stdio--> chromium-bridge (broker: first MCP server instance)
MCP client B --stdio--> chromium-bridge ----attach----^   |
(each client attested against the trusted-client         | bridge socket
 allowlist before it is served)                          | (Unix-domain socket,
                                                          | peer attestation +
                                                          | HMAC; TCP on Windows)
                                                          v
                             chromium-bridge --native-host   <-- spawned by
                                       |                         each browser
                                       | chrome.runtime.connectNative
                                       v
                             Chromium Bridge extension (MV3) --> your page
```

- **MCP server (default mode)**: launched by your MCP client over stdio.
  Speaks JSON-RPC 2.0 (MCP protocol `2025-06-18`). The first instance owns
  the socket and becomes the broker; later instances attach as relays, so
  several clients share the browsers concurrently.
- **`--native-host`**: launched by the browser via the host manifest. A thin
  bridge translating Chrome's native-messaging frames to NDJSON on the
  socket. Each installed browser launches its own host with its own label,
  so one broker can address several browsers by name.
- **Desktop app / CLI**: co-equal management surfaces over the same core
  (registration, pairing, revocation, kill switch, audit). Neither is a
  trust root; capability-granting acts end in a user-presence gate.

Why two processes? The browser spawns the native host; the MCP client spawns
the server. They are not parent and child, so they need an IPC. The native
host stays thin so that MV3 service-worker recycling (about every 5 minutes)
and host restarts do not lose session state.

Deep dive: [docs/architecture.md](./docs/architecture.md).

## Compatibility

| | Supported |
|---|---|
| macOS | Apple Silicon (arm64) prebuilt; the desktop app and Touch ID gates live here. Intel builds from source. |
| Linux | x64 prebuilt; any Chromium-based browser; CLI management surface. |
| Windows | x64 prebuilt (native, no admin). Bridge security is best-effort; see [SECURITY.md](./SECURITY.md#platform-support). |
| Browser | Any Chromium-based browser, Manifest V3 |
| MCP protocol | `2025-06-18` ([ADR-0007](./docs/adr/0007-mcp-protocol-version-2025-06-18.md)) |
| Internal bridge protocol | `1` (`BRIDGE_PROTOCOL_VERSION` in [src/packages/core/src/protocol.rs](./src/packages/core/src/protocol.rs)) |

Known browsers (`--browser` keys): `chrome`, `chromium`, `brave`, `edge`,
`vivaldi`, `opera`. Every Chromium browser reads the same native-messaging
manifest; only the per-user `NativeMessagingHosts` location differs, and the
shared resolver in the core knows them all. For a Chromium variant not in the
table, `doctor --fix --manifest-dir <dir>` targets its directory explicitly
(macOS/Linux; a Windows registry escape hatch is a tracked follow-up).
See [docs/compatibility.md](./docs/compatibility.md) and
[docs/cli.md](./docs/cli.md).

## Configuration

Environment variables read at launch:

| Var | Values | Default | Effect |
|-----|--------|---------|--------|
| `BB_LOG` | `error` \| `warn` \| `info` \| `debug` | `info` | stderr log / audit threshold |
| `BB_LOG_FORMAT` | `text` \| `json` | `text` | Audit-line format; `json` emits one object per line |

The durable audit trail (`chromium-bridge audit`) records independently of
these; see [docs/cli.md](./docs/cli.md#logging-and-audit-bb_log--bb_log_format).

## Troubleshooting

Run the built-in read-only self-check first:

```sh
chromium-bridge doctor    # or: chromium-bridge status
```

It reports whether the server is reachable, the lock-file state, the kill
switch, and each browser's registration state, and `doctor --fix` repairs
registrations in place. Then check your MCP client's server UI (reconnect
via `/mcp` in Claude Code) and the extension's service-worker console at
`chrome://extensions` (look for `[bb]` logs). Full runbook:
[docs/cli.md](./docs/cli.md) and [docs/operations.md](./docs/operations.md).

## Docs map

| Doc | What's in it |
|-----|--------------|
| [docs/quickstart.md](./docs/quickstart.md) | Install and first use, app and CLI (also in [Simplified](./docs/quickstart.zh_CN.md) and [Traditional Chinese](./docs/quickstart.zh_TW.md)) |
| [docs/architecture.md](./docs/architecture.md) | Components, data flow, protocols, security model, key constraints |
| [docs/security/](./docs/security/) | Threat model, trust boundaries, tool risk matrix, incident response |
| [docs/cli.md](./docs/cli.md) | The full CLI: doctor/--fix, uninstall, pairing, revocation, kill switch, audit |
| [docs/desktop-app.md](./docs/desktop-app.md) | The desktop app: what it manages and how to verify it |
| [docs/operations.md](./docs/operations.md) | The binary modes, logging/audit, the runtime directory, reconnect |
| [docs/compatibility.md](./docs/compatibility.md) | Version discipline and the capability/protocol handshake |
| [docs/release.md](./docs/release.md) | Tag-driven releases, prebuilt archives + checksums, SBOM |
| [docs/wsl.md](./docs/wsl.md) | The two WSL modes: Windows Chrome interop and WSLg |
| [docs/adr/](./docs/adr/) | Architecture Decision Records: every "why was this chosen" |

<details>
<summary>Testing and project layout</summary>

Independent suites across two languages:

- Protocol layer: `tests/protocol/e2e.py` (plus `adversarial.py` and
  `chaos.py`) drive the real binary over the actual wire protocols.
- DOM layer: `tests/browser/dom_test.ts` injects the real content script into
  an isolated Chrome via CDP and exercises every op against a real DOM.
- Smoke: `tests/browser/ext_test.ts` boots an isolated Chrome with the built
  extension.
- Real integration (opt-in): `tests/browser/integration_e2e.ts` with
  `BB_REAL_E2E=1`.

See [tests/README.md](./tests/README.md). Layout: `src/apps/host` (the Rust
binary), `src/apps/extension` (MV3, WXT), `src/apps/desktop` (Tauri app),
`src/packages/core` (the Rust library and the single source for cross-process
contracts), `src/packages/shared` (generated TS contracts + validators).

</details>

## Project status

Pre-1.0 ([Cargo.toml](./Cargo.toml)). The protocol layers are covered by
end-to-end, adversarial, and chaos tests; the wire parsers are fuzzed. See
[CHANGELOG.md](./CHANGELOG.md).

## Contributing and governance

[CONTRIBUTING.md](./CONTRIBUTING.md) (workflow),
[GOVERNANCE.md](./GOVERNANCE.md) (how changes get made),
[SECURITY.md](./SECURITY.md) (reporting + review bar),
[docs/development.md](./docs/development.md) (build/test/release loop).

## License

[Apache-2.0](./LICENSE). Copyright the browser-bridge contributors.
