# chromium-bridge

Let any **MCP client** — Claude Code, Claude Desktop, Codex, or anything that
speaks the Model Context Protocol — drive **your real Chrome**: your tabs, your
logged-in sessions, your cookies, through a Chrome extension + a native
messaging host. No second browser, no CDP debug port, no `--remote-debugging`
flag.

Because it operates the browser you're already signed into, an agent can do
things that a fresh headless browser can't: read a page behind your auth,
click through an app you're logged into, pull a token your framework stashed in
`localStorage`. That power is also the risk — see **Security** below before you
install.

---

## 🔒 Security first — read this

chromium-bridge drives a **real, authenticated Chrome**. It can read page
content, cookies (including `httpOnly`), and web storage, and can run
JavaScript in your pages. The guardrails that keep that safe:

- **Approve every site.** A new origin triggers a popup prompt; nothing runs on
  a site you haven't approved (which also grants the host permission the content
  script needs).
- **Confirm high-risk actions.** Submit-button clicks and link navigations pop
  an on-page confirmation you must approve; a repeat of the same action on the
  same origin within a short grace window skips the re-prompt. Tab close and
  **every `page_eval`** are excluded from that grace window and re-prompt on
  every call.
- **Read-only credentials.** Cookies and storage can be *read* (always masked —
  JWTs, long hex, long digit runs), never written. There is no `cookie_set` /
  `storage_set` by design.
- **Authenticated bridge.** No connection between the two host processes is
  served until it answers an HMAC challenge over a per-run secret. On
  macOS/Linux the bridge is a private Unix-domain socket (no listening port),
  and the server also checks the peer's UID and kernel-attests that the peer
  runs this same binary; the native-host manifest pins the extension ID.

**Platform support:** the strong bridge guarantees (portless Unix-domain
socket, peer-UID check, kernel attestation of the peer binary) exist on macOS
and Linux only. On Windows the bridge is a loopback TCP socket that any local
process can reach, gated only by the HMAC secret in the lock file, and the
server warns about this at startup. Windows support is best-effort; treat it
accordingly. Details in [SECURITY.md](./SECURITY.md#platform-support).

Full details: **[SECURITY.md](./SECURITY.md)** ·
[threat model](./docs/security/threat-model.md) ·
[trust boundaries](./docs/security/trust-boundaries.md) ·
[per-tool risk matrix](./docs/security/tool-risk-matrix.md).

---

## Quickstart (≈60 seconds)

**Prereqs:** any Chromium-based browser (Chrome, Chromium, Brave, Edge, Vivaldi,
Opera, ...). The **prebuilt** path below
needs *no Rust and no Node.js*.

### 1. Get the binary + extension

Download the archive for your platform from the
**[latest release](https://github.com/Vivswan/chromium-bridge/releases/latest)**,
then run the bundled installer. `install.sh` auto-detects the prebuilt tarball
and installs the shipped binary + extension directly.

<details open>
<summary><b>macOS (Apple Silicon) / Linux x64</b></summary>

```sh
tar xzf chromium-bridge-*-macos-arm64.tar.gz   # or -linux-x64
cd chromium-bridge-*-macos-arm64
./install.sh
```

Installs the binary to `~/.chromium-bridge/` (macOS) or
`~/.local/share/chromium-bridge/` (Linux) and writes the native-messaging host
manifest with the pinned extension ID already trusted.

> **macOS Gatekeeper:** the prebuilt binary is not yet notarized. The installer
> verifies the binary against the release's published checksum and then clears
> the quarantine attribute on the installed copy, so no manual step is needed
> for the binary itself. If macOS refuses to run `install.sh` because the
> script is quarantined, clear it first: `xattr -d com.apple.quarantine install.sh`.
</details>

<details>
<summary><b>Windows x64</b></summary>

```powershell
Expand-Archive chromium-bridge-*-windows-x64.zip -DestinationPath .
cd chromium-bridge-*-windows-x64
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Installs `chromium-bridge.exe` to `%LOCALAPPDATA%\chromium-bridge\` and registers
the host under the Native Messaging registry key of each detected Chromium
browser (pick specific ones with `-Browser chrome,brave`, or point at any other
with `-NmRegistry`). No admin rights needed.

> **SmartScreen:** the prebuilt exe is unsigned, so SmartScreen may warn on first
> run — choose **More info → Run anyway**.
</details>

<details>
<summary><b>Build from source (needs Rust + Node.js/npm)</b></summary>

```sh
git clone https://github.com/Vivswan/chromium-bridge && cd chromium-bridge
./install/install.sh            # --browser auto|all|chrome,chromium,brave,... | --nm-dir DIR
```

`install/install.sh` builds the Rust binary and the extension bundle, then installs both.
See [docs/development.md](./docs/development.md) for the full build/test loop.
</details>

> Only need the extension (binary already installed)? Grab
> `chromium-bridge-extension-<tag>.zip` from the same release and unzip it — it
> contains a top-level `dist/` you can load directly.

<details>
<summary><b>Verifying your binary (checksums, provenance, reproducible builds)</b></summary>

In prebuilt mode `install.sh` verifies the shipped binary before installing
anything, through an anchor whose trust is independent of the release asset, so
a swapped or tampered binary cannot pass. There are two paths:

- Online (the default): it hashes the exact copy it is about to install and
  requires a successful GitHub build-provenance attestation for those bytes,
  checked with an authenticated `gh` CLI against the repository pinned in the
  installer. The release's `.binary.sha256` is fetched and compared too, but
  only as a corruption check: it lives in the same release as the binary, so on
  its own it is not proof of origin. If `gh` is missing or unauthenticated, or
  the attestation does not verify, the install aborts.
- Offline: pass a hash you obtained out of band with
  `./install.sh --expected-sha256 <hash>`. That hash is itself the independent
  anchor, so this path needs no `gh` and fetches nothing.

The archive's `RELEASE.txt` names the tag and platform but cannot pick the
repository (a fork's release needs an explicit `--release-repo`). Any mismatch
aborts the install, and on macOS the quarantine attribute is cleared only after
verification has passed.

One thing the bundled installer cannot prove is its own integrity: it ships
inside the archive it checks. To rule out a tampered archive entirely, verify
the archive before running anything from it:

```sh
shasum -a 256 -c chromium-bridge-<tag>-<platform>-<arch>.tar.gz.sha256
gh attestation verify chromium-bridge-<tag>-<platform>-<arch>.tar.gz --repo <owner>/<repo>
```

The binary itself builds reproducibly, so you can also re-derive its hash from
source instead of trusting the release pipeline. Install the exact toolchain
pinned in `rust-toolchain.toml` via [rustup](https://rustup.rs) (a Homebrew or
distro rustc embeds different standard-library paths and will not match), on
the same platform the release targets, then:

```sh
git checkout <tag>
./scripts/build-repro.sh
shasum -a 256 target/release/chromium-bridge   # compare with the release's .binary.sha256
```

Two honest limits. Reproducibility is verified across clean rebuilds and
checkout paths on one machine so far; matching the CI-published hash from
your machine also depends on the platform SDK and linker matching the
runner's, and the archives are not bit-reproducible at all (tar and gzip
embed metadata), which is why the release publishes the binary's hash
separately. And the binaries are not yet Apple-codesigned, notarized, or
Authenticode-signed: once a real signing identity lands, a released macOS
binary will carry a signature a local rebuild cannot have, and verification
there will move from whole-file hashes to comparing cdhashes.
`install.ps1` on Windows does not verify yet. See
[SECURITY.md](./SECURITY.md#release-artifact-integrity) for the full picture.
</details>

### 2. Load the extension

`chrome://extensions` → enable **Developer mode** → **Load unpacked** → select
the **`extension/dist/`** directory (the build output, *not* `extension/`).

The extension ID is **pinned** to `mkjjlmjbcljpcfkfadfmhblmmddkdihf` (via the
manifest `key`), which the installer already trusted — **nothing to copy, nothing
to patch.**

### 3. Register the MCP server

Point your client at the installed binary (run with no args — it speaks MCP over
stdio). Use an **absolute path**; most clients don't expand `~`.

- **Claude Code (CLI):**
  ```sh
  claude mcp add chromium-bridge -- "$HOME/.chromium-bridge/chromium-bridge"
  ```
- **Claude Desktop / generic (`mcpServers` JSON):** copy the `chromium-bridge`
  entry from [`mcp-config.example.json`](./install/mcp-config.example.json).
- **Codex (`~/.codex/config.toml`):**
  ```toml
  [mcp_servers.chromium-bridge]
  command = "/absolute/path/to/chromium-bridge"
  args = []
  ```

### 4. Restart Chrome & try it

Restart Chrome so it loads the native-host manifest, then reconnect your MCP
client and ask: **"list my browser tabs."** The first time you target a new
site, click the Chromium Bridge toolbar icon and approve it.

> On **WSL**: if your everyday browser is Windows Chrome, install on Windows and
> point the WSL client at the `.exe` via `/mnt/c` — don't install a Linux host.
> If Chrome runs under WSLg, install natively in Linux. See the
> [WSL guide](./docs/wsl.md).

---

## What you can do — 16 tools

Grouped from the single source of truth,
[`contracts/tools.json`](./contracts/tools.json):

### Browsers
| Tool | Does | Risk |
|------|------|------|
| `list_browsers` | List the browsers connected to the bridge (label + open-tab count) | low |

Several browsers can be connected at once (on macOS/Linux each gets its own
native host and label, e.g. `chrome` and `brave`). Every other tool takes an
optional `browser` argument to pick one. With a single browser connected no
argument is needed; with several, an unaddressed call fails with a clear
error rather than guessing which logged-in browser to act in. Windows
manifests launch the binary with no arguments, so Windows browsers all share
one unlabeled slot for now. See
[ADR-0022](./docs/adr/0022-multi-browser-label-routing.md).

### Tabs
| Tool | Does | Risk |
|------|------|------|
| `tab_list` | List open tabs (id, title, url, active) | low |
| `tab_focus` | Bring a tab to the foreground | low |
| `tab_open` | Open a URL in a new tab (host must be allowlisted) | medium |
| `tab_close` | Close a tab (on-page confirmation) | high |

### Inspect a page
| Tool | Does | Risk |
|------|------|------|
| `page_snapshot` | Accessibility-style tree of interactive elements, each with a stable `ref` | low |
| `page_snapshot_precise` | Authoritative a11y tree via `chrome.debugger` (shadow DOM / complex ARIA); refs use a `p` prefix | medium |
| `page_text` | Visible page text (passwords & card-like numbers masked) | medium |
| `page_screenshot` | Visible viewport as a PNG | medium |

### Drive a page
| Tool | Does | Risk |
|------|------|------|
| `page_click` | Click by `ref` or `selector`; submit/link clicks require confirmation | high |
| `page_fill` | Type into a field (native setter, so React/Vue detect it) | high |
| `page_scroll` | Up / down / top / bottom / N pixels | low |
| `page_wait_for` | Wait for a selector, text, or navigation | low |

### Run code (highest risk)
| Tool | Does | Risk |
|------|------|------|
| `page_eval` | ⚠ Execute arbitrary JS. **Every call** shows the full code in a confirmation prompt; return value masked by default. Prefer the tools above. | critical |

### Read credentials (read-only, always masked)
| Tool | Does | Risk |
|------|------|------|
| `cookie_get` | Read cookies for the active tab, incl. `httpOnly`; allowlisted hosts only | high |
| `storage_get` | Read the page's `localStorage` / `sessionStorage` (same-origin) | high |

*No write tools by design — cookie/storage writes are out of scope
([ADR-0010](./docs/adr/0010-cookie-storage-readonly.md)).*

---

## How it works

One Rust binary, two modes, joined by a local socket:

```
MCP client ──stdio MCP──▶ chromium-bridge (MCP server, Rust)
(Claude Code,             │
 Codex, …)                │ bridge socket (NDJSON, HMAC auth; Unix-domain
                          │ socket on macOS/Linux, loopback TCP on Windows)
                          ▼
                   chromium-bridge --native-host  ◀── spawned by Chrome
                          │
                          │ chrome.runtime.connectNative
                          ▼
                   Chromium Bridge extension (MV3) ──▶ your page
```

- **MCP server (default mode)** — launched by your MCP client over stdio.
  Speaks JSON-RPC 2.0 (MCP protocol `2025-06-18`). Owns session state and the
  bridge socket, published via a lock file.
- **`--native-host`** — launched *by Chrome* via the host manifest. A thin
  bridge translating Chrome's native-messaging frames (4-byte LE length + JSON)
  to NDJSON on the socket. On macOS/Linux each installed browser launches its
  own host with its own `--label` (baked into that browser's
  `run-host-<browser>.sh` wrapper), so one server can hold several browsers
  at once and address them by name.

Why two processes? Chrome spawns the native host; the MCP client spawns the
server — they aren't parent/child, so they need an IPC. The native host stays
dumb so that MV3 service-worker recycling (~every 5 min) and host restarts don't
lose session state.

Deep dive: [docs/architecture.md](./docs/architecture.md) ·
[ADR-0002](./docs/adr/0002-three-process-architecture-localhost-tcp.md).

---

## Compatibility

| | Supported |
|---|---|
| **macOS** | Apple Silicon (arm64) prebuilt. Intel builds from source (Rosetta 2 runs x86_64 on Apple Silicon, not the arm64 build on Intel). |
| **Linux** | x64 prebuilt; any Chromium-based browser. |
| **Windows** | x64 prebuilt (native, no admin). Bridge security is best-effort; see [SECURITY.md](./SECURITY.md#platform-support). |
| **Browser** | Any Chromium-based browser, Manifest V3 |
| **MCP protocol** | `2025-06-18` ([ADR-0007](./docs/adr/0007-mcp-protocol-version-2025-06-18.md)) |
| **Internal bridge protocol** | `1` (see [contracts/protocol-version.json](./contracts/protocol-version.json)) |

Every Chromium browser reads the same native-messaging manifest (same pinned
extension ID, same `allowed_origins`); only the per-user `NativeMessagingHosts`
directory differs. The installer knows these by name (`--browser` /
`-Browser` keys):

| Key | macOS `NativeMessagingHosts` under | Linux (`$XDG_CONFIG_HOME`) | Windows registry root (HKCU) |
|---|---|---|---|
| `chrome` | `Google/Chrome/` | `google-chrome/` | `Software\Google\Chrome` |
| `chromium` | `Chromium/` | `chromium/` | `Software\Chromium` |
| `brave` | `BraveSoftware/Brave-Browser/` | `BraveSoftware/Brave-Browser/` | `Software\BraveSoftware\Brave-Browser` |
| `edge` | `Microsoft Edge/` | `microsoft-edge/` | `Software\Microsoft\Edge` |
| `vivaldi` | `Vivaldi/` | `vivaldi/` | `Software\Vivaldi` |
| `opera` | `com.operasoftware.Opera/` | `opera/` | `Software\Opera Software` |

`--browser auto` (the default) installs for every browser whose config directory
already exists; `--browser all` targets every row; a comma-separated list
(`--browser chrome,brave`) targets specific ones. For any Chromium browser not
in the table, use the escape hatch: `--nm-dir <NativeMessagingHosts dir>` on
macOS/Linux (repeatable), or `-NmRegistry <HKCU key>` on Windows (pass an array
for several, e.g. `-NmRegistry 'keyA','keyB'`). Uninstall clears every row above
automatically; because the installer keeps no record of escape-hatch targets,
re-pass the same `--nm-dir` / `-NmRegistry` to the uninstall command to clear
those too.

Prebuilt targets come from the tag-driven [release workflow](./.github/workflows/release.yml);
see [docs/compatibility.md](./docs/compatibility.md).

## Configuration

Environment variables read at launch (source: `src/log.rs`, [docs/cli.md](./docs/cli.md)):

| Var | Values | Default | Effect |
|-----|--------|---------|--------|
| `BB_LOG` | `error` \| `warn` \| `info` \| `debug` | `info` | stderr log / audit threshold. `warn`/`error` silences audit lines. |
| `BB_LOG_FORMAT` | `text` \| `json` | `text` | Audit-line format; `json` emits one object per line for machine collection. |

## Troubleshooting

Run the built-in read-only self-check first:

```sh
chromium-bridge doctor    # or: chromium-bridge status
```

It reports whether the server is reachable, the lock-file port/pid, and common
misconfigurations. Then check your MCP client's server UI (reconnect via `/mcp`
in Claude Code) and the extension's Service Worker console at
`chrome://extensions` (look for `[bb]` logs). Full runbook:
[docs/cli.md](./docs/cli.md) · [docs/operations.md](./docs/operations.md).

---

## Docs map

| Doc | What's in it |
|-----|--------------|
| [docs/requirements.md](./docs/requirements.md) | Goals, user stories, functional/non-functional requirements, scope boundaries |
| [docs/architecture.md](./docs/architecture.md) | Components, data flow, protocols, security model, key constraints |
| [docs/security/](./docs/security/) | Threat model, trust boundaries, tool risk matrix, incident response |
| [docs/cli.md](./docs/cli.md) | `doctor`/`status` self-check, troubleshooting |
| [docs/operations.md](./docs/operations.md) | The two binary modes, logging/audit, the lock file, reconnect |
| [docs/compatibility.md](./docs/compatibility.md) | Version discipline and the capability/protocol handshake |
| [docs/release.md](./docs/release.md) | Tag-driven releases, prebuilt tarballs + checksums, SBOM |
| [docs/wsl.md](./docs/wsl.md) | The two modes: Windows Chrome interop and WSLg |
| [docs/adr/](./docs/adr/) | Architecture Decision Records (ADRs): every "why was this chosen" |
| [contracts/](./contracts/README.md) | Tool catalogue, error codes, capabilities, protocol version (source of truth for cross-process contracts) |

<details>
<summary>Testing & project layout</summary>

Independent suites across two languages, run together with
`./tests/run_all.sh`:

- **Protocol layer** — `tests/e2e.py` drives the real binary (MCP over stdio,
  `--native-host` framing, mock extension over the TCP bridge).
- **DOM layer** — `tests/dom_test.ts` injects the real content script into
  headless Chrome via CDP and exercises every op against a real DOM.
- **Smoke** — `tests/ext_test.ts` boots real Chrome with `extension/dist/`.
- **Real integration** (opt-in) — `tests/integration_e2e.ts`; run with
  `BB_REAL_E2E=1`. Needs Chrome for Testing / Chromium.

See [tests/README.md](./tests/README.md). Rough source layout: `src/` (Rust:
`main.rs` mode dispatch, `protocol.rs`, `ipc.rs`, `native_host.rs`,
`mcp_server.rs`, `tools/`, `session.rs`), `extension/src/` (TypeScript →
`dist/` via esbuild), `contracts/` (cross-process contracts), `docs/`.
</details>

---

## Project status

**v0.1.0** ([Cargo.toml](./Cargo.toml)) plus phase-two/three tools. Protocol
layers (NM framing, MCP JSON-RPC, TCP bridge) are covered by end-to-end tests.
The default snapshot is a content-script approximation of the a11y tree;
`page_snapshot_precise` is the debugger-based fallback for complex ARIA/shadow
DOM. Cookie/storage access is read-only and masked. See
[CHANGELOG.md](./CHANGELOG.md).

## Contributing & governance

[CONTRIBUTING.md](./CONTRIBUTING.md) (workflow) ·
[GOVERNANCE.md](./GOVERNANCE.md) (how changes get made) ·
[SECURITY.md](./SECURITY.md) (reporting + review bar) ·
[docs/development.md](./docs/development.md) (build/test/release loop).

## License

[Apache-2.0](./LICENSE). Copyright the browser-bridge contributors.
