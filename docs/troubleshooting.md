# Troubleshooting

Every entry starts from the read-only self-check, which changes nothing:

```sh
chromium-bridge doctor    # or: chromium-bridge status
```

What each `doctor` row means is on the [CLI page](cli.md#doctor--status-read-only-self-check).

## Doctor says "server not reachable"

- **You see:** `doctor` read an endpoint from the lock file, but its connect-and-drop probe failed.
- **It means:** no MCP client session is up, so nothing is listening, or a previous broker left a stale lock file behind.
- **Do:** open or reconnect a session in your MCP client. The next server instance replaces a stale lock at startup; `doctor` never cleans it up, kills a process, or restarts the server ([the CLI page explains the probe](cli.md#how-to-interpret-server-not-reachable)).

## Doctor says a registration is missing or stale

- **You see:** a browser's registration row reads `missing` or `stale`.
- **It means:** that browser cannot spawn the native host: nothing is registered for it, or what is registered is broken, and the row says which (a dangling launch path, or on Windows a missing registry key).
- **Do:** run `chromium-bridge doctor --fix`, then restart the browser ([registration on the CLI page](cli.md#doctor---fix--uninstall-native-messaging-registration)).

## Doctor says the kill state or the trust record is unreadable

- **You see:** `kill state unreadable - failing closed`, or `kill` and `unkill` refuse to write; `doctor` exits non-zero.
- **It means:** `trust.json` in the runtime directory (the kill latch and the trusted-client allowlist) cannot be read: corrupt JSON, unknown fields, or bad permissions. Every enforcement point reads it fail-closed, so tool calls are refused with `BRIDGE_KILLED`, browser connections are severed, and fresh instances refuse to start.
- **Do:** recover by hand, in the order below. Releasing from a state you cannot read would fail open, and rebuilding the file silently would mask tampering, so nothing does either for you.

1. Run `chromium-bridge doctor` to confirm the state and find the runtime directory.
2. Look at `trust.json` before touching it. A corruption you cannot explain (no crash mid-write, no disk incident) is a possible tampering indicator: read [incident response](security/incident-response.md) first.
3. Delete `trust.json`. That is a factory reset of harness trust, back to the loudly logged unenrolled bootstrap; the paired clients go with it.
4. Re-pair each trusted client (`chromium-bridge pair-client`) and re-engage the kill switch if you had it on. The extension's enrollment pin is unaffected: the host key never lived in this record.

## Doctor reports `policy baseline: none yet`

- **You see:** the `policy baseline:` row reads `none yet`.
- **It means:** the healthy pre-cutover state. No signed baseline has been written, so the extension enforces the deny baseline: every capability grant off, every confirmation on. The row never flips `doctor`'s exit code.
- **Do:** nothing, unless you want grants: `chromium-bridge policy set` writes the first baseline ([policy on the CLI page](cli.md#host-owned-policy-policy)). A present store reports its revision, `signed` or `unsigned`, and whether an unsigned restriction overlay is active; the host reports signed-ness and never claims "valid", since only the extension can verify the signature against its own pinned key.

## Doctor reports `policy baseline: UNREADABLE`

- **You see:** `UNREADABLE (...) - failing closed`, and `doctor` exits non-zero.
- **It means:** the policy store exists but cannot be read or parsed. Every consumer fails closed: the host's dispatch gate denies every tool, and the extension keeps enforcing its stored effective policy or the deny baseline.
- **Do:** inspect the store before anything else. It is never replaced with defaults for you, because defaults can be laxer than the policy you restricted, and a relaxation lever made of garbage is not one.

## The native host exits every few minutes

- **You see:** the host process ends and restarts, and the extension's connection state blinks about every five minutes.
- **It means:** Chromium force-restarts the MV3 service worker about every five minutes, which closes the native-messaging port; the host gets EOF on stdin and exits, and the extension reconnects after two seconds ([the reconnect flow](architecture.md#52-native-host-reconnect)).
- **Do:** nothing. A call in flight on the closing connection fails with `CONNECTION_LOST`; the next call re-resolves the active tab, and session bookkeeping lives in the MCP server rather than the service worker, so the reconnect needs no re-pair.

## The extension and the host are different versions

The host-owned policy frames were added without a bridge protocol version bump: they are additive and host-handled, so the two skews behave as the table says. Which number moves when is on the [release page](release.md#versions).

| Skew | Behavior |
| --- | --- |
| New extension, old host | The host never pushes a policy frame, so the extension never sends one either (an old host would classify the unknown frame as forwardable and the server's strict parse would tear the browser leg down). The extension stays pre-cutover and enforces the deny baseline. |
| Old extension, new host | The old extension drops the unfamiliar `policy_current` push (pinned by test) and keeps its local settings; the new host still applies its own policy at dispatch, so the combined enforcement is never more permissive than the old extension alone. |
| New extension, a host without the options page's frames | The options page sends `registration_status`, `registration_repair`, `policy_restrict`, `audit_read`, and `doctor_report` on demand, so the never-speak-first rule does not cover them: the broker's strict parse tears the browser leg down. Accepted before the first release, since no shipped host lacks them; covering it later needs the deferred handshake to advertise the host's control frames and the extension to gate its sends on that. |

## A Mac without a Secure Enclave cannot enroll

- **You see:** `chromium-bridge pair` refuses on a pre-T2 Intel Mac.
- **It means:** every grant and policy signature hangs off the Secure Enclave key, which that hardware cannot hold, and the `requireEnrollment` opt-out was retired. The bridge stays blocked there, by design and with no recovery path.
- **Do:** use an Apple Silicon or T2 Mac, or Linux or Windows, where enrollment is not required.

## Running under WSL

Chrome, the native host it launches, and the MCP server must all belong to the same operating system. Pick the mode by where Chrome runs.

### WSL client with Windows Chrome

The usual setup: the MCP client runs in WSL and the everyday browser is Windows Chrome. No Linux install and no Chrome in WSL.

1. On Windows, extract the Windows release archive (or build from source), run `chromium-bridge.exe doctor --fix` there, and load the archive's `extension/dist` into Windows Chrome.
2. In the WSL MCP configuration, run the Windows `.exe` directly. WSL interop launches it as a Windows process, so it shares the registry, the `%LOCALAPPDATA%` lock file, and the native-messaging host with Windows Chrome.

For Codex, in `~/.codex/config.toml`:

```toml
[mcp_servers.chromium-bridge]
command = "/mnt/c/Users/YOUR_WINDOWS_USER/AppData/Local/chromium-bridge/chromium-bridge.exe"
args = []
```

Replace `YOUR_WINDOWS_USER` and confirm the path exists; the example assumes the binary lives in `%LOCALAPPDATA%\chromium-bridge`.

### WSLg with Linux Chrome or Chromium

When the browser itself runs inside WSLg, install natively in Linux: put the Linux `chromium-bridge` binary at a stable path in the WSL filesystem and register it.

```sh
./chromium-bridge doctor --fix                    # every detected browser
./chromium-bridge doctor --fix --browser chrome   # Google Chrome only
./chromium-bridge doctor --fix --browser chromium # Chromium only
```

| What | Where |
| --- | --- |
| manifests | `~/.config/google-chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json`, `~/.config/chromium/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json` |
| lock file | `$XDG_RUNTIME_DIR/chromium-bridge/run.lock`; without `XDG_RUNTIME_DIR`, `$XDG_CACHE_HOME/chromium-bridge/run.lock` or `~/.cache/chromium-bridge/run.lock` |

Load the release archive's `extension/dist` (or a built `build/extension/chrome-mv3`) at `chrome://extensions` in the Linux browser, then point the MCP client at the Linux binary (Codex again, in `~/.codex/config.toml`):

```toml
[mcp_servers.chromium-bridge]
command = "/home/YOUR_WSL_USER/.local/lib/chromium-bridge/chromium-bridge"
args = []
```

### Do not mix the two systems

- **Windows Chrome** cannot read the Linux native-messaging manifest inside WSL and cannot launch a Linux ELF binary.
- **Linux Chrome in WSLg** does not read the Windows registry and cannot use Windows Chrome's registration.
- **Launching a Windows `.exe` from WSL is not mixing:** that process is still a Windows process, which is why the first mode works.

When a connection fails under WSL, confirm Chrome, the native host, and the MCP server all land on the same side, then check the lock file: `%LOCALAPPDATA%\chromium-bridge\run.lock` on Windows, the XDG path above on Linux.

## A lock file is left behind after a crash

- **You see:** `doctor` reports a lock file whose endpoint is not reachable, after a broker exited abnormally.
- **It means:** the lock file (`run.lock` in the runtime directory) outlived its broker. There is no forced takeover of a live owner: a second instance that finds a live broker attaches to it instead.
- **Do:** start a client session. The next server instance probes the stale endpoint and replaces the lock at startup; `doctor` only reads it.
