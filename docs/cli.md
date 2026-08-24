# CLI and troubleshooting: chromium-bridge

> This doc is the reference for the `chromium-bridge` binary's subcommands and the common troubleshooting paths. The CLI is one of two co-equal management surfaces; the other is the [desktop app](./desktop-app.md), and both drive the same engines in the core, so either can inspect or repair what the other wrote. Components and process boundaries are in [architecture.md](./architecture.md); on-disk paths are in [architecture.md section 4.3](./architecture.md#43-on-disk-artifacts).

## Subcommand overview

`chromium-bridge` is a single binary with subcommand dispatch (see [ADR-0001](./adr/0001-use-rust-single-binary.md)):

| Invocation | Mode | Description |
|------|------|------|
| `chromium-bridge` (no arguments) | MCP server | Default mode, spawned by the MCP client. The first instance becomes the broker; later instances attach to it ([ADR-0024](./adr/0024-multi-client-attested-pairing-and-broker.md)). |
| `chromium-bridge --native-host [--label <browser>]` | native host | Thin bridge, spawned by the browser via the host manifest. Never invoked by hand. |
| `chromium-bridge doctor` (alias `status`) | read-only diagnostics | Environment and connectivity self-check; changes nothing. |
| `chromium-bridge doctor --list` | read-only diagnostics | One line per known browser: detection and registration state. |
| `chromium-bridge doctor --fix` | repair / install | Registers (or re-registers) this binary as the native-messaging host. The only mutating form of doctor. |
| `chromium-bridge uninstall` | removal | Removes exactly the registrations this project wrote, nothing else. |
| `chromium-bridge pair [--reset]` | enrollment | Mints the Secure Enclave enrollment key (macOS); every use of the key demands Touch ID ([ADR-0021](./adr/0021-enrollment-ceremony.md)). |
| `chromium-bridge revoke` | enrollment | Deletes the enrollment key; a pinning extension then fails closed ([ADR-0025](./adr/0025-any-side-revocation-epoch.md)). |
| `chromium-bridge enclave-status [--json]` | read-only | Prints the enrollment state and key fingerprint. |
| `chromium-bridge presence-selftest` | diagnostic | Raises one user-presence prompt and reports the result, without a browser ([ADR-0031](./adr/0031-touch-id-confirmations-and-presence-grants.md)). |
| `chromium-bridge pair-client --name <label> (--this-parent \| --hash <hex> \| --team-id <id>)` | trusted clients | Adds an MCP-client harness to the trusted-client allowlist; presence-gated ([ADR-0024](./adr/0024-multi-client-attested-pairing-and-broker.md)). |
| `chromium-bridge revoke-client --name <label>` | trusted clients | Removes a client; a live broker drops it immediately. |
| `chromium-bridge list-clients` | read-only | Prints the trusted-client allowlist. |
| `chromium-bridge kill` | kill switch | Engages the global kill switch: halts ALL bridge activity until an explicit release ([ADR-0030](./adr/0030-global-kill-switch-and-audit.md)). |
| `chromium-bridge unkill` | kill switch | Releases the kill switch, after proof of user presence (Touch ID on an enrolled Mac; otherwise an interactive terminal confirmation that refuses a piped stdin). |
| `chromium-bridge policy show [--json]` | read-only | Prints the host-owned policy state and the effective policy ([ADR-0032](./adr/0032-host-owned-policy-settings.md)). |
| `chromium-bridge policy set <field flags> [--json]` | policy (grant lane) | Mints a fresh SIGNED policy baseline: one Touch ID tap. Signature-only; refuses up front where no enrollment key exists. |
| `chromium-bridge policy restrict <field flags>` | policy (free lane) | Applies an unsigned restriction overlay; no prompt, because it can only remove capability. |
| `chromium-bridge policy history [--json]` | read-only | Prints the superseded-revision ring. |
| `chromium-bridge policy pending-import [--json]` | read + self-heal | Prints the pending legacy-import state (finalizing a stranded mid-consume record first); `--json` is the only mode that prints the bag. |
| `chromium-bridge policy rollback --revision <n> [--json]` | policy | Re-derives a past revision's effective policy as a FRESH write, never a replay. |
| `chromium-bridge audit [--limit <n>]` | read-only audit | Prints the on-disk audit trail, oldest first (default: the last 200 records). |
| `chromium-bridge --help` | help | Usage information. |

## doctor / status (read-only self-check)

`doctor` (with `status` as an equivalent alias) is a read-only subcommand: it does not bind the socket, does not write the lock file, and does not spawn any child process. It only probes the current environment and prints its conclusions, to answer the question "why can't I connect".

It reports:

- **Version / platform**: the binary version (Cargo is the source) and the running platform.
- **Lock file**: whether the bridge lock file exists in the runtime directory, and the endpoint and pid recorded in it.
- **Server reachability**: a passive connect-and-drop probe against our own bridge socket (no bytes sent), reporting `reachable` / `not reachable`. The desktop app's status view shares this exact probe.
- **Kill switch**: engaged, clear, or unreadable. `doctor` exits non-zero while the switch is engaged or its state cannot be read.
- **Native-host registrations**: for each known browser (chrome, chromium, brave, edge, vivaldi, opera), whether it looks present for this user and the state of its registration for `com.vivswan.chromium_bridge.host`: `ok`, `missing`, `stale` (ours, but its launch path dangles), or not ours. The diagnosis comes from the same resolver `--fix` repairs with, so what doctor reports is exactly what `--fix` produces.

### How to interpret "server not reachable"

"Server not reachable" means `doctor` read the endpoint from the lock file, but the probe failed. Common causes:

1. **No MCP server is running.** The server is spawned by the MCP client (such as Claude Code) inside its session. If no client session is up, nothing is listening, and "not reachable" is the expected state. Confirm the client has the chromium-bridge server configured and a session open.
2. **Stale lock file.** A previous broker exited abnormally and left the lock file behind. The next server instance detects and replaces a stale lock at startup; just start a new client session.

> `doctor` only probes; it does not repair. It will not kill processes, delete the lock file, or restart the server. When you see "not reachable", re-establish the session from the MCP client side rather than intervening in processes by hand.

If a registration is missing or stale for a browser you use, that browser cannot spawn the native host. Run `chromium-bridge doctor --fix`, then restart the browser.

## doctor --fix / uninstall (native-messaging registration)

There are two equal ways to register the native-messaging host: the desktop app, which registers itself with your browsers on first launch, and the CLI below, which does the same thing from a terminal. Both drive one shared engine (`registration.rs`), so they write identical registrations and either one can repair what the other wrote. The CLI needs nothing but the host binary itself, which also makes it the natural choice for Linux, Windows, headless machines, and CI.

`chromium-bridge doctor --fix` (re-)registers the binary you invoke it from as the native-messaging host: for each targeted browser it writes the `com.vivswan.chromium_bridge.host.json` manifest where that browser looks for it. The repair is idempotent re-registration, so on a fresh machine `--fix` is also the first registration, and after moving the binary it refreshes a stale one. It never builds, downloads, or copies anything; the manifest points at this binary's own resolved path (through a small per-browser wrapper script on macOS/Linux, which bakes in `--native-host --label <browser>` because Chrome's manifest format has no `args` field). It refuses to overwrite a manifest it cannot verify this project wrote.

Selecting browsers:

```text
chromium-bridge doctor --fix                      # every browser detected for this user
chromium-bridge doctor --fix --browser chrome,brave
chromium-bridge doctor --fix --all                # every known browser, detected or not
chromium-bridge doctor --fix --manifest-dir DIR   # exact NativeMessagingHosts dir
                                                  # (absolute; repeatable), for a Chromium
                                                  # variant we do not know by name
chromium-bridge doctor --list                     # read-only: detection + registration state
```

Known browser keys: `chrome`, `chromium`, `brave`, `edge`, `vivaldi`, `opera`. "Detected" means the browser is actually installed, as far as a cheap local check can tell. On macOS that check is the application bundle under `/Applications` or `~/Applications` - a leftover per-user config directory alone (uninstalled browsers keep those forever, and some dev tools create them) does not count, and a freshly installed browser counts before its first run. On Linux and Windows the check is the per-user config (profile) directory, the best cheap signal there. A browser installed somewhere non-standard on macOS reads as "not detected"; it can still be registered explicitly with `--browser <key>` or `--manifest-dir`. Plain `doctor`'s summary counts only detected browsers, so a healthy explicit registration for a non-standard install keeps the summary below "OK" even though the bridge works - the per-browser lines tell the real story. When nothing is detected, `--fix` refuses and asks for an explicit selection instead of guessing.

`chromium-bridge uninstall` reverses exactly what this project registers (via `--fix` or the app): the per-browser manifests and the wrapper scripts. Re-pass any `--manifest-dir` you registered. Before deleting a manifest it verifies the file's content is ours (our host id and description marker); anything else is reported and left in place, and so is anything it cannot read and verify. It never touches this binary, your browsers, or the loaded extension.

Platform notes:

- **Linux AppImage / temp paths**: a registration pointing into an AppImage's FUSE mount (or any temp dir) breaks when that path disappears. `--fix` warns when it detects this. Copy the binary to a stable location first, for example `~/.local/lib/chromium-bridge/chromium-bridge`, and run `doctor --fix` from there.
- **Windows**: registration is an `HKCU` registry key per browser plus a manifest file under `%LOCALAPPDATA%\chromium-bridge`. The code path compiles and mirrors what the retired `install.ps1` script did, but it has not yet been verified on a real Windows machine; treat Windows registration as best-effort until then. Browser detection on Windows (per-user profile directories; Opera under the roaming profile) carries the same caveat.

## Enrollment: pair / revoke / enclave-status

The enrollment ceremony ([ADR-0021](./adr/0021-enrollment-ceremony.md)) binds the host to this machine's Secure Enclave and to you:

- `chromium-bridge pair` mints a P-256 key inside the Secure Enclave whose every use requires user presence (Touch ID or the login password), then performs a presence-gated self-test signature and prints the key's SHA-256 fingerprint. Compare that fingerprint with the one the extension shows on its enrollment screen; a mismatch means something sits between them.
- `chromium-bridge pair --reset` replaces the key with a fresh one (presence-gated again); the extension must re-pin.
- `chromium-bridge revoke` deletes the key. The host confirms the deletion and pushes a revocation to the extension, which fails closed ([ADR-0025](./adr/0025-any-side-revocation-epoch.md)).
- `chromium-bridge enclave-status [--json]` reports the current state read-only.

Enrollment is what upgrades the highest-risk confirmations (`page_eval`, `page_upload`, kill-switch release, client pairing) from an on-screen dialog to a hardware Touch ID tap ([ADR-0031](./adr/0031-touch-id-confirmations-and-presence-grants.md)). `chromium-bridge presence-selftest` raises exactly one such prompt so you can see it work without a browser.

## Trusted clients: pair-client / revoke-client / list-clients

By default (unenrolled), any process that spawns the server is served, and every start logs that open posture at ERROR level. Creating the trusted-client allowlist closes it ([ADR-0024](./adr/0024-multi-client-attested-pairing-and-broker.md)):

```text
chromium-bridge pair-client --name claude-code --this-parent
chromium-bridge pair-client --name codex --hash <sha256-hex>
chromium-bridge pair-client --name claude-desktop --team-id <apple-team-id>
chromium-bridge list-clients
chromium-bridge revoke-client --name codex
```

- `--this-parent` measures the process that spawned this CLI invocation (run it from inside the client you want to trust).
- Authorization keys on the attested anchor (a signing Team ID where the client is signed, an image hash otherwise); the `--name` is a label for logs and revocation, never the authorization key.
- Hash anchors change when the client updates; re-run `pair-client` with the same name to replace the entry (the re-pair path).
- Adding a client is a capability grant, so it is presence-gated: Touch ID on an enrolled Mac, an interactive terminal confirmation otherwise. Revoking is friction-free by design; a live broker drops the revoked client and refuses its re-attach.

Once the allowlist exists, anything unmatched fails closed, including an identity that cannot be measured and an unreadable allowlist. Windows has no attestation, so admission is unenforced there (see [SECURITY.md](../SECURITY.md#platform-support)).

## Kill switch (kill / unkill)

`chromium-bridge kill` is the emergency brake: one command that stops every MCP client from driving every connected browser, at once.

- Live browser connections are severed within about a second, and new ones are refused. In-flight tool calls fail fast with `CONNECTION_LOST`.
- Every subsequent tool call, from every attached client, is refused with the stable `BRIDGE_KILLED` error code. Clients stay connected so they can show you the refusal instead of dying silently.
- The state is persisted (in `revocation.json`, next to the lock file) and survives restarts, reconnects, and reboots.
- The extension's options page and the desktop app show the state; engaging the switch works from any surface, but releasing it does not (a web page cannot see or touch any of it).

Nothing releases the switch on its own. Release is an app/CLI act: `chromium-bridge unkill` from a terminal, or the desktop app through the same `core` call ([ADR-0032](./adr/0032-host-owned-policy-settings.md) decision 6 retired the extension's release toggle; a release request from the extension is refused and audited), and releasing demands proof of user presence ([ADR-0031](./adr/0031-touch-id-confirmations-and-presence-grants.md)): on an enrolled Mac this is a Secure Enclave Touch ID tap, and where no Enclave key exists `unkill` asks you to type an explicit confirmation on a real terminal, and refuses outright when its stdin is a pipe, so no script or background program can quietly reopen the bridge through the CLI. Every release attempt is audited with the auth path that decided it (`auth=touch_id`, `auth=cli_confirm`), whether it was granted, refused at the presence gate, or refused by an unwritable record after presence passed.

If either command reports that the revocation record is unreadable, see the recovery section in [operations.md](./operations.md#kill-switch-state-and-recovering-an-unreadable-record); until then, everything keeps failing closed.

`doctor` prints the kill state and exits non-zero while the switch is engaged or its state is unreadable.

## Host-owned policy (policy)

`chromium-bridge policy` is the CLI half of the host-owned policy surface ([ADR-0032](./adr/0032-host-owned-policy-settings.md)); the desktop app is the co-equal other half. For GRANTS the app's policy editor drives this same binary as a subprocess, so the two grant surfaces cannot drift apart; reads and the free restrict lane run in-process over the same core seams. The concepts (the signed baseline, the unsigned restriction overlay, the extension-side ratchet) are in [architecture.md section 11.3](./architecture.md#113-host-owned-policy-and-language-sync-adr-0032); the doctor rows are in [operations.md](./operations.md#host-owned-policy-the-doctor-rows-and-the-pending-import).

```text
chromium-bridge policy show [--json]              # read-only: store state + effective policy
chromium-bridge policy set <field flags> [--json] # GRANT lane: sign a fresh baseline (Touch ID)
chromium-bridge policy restrict <field flags>     # FREE lane: unsigned restriction overlay
chromium-bridge policy history [--json]           # read-only: superseded revisions
chromium-bridge policy pending-import [--json]    # the one-shot legacy import's state
chromium-bridge policy rollback --revision <n> [--json]
```

**Field flags.** `set` and `restrict` share one flag per policy field, spelled as the kebab-case of its camelCase wire name: `--cdp-mode`, `--file-upload`, `--handle-dialog`, `--page-eval`, `--confirm-high-risk-click`, `--confirm-page-eval`, `--touch-id-confirm`, `--confirm-tab-close`, `--warn-precise-snapshot`, `--eval-mask`, `--host-reverify-ms`, `--confirm-grace-ms`, `--click-toast-timeout-ms`, `--eval-toast-timeout-ms`, and `--disabled-tools`. Boolean flags take
`on|off`; the four `*-ms` flags take a non-negative integer;
`--disabled-tools` takes a comma-separated tool list that states the WHOLE disabled set (keep the tools already in it when adding one; empty entries are dropped, so `--disabled-tools ""` is the empty set - a full clear, which on the `set` lane is a relaxation and costs the tap like any other). Because the list travels comma-joined, a tool name containing a comma or surrounding whitespace cannot ride this transport faithfully: every write seam refuses such a name outright rather than signing a silently mangled list. Parsing is strict: an unknown subcommand, a stray argument, a repeated flag, or a malformed value is an error, never a guess, and `set`/`restrict` demand at least one field flag.

**The two lanes are deliberately asymmetric** (ADR-0032 decision 3). `policy set` is the grant lane: it folds the edits over the current baseline (untouched fields carry baseline values, never effective ones), embeds the touched-field set in the document, and signs the exact document bytes with the Secure Enclave enrollment key - the Touch ID tap IS the signature. Where no enrollment key exists (non-macOS, an unenrolled Mac), the CLI refuses UP FRONT, before any prompt could appear: the CLI's grant path exists only as that signature and never constructs an interactive floor, because a floor-gated CLI grant would quietly create a baseline-writing path on every platform the CLI ships to (decision 5; the desktop app's floor for the genuinely unenrolled Mac is the single, deliberate exception). `policy restrict` is the free lane: no prompt, no signature, and the seam's direction check refuses any edit that would relax the effective policy, so a scripted or forged restriction is at worst a denial of service against your own bridge.

**Rollback never replays.** `policy rollback --revision <n>` re-derives that revision's effective policy, diffs it against the current one, and applies the difference as a FRESH write: a rollback that only tightens rides the free restrict lane with no prompt; one that relaxes anything is one fresh Touch ID tap, exactly like any other grant. The old signed artifact is never written back - a lower revision must keep failing the extension's ratchet, which is the anti-replay property, not a limitation.

**`--json` contracts.** `show`, `history`, `pending-import`, `set`, and `rollback` accept `--json`, which swaps the prose for a versioned report on stdout (and, for the write lanes, a versioned error object on refusal) - the desktop app's parse surface. Check the `v` field first and refuse a newer value before reading anything else (fail closed). `pending-import` never records or consumes a live import; the one write it may perform is the idempotent self-heal - finalizing a stranded mid-consume record whose baseline already landed - so the app's probe unsticks a crashed finalize. `--json` is the ONLY mode that prints the recorded bag: the prose rendering deliberately reports state and byte count without bag content, because the bag is reviewed in the app, not dumped on a terminal.

Every policy transition is audited with the surface and, for grants, the presence rung that authorized the signature (`auth=touch_id`; an app-floor grant is recorded as exactly that), so a hardware-signed grant is never conflated with a floor one.

## Logging and audit (BB_LOG / BB_LOG_FORMAT)

Diagnostics in both modes go to **stderr** (stdout carries protocol frames). Two environment variables control the output:

| Variable | Values | Effect |
|------|------|------|
| `BB_LOG` | `error` \| `warn` \| `info` (default) \| `debug` | Log threshold. `info` and above print audit lines; set `warn`/`error` to silence auditing. |
| `BB_LOG_FORMAT` | `text` (default) \| `json` | Format of audit lines. `json` emits one JSON object per line, convenient for machine collection. |

**Audit events (stderr)**: every security decision emits one audit line: tool calls (with `req`, `tool`, `outcome`, and on error the stable `code` from [`ERROR_SPECS`](../src/packages/core/src/error.rs), plus `dur_ms`), harness admissions and refusals, client pairing and revocation, host-key revocations, kill-switch transitions, and the extension's confirmation and enrollment decisions (forwarded over the port). The same events are appended as strict JSON records to a durable, size-capped `audit.log` (0600, in the runtime directory next to the lock file), which survives the short-lived processes that write it.

```text
# BB_LOG_FORMAT default (text)
[AUDIT] ts=1721000000000 kind=tool_call req=7 tool=page_click outcome=ok dur_ms=12
# BB_LOG_FORMAT=json
{"kind":"audit","ts":1721000000000,"kind":"tool_call","req":"7","tool":"page_eval","outcome":"error","code":"EXECUTION_FAILED","dur_ms":"8"}
```

Read the durable trail with the read-only subcommand:

```text
$ chromium-bridge audit --limit 20
2026-07-17 19:04:11.201Z  kill_engage     surface=cli outcome=ok
2026-07-17 19:04:12.480Z  tool_call       tool=tab_list outcome=error code=BRIDGE_KILLED dur_ms=0
2026-07-17 19:05:02.913Z  kill_release    surface=cli outcome=ok
```

A record the reader cannot parse is shown as `UNRECOGNIZED RECORD` and counted, never guessed at; a `dropped=n` field marks records lost to a failed write (a full disk, for example). Recording never blocks or fails an operation: the trail observes decisions, it does not gate them ([ADR-0030](./adr/0030-global-kill-switch-and-audit.md)).

Error codes and the error taxonomy are in [architecture.md section 11.1](./architecture.md#111-error-taxonomy-error_specs).

## Related

- Install and first use: [quickstart.md](./quickstart.md).
- The desktop app as the other management surface: [desktop-app.md](./desktop-app.md).
- Connection lifecycle and disconnect/reconnect semantics: [architecture.md section 5.2](./architecture.md#52-native-host-reconnect).
- Error taxonomy (`NOT_CONNECTED` / disconnect class): [architecture.md section 11.1](./architecture.md#111-error-taxonomy-error_specs).
