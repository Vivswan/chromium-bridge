# CLI and troubleshooting: chromium-bridge

> This doc is the reference for the `chromium-bridge` binary's subcommands and the common troubleshooting paths. The CLI is the management surface over the core. Components and process boundaries are in [architecture.md](./architecture.md); on-disk paths are in [architecture.md section 4.3](./architecture.md#43-on-disk-artifacts).

## Subcommand overview

`chromium-bridge` is a single binary with subcommand dispatch:

| Invocation | Mode | Description |
|------|------|------|
| `chromium-bridge` (no arguments) | MCP server | Default mode, spawned by the MCP client. The first instance becomes the broker; later instances attach to it. |
| `chromium-bridge --native-host [--label <browser>]` | native host | Thin bridge, spawned by the browser via the host manifest. Never invoked by hand. |
| `chromium-bridge doctor [--json]` (alias `status`) | read-only diagnostics | Environment and connectivity self-check; changes nothing. `--json` prints the report as one versioned object. |
| `chromium-bridge doctor --list` | read-only diagnostics | One line per known browser: detection and registration state. |
| `chromium-bridge doctor --paths` | read-only diagnostics | Prints the runtime dir and lock path this environment resolves to, creating neither. |
| `chromium-bridge doctor --fix` | repair / install | Registers (or re-registers) this binary as the native-messaging host. The only mutating form of doctor. |
| `chromium-bridge uninstall` | removal | Removes exactly the registrations this project wrote, nothing else. |
| `chromium-bridge pair [--reset] [--file-store]` | enrollment | Mints the host key the extension pins, behind a confirmation typed on the terminal; the key lives in the OS credential store, or in a 0600 file with `--file-store`. |
| `chromium-bridge revoke` | enrollment | Deletes the host key; a pinning extension then fails closed. |
| `chromium-bridge enclave-status [--json]` | read-only | Prints the host key state, where it lives, and its fingerprint. |
| `chromium-bridge pair-client --name <label> (--this-parent \| --hash <hex> \| --signer <id>)` | trusted clients | Adds an MCP-client harness to the trusted-client allowlist; presence-gated. |
| `chromium-bridge revoke-client --name <label>` | trusted clients | Removes a client; a live broker drops it immediately. |
| `chromium-bridge list-clients` | read-only | Prints the trusted-client allowlist. |
| `chromium-bridge kill` | kill switch | Engages the global kill switch: halts ALL bridge activity until an explicit release. |
| `chromium-bridge unkill` | kill switch | Releases the kill switch, after proof of user presence: a confirmation typed on an interactive terminal (a piped stdin is refused). |
| `chromium-bridge policy show [--json]` | read-only | Prints the host-owned policy state and the effective policy. |
| `chromium-bridge policy set <field flags> [--json]` | policy (grant lane) | Mints a fresh SIGNED policy baseline behind the typed terminal confirmation. Signature-only; refuses up front where no host key exists. |
| `chromium-bridge policy restrict <field flags>` | policy (free lane) | Applies an unsigned restriction overlay; no prompt, because it can only remove capability. |
| `chromium-bridge policy history [--json]` | read-only | Prints the superseded-revision ring. |
| `chromium-bridge policy rollback --revision <n> [--json]` | policy | Re-derives a past revision's effective policy as a FRESH write, never a replay. |
| `chromium-bridge audit [--limit <n>]` | read-only audit | Prints the on-disk audit trail, oldest first (default: the last 200 records). |
| `chromium-bridge --help` | help | Usage information. |

## doctor / status (read-only self-check)

`doctor` (with `status` as an equivalent alias) is a read-only subcommand: it does not bind the socket, does not write the lock file, and does not spawn any child process. It only probes the current environment and prints its conclusions, to answer the question "why can't I connect".

It reports:

- **Version / platform**: the binary version (Cargo is the source) and the running platform.
- **Lock file**: whether the bridge lock file exists in the runtime directory, and the endpoint and pid recorded in it.
- **Server reachability**: a passive connect-and-drop probe against our own bridge socket (no bytes sent), reporting `reachable` / `not reachable`.
- **Kill switch**: engaged, clear, or unreadable. `doctor` exits non-zero while the switch is engaged or its state cannot be read.
- **Native-host registrations**: for each known browser (chrome, chromium, brave, edge, vivaldi, opera), whether it looks present for this user and the state of its registration for `com.vivswan.chromium_bridge.host`: `ok`, `missing`, `stale` (ours, but its launch path dangles), or not ours. The diagnosis comes from the same resolver `--fix` repairs with, so what doctor reports is exactly what `--fix` produces.

`doctor --json` prints the same report as one JSON object on stdout, with the same exit code. Check its `v` field first and refuse a newer value before reading anything else (fail closed), as with every `--json` report of this binary.

### How to interpret "server not reachable"

"Server not reachable" means `doctor` read the endpoint from the lock file, but the probe failed. Common causes:

1. **No MCP server is running.** The server is spawned by the MCP client (such as Claude Code) inside its session, so with no client session up nothing is listening and "not reachable" is the expected state. Confirm the client has the chromium-bridge server configured and a session open.
2. **Stale lock file.** A previous broker exited abnormally and left the lock file behind. The next server instance detects and replaces a stale lock at startup; just start a new client session.

> `doctor` only probes; it does not repair. It will not kill processes, delete the lock file, or restart the server. When you see "not reachable", re-establish the session from the MCP client side rather than intervening in processes by hand.

If a registration is missing or stale for a browser you use, that browser cannot spawn the native host. Run `chromium-bridge doctor --fix`, then restart the browser.

## doctor --fix / uninstall (native-messaging registration)

The CLI below registers the native-messaging host from a terminal through one engine (`registration.rs`). It needs nothing but the host binary itself, on desktops, headless machines, and CI alike.

`chromium-bridge doctor --fix` (re-)registers the binary you invoke it from as the native-messaging host: for each targeted browser it writes the `com.vivswan.chromium_bridge.host.json` manifest where that browser looks for it, and beside it the extension pointer (below).

- **Idempotent re-registration:** on a fresh machine `--fix` is also the first registration, and after moving the binary it refreshes a stale one.
- **Nothing built, downloaded, or copied:** the manifest points at this binary's own resolved path, through a small per-browser wrapper script on macOS/Linux.
- **That wrapper** bakes in `--native-host --label <browser>`, because Chrome's manifest format has no `args` field.
- **Refuses to overwrite** a manifest or pointer it cannot verify this project wrote.

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

Known browser keys: `chrome`, `chromium`, `brave`, `edge`, `vivaldi`, `opera`. "Detected" means the browser is actually installed, as far as a cheap local check can tell:

| Platform | The detection check | What it means |
| --- | --- | --- |
| macOS | the application bundle under `/Applications` or `~/Applications` | a leftover per-user config directory alone does not count (uninstalled browsers keep those forever, and some dev tools create them); a freshly installed browser counts before its first run |
| Linux, Windows | the per-user config (profile) directory | the best cheap signal there |

- **A non-standard install on macOS** reads as "not detected"; it can still be registered explicitly with `--browser <key>` or `--manifest-dir`.
- **Plain `doctor` counts only detected browsers,** so a healthy explicit registration for a non-standard install keeps the summary below "OK" even though the bridge works - the per-browser lines tell the real story.
- **Nothing detected:** `--fix` refuses and asks for an explicit selection instead of guessing.

`chromium-bridge uninstall` reverses exactly what this project registers (via `--fix`): the per-browser manifests, the extension pointers, and the wrapper scripts. Re-pass any `--manifest-dir` you registered.

Before deleting a manifest or pointer it verifies the content is ours (our host id and description marker; the Web Store update url alone). Anything else, or anything it cannot read, is reported and left in place; the other artifacts of ours beside it still go.

It never touches this binary or your browsers. A browser drops the extension it installed from the pointer on its next start; an unpacked extension is yours to remove.

The extension pointer, beside each manifest:

| OS | Where `--fix` writes it | What the browser does with it |
| --- | --- | --- |
| macOS | `<user data dir>/External Extensions/<extension id>.json`, naming the Web Store | asks "Enable Chromium Bridge?" on its next start |
| Windows | `HKCU\<vendor>\Extensions\<extension id>`, value `update_url` | the same prompt |
| Linux | nothing; `doctor` prints `pointer n/a` | it would install from a pointer silently, which the threat model refuses: add the extension from the Web Store yourself |

Chrome's own locations come from its documentation. The other vendors are derived from the same user-data root and registry root they keep their manifests under, and Edge is pointed at the Chrome Web Store too (a residual: unverified on those browsers).

The pointer informs `doctor` and never decides its verdict: the bridge works with an unpacked extension and no pointer. It is written for the browsers `--fix` names or detects; a `--manifest-dir` registration gets none, since its browser cannot be named.

Whether the listing exists yet, and what to load until it does, is [quickstart.md](./quickstart.md#the-cli-macos-linux-windows) step 4's.

Platform notes:

- **Linux AppImage / temp paths**: a registration pointing into an AppImage's FUSE mount (or any temp dir) breaks when that path disappears. `--fix` warns when it detects this. Copy the binary to a stable location first, for example `~/.local/lib/chromium-bridge/chromium-bridge`, and run `doctor --fix` from there.
- **Windows**: registration is an `HKCU` registry key per browser plus a manifest file under `%LOCALAPPDATA%\chromium-bridge`. The code path compiles and mirrors what the retired `install.ps1` script did, but it has not yet been verified on a real Windows machine; treat Windows registration as best-effort until then. Browser detection on Windows (per-user profile directories; Opera under the roaming profile) carries the same caveat.

## Enrollment: pair / revoke / enclave-status

The host-key ceremony gives the extension one host identity to pin:

- `chromium-bridge pair` asks for a confirmation typed on the terminal (a piped stdin is refused before any prompt), mints a P-256 host key, keeps it in the OS credential store (the Keychain, the Credential Manager, or the Secret Service), and prints the key's SHA-256 fingerprint. Compare that fingerprint with the one the extension shows on its enrollment screen; a mismatch means something sits between them.
- `chromium-bridge pair --file-store` keeps the key in a 0600 file in the runtime directory instead, for a machine with no usable credential store. The choice is explicit: a store failure is reported, never silently redirected to the file.
- `chromium-bridge pair --reset` asks for the confirmation first, then removes the previous key (from whichever store holds it) and mints a fresh one; the extension must re-pin. When the credential store does not answer, a `--file-store` reset proceeds with a warning that an entry the store may hold stays behind; run `revoke` again once the store answers.
- `chromium-bridge revoke` deletes the key and confirms it is gone. The host pushes a revocation to the extension, which fails closed.
- `chromium-bridge enclave-status [--json]` reports the current state read-only: whether a key is present, which store holds it, and its fingerprint.

User presence for the browser's own acts (releasing the kill switch, enrolling a second browser) is a WebAuthn tap on the browser's authenticator, verified by the host. The options page does not offer the panel that enrolls and answers yet (the exchange is reachable from the background handlers and the browser suite). The CLI never raises that prompt: its own grants (`pair`, `pair-client`, `unkill`, `policy set`) are confirmed by the typed phrase on a real terminal.

## Trusted clients: pair-client / revoke-client / list-clients

By default (unenrolled), any process that spawns the server is served, and every start logs that open posture at ERROR level. Creating the trusted-client allowlist closes it:

```text
chromium-bridge pair-client --name claude-code --this-parent
chromium-bridge pair-client --name codex --hash <sha256-hex>
chromium-bridge pair-client --name claude-desktop --signer <signer-id>
chromium-bridge list-clients
chromium-bridge revoke-client --name codex
```

- `--this-parent` measures the process that spawned this CLI invocation (run it from inside the client you want to trust). Unix only: on Windows the server keys a harness on the creator of its stdin pipe, which a console command has none of, so pair with `--hash` or `--signer` using the values the server logs at startup while unenrolled.
- Authorization keys on the attested anchor, never the `--name` label, which labels logs and revocation. What each platform measures is on the [trust boundaries page](security/trust-boundaries.md#boundary-1-mcp-client---rust-mcp-server--stdio-json-rpc-20).
- Hash anchors change when the client updates; re-run `pair-client` with the same name to replace the entry (the re-pair path).
- Adding a client is a capability grant, so it is presence-gated: a confirmation typed on an interactive terminal, with a piped stdin refused. Revoking is friction-free by design; a live broker drops the revoked client and refuses its re-attach.

Once the allowlist exists, anything unmatched fails closed, including an identity that cannot be measured and an unreadable allowlist. The Windows measurement is in [SECURITY.md](../.github/SECURITY.md#platform-support).

## Kill switch (kill / unkill)

`chromium-bridge kill` is the emergency brake: one command that stops every MCP client from driving every connected browser, at once.

- Live browser connections are severed within about a second, and new ones are refused. In-flight tool calls fail fast with `CONNECTION_LOST`.
- Every subsequent tool call, from every attached client, is refused with the stable `BRIDGE_KILLED` error code. Clients stay connected so they can show you the refusal instead of dying silently.
- The state is persisted (in `trust.json`, next to the lock file) and survives restarts, reconnects, and reboots.
- The extension's options page shows the state; engaging the switch works from any surface. Releasing it from the extension is answered by the host with a presence request (the WebAuthn tap, or the window on a browser with no enrolled credential); the options page does not offer that control yet, so today release is the CLI's (a web page cannot see or touch any of it).

Nothing releases the switch on its own. Release demands proof of user presence on either surface:

| Surface | The proof a release demands |
| --- | --- |
| `chromium-bridge unkill` on the CLI | an explicit confirmation typed on a real terminal; a piped stdin is refused outright, so no script or background program can quietly reopen the bridge through the CLI |
| the extension's options page | a WebAuthn assertion from a credential enrolled under that browser; the browser's confirmation window only when the browser has no enrolled credential |

Every release attempt is audited: a granted release with the auth path that decided it (`auth=tty`, `auth=webauthn:<fingerprint>`, `auth=confirm_window`), a refusal at the presence gate with the presence error, and a refusal by an unwritable record after presence passed with both.

If either command reports that the trust record is unreadable, see [the recovery steps](./troubleshooting.md#doctor-says-the-kill-state-or-the-trust-record-is-unreadable); until then, everything keeps failing closed.

`doctor` prints the kill state and exits non-zero while the switch is engaged or its state is unreadable.

## Host-owned policy (policy)

`chromium-bridge policy` is the host-owned policy surface. The concepts (the signed baseline, the unsigned restriction overlay, the extension-side ratchet) are in [architecture.md section 11.3](./architecture.md#113-host-owned-policy-and-language-sync); the `policy baseline:` doctor row is read on the [troubleshooting page](./troubleshooting.md#doctor-reports-policy-baseline-none-yet).

```text
chromium-bridge policy show [--json]              # read-only: store state + effective policy
chromium-bridge policy set <field flags> [--json] # GRANT lane: sign a fresh baseline (terminal confirmation)
chromium-bridge policy restrict <field flags>     # FREE lane: unsigned restriction overlay
chromium-bridge policy history [--json]           # read-only: superseded revisions
chromium-bridge policy rollback --revision <n> [--json]
```

**Field flags.** `set` and `restrict` share one flag per policy field, spelled as the kebab-case of its camelCase wire name: `--cdp-mode`, `--file-upload`, `--handle-dialog`, `--page-eval`, `--confirm-high-risk-click`, `--confirm-page-eval`, `--touch-id-confirm`, `--confirm-tab-close`, `--warn-precise-snapshot`, `--eval-mask`, `--host-reverify-ms`, `--confirm-grace-ms`, `--click-toast-timeout-ms`, `--eval-toast-timeout-ms`, and `--disabled-tools`.

| Flag kind | Value |
| --- | --- |
| boolean flags | `on` or `off` |
| the four `*-ms` flags | a non-negative integer |
| `--disabled-tools` | a comma-separated tool list that states the WHOLE disabled set (keep the tools already in it when adding one) |

- **`--disabled-tools ""` is the empty set:** empty entries are dropped, so this is a full clear, which on the `set` lane is a relaxation and costs the tap like any other.
- **A tool name containing a comma or surrounding whitespace** cannot ride the comma-joined transport faithfully: every write seam refuses such a name outright rather than signing a silently mangled list.
- **Parsing is strict:** an unknown subcommand, a stray argument, a repeated flag, or a malformed value is an error, never a guess, and `set`/`restrict` demand at least one field flag.

**The two lanes are deliberately asymmetric.**

- **`policy set` is the grant lane:** it folds the edits over the current baseline (untouched fields carry baseline values, never effective ones), embeds the touched-field set in the document, and signs the exact document bytes with the host key once the typed terminal confirmation passes.
- **No host key, no grant:** on a machine that has not run `pair` the CLI refuses UP FRONT, before any prompt could appear, so no baseline can exist that the extension's pin could not verify.
- **`policy restrict` is the free lane:** no prompt, no signature, and the seam's direction check refuses any edit that would relax the effective policy, so a scripted or forged restriction is at worst a denial of service against your own bridge.

**Rollback never replays.** `policy rollback --revision <n>` re-derives that revision's effective policy, diffs it against the current one, and applies the difference as a FRESH write.

- **A rollback that only tightens** rides the free restrict lane with no prompt.
- **One that relaxes anything** is one fresh terminal confirmation and signature, exactly like any other grant.
- **The old signed artifact is never written back:** a lower revision must keep failing the extension's ratchet, which is the anti-replay property, not a limitation.

**`--json` contracts.** `show`, `history`, `set`, and `rollback` accept `--json`, which swaps the prose for a versioned report on stdout (and, for the write lanes, a versioned error object on refusal). Check the `v` field first and refuse a newer value before reading anything else (fail closed).

Every policy transition is audited with the surface and, for grants, the presence path that authorized the signature (`auth=tty`).

## Logging and audit (BB_LOG / BB_LOG_FORMAT)

Diagnostics in both modes go to **stderr** (stdout carries protocol frames). Two environment variables control the output:

| Variable | Values | Effect |
|------|------|------|
| `BB_LOG` | `error` \| `warn` \| `info` (default) \| `debug` | Log threshold. `info` and above print audit lines; set `warn`/`error` to silence auditing. |
| `BB_LOG_FORMAT` | `text` (default) \| `json` | Format of audit lines. `json` emits one JSON object per line, convenient for machine collection. |

**Audit events (stderr)**: every security decision emits one audit line: tool calls (with `req`, `tool`, `outcome`, and on error the stable `code` from [`ERROR_SPECS`](../src/packages/core/src/error.rs), plus `dur_ms`), harness admissions and refusals, client pairing and revocation, host-key revocations, kill-switch transitions, WebAuthn enrollments and presence verdicts, policy writes, and the extension's confirmation and enrollment decisions (forwarded over the port).

The same events are appended as strict JSON records to a durable, size-capped `audit.log` (0600, in the runtime directory next to the lock file), which survives the short-lived processes that write it. Each record names its event in `event_kind`; the JSON stderr form wraps the record in a `"kind":"audit"` envelope, so a collector keys on `kind` and reads the event from `event_kind`.

- **No sensitive content is recorded:** no page text, cookie or storage values, eval return values, or form fill values; masking happens on the extension side ([threat model](./security/threat-model.md)).
- **Correlation:** a tool-call line carries its request id (`req`) and the generation of the browser connection the call was routed to (`conn`); the generation increments on every re-attach, so a reconnect starts a new `conn`.
- **Two extension-local kinds never reach `audit.log`:** `policy_refused` and `policy_compromised` stay in the extension's own audit ring by design, outside the forwarding whitelist; the host records every policy transition as `policy_write`.

```text
# BB_LOG_FORMAT default (text)
[AUDIT] 2026-10-03 23:12:44.302Z  kill_engage     surface=cli outcome=ok
# BB_LOG_FORMAT=json
{"kind":"audit","v":1,"ts_ms":1791069164310,"event_kind":"kill_engage","surface":"cli","outcome":"ok"}
```

Read the durable trail with the read-only subcommand:

```text
$ chromium-bridge audit --limit 20
2026-07-17 19:04:11.201Z  kill_engage     surface=cli outcome=ok
2026-07-17 19:04:12.480Z  tool_call       tool=tab_list outcome=error code=BRIDGE_KILLED dur_ms=0
2026-07-17 19:05:02.913Z  kill_release    surface=cli outcome=ok
```

A record the reader cannot parse is shown as `UNRECOGNIZED RECORD` and counted, never guessed at; a `dropped=n` field marks records lost to a failed write (a full disk, for example). Recording never blocks or fails an operation: the trail observes decisions, it does not gate them.

Error codes and the error taxonomy are in [architecture.md section 11.1](./architecture.md#111-error-taxonomy-error_specs).

## Related

- Install and first use: [quickstart.md](./quickstart.md).
- Connection lifecycle and disconnect/reconnect semantics: [architecture.md section 5.2](./architecture.md#52-native-host-reconnect).
- Error taxonomy (`NOT_CONNECTED` / disconnect class): [architecture.md section 11.1](./architecture.md#111-error-taxonomy-error_specs).
