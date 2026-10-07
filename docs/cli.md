# CLI and troubleshooting: chromium-bridge

> This doc is the reference for the `chromium-bridge` binary's subcommands and the common troubleshooting paths. The CLI is the management surface over the core. Components and process boundaries are in [architecture.md](./architecture.md); on-disk paths are in [architecture.md section 4.3](./architecture.md#43-on-disk-artifacts).

## Subcommand overview

`chromium-bridge` is a single binary with subcommand dispatch:

| Invocation | Mode | Description |
|------|------|------|
| `chromium-bridge` (no arguments) | MCP server | Default mode, spawned by the MCP client. The first instance becomes the broker; later instances attach to it. |
| `chromium-bridge --native-host [--label <browser>]` | native host | Thin bridge, spawned by the browser via the host manifest. Never invoked by hand. |
| `chromium-bridge doctor [--json]` (alias `status`) | read-only diagnostics | Environment and connectivity self-check; changes nothing. `--json` prints the report as one versioned object. |
| `chromium-bridge doctor --list` | read-only diagnostics | One line per known browser and scope: detection and registration state. |
| `chromium-bridge doctor --paths` | read-only diagnostics | Prints the runtime dir and lock path this environment resolves to, creating neither. |
| `chromium-bridge doctor --fix` | repair / install | Registers (or re-registers) this binary as the native-messaging host for your account. The only mutating form of doctor. |
| `chromium-bridge doctor --fix --system` | repair / install (root) | The same, machine-wide: into the root-owned directories every account's browser reads. What the `.deb` runs after install. |
| `chromium-bridge uninstall [--system]` | removal | Removes exactly the registrations this project wrote in that scope, nothing else. |
| `chromium-bridge pair [--reset] [--file-store]` | enrollment | Mints the host key the extension pins, behind a confirmation typed on the terminal; the key lives in the OS credential store, or in a 0600 file with `--file-store`. |
| `chromium-bridge revoke <browser>` | enrollment | Forgets that browser's enrolled authenticators; no proof needed, the browser enrolls again from its options page. |
| `chromium-bridge revoke --all` | enrollment | Starts over: deletes the host key and the signed policy baseline, forgets every browser and every trusted client. A bare `revoke` is refused with the usage. |
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
| `chromium-bridge policy rollback --revision <n> [--entry <id>] [--json]` | policy | Re-derives a past revision's effective policy as a FRESH write, never a replay; `--entry` names one record where the revision appears more than once. |
| `chromium-bridge audit [--limit <n>]` | read-only audit | Prints the on-disk audit trail, oldest first (default: the last 200 records). |
| `chromium-bridge lang [show \| set <value>]` | display language | Reads or sets the display language the options page shows; `lang` alone is `show`. |
| `chromium-bridge --help` | help | Usage information. |

The options page offers the same actions. Terminal-only by design: `uninstall` (below), and the `--system` and `--manifest-dir` repair forms. The page's audit view is the default page alone; a longer trail is `audit --limit <n>`. The site allowlist, allow-all, and tab grouping stay on the page. They are browser-local extension storage (see the [privacy policy](./privacy-policy.md)), which no subcommand reads or writes.

## doctor / status (read-only self-check)

`doctor` (with `status` as an equivalent alias) is a read-only subcommand: it does not bind the socket, does not write the lock file, and does not spawn any child process. It only probes the current environment and prints its conclusions, to answer the question "why can't I connect".

It reports:

- **Version / platform**: the binary version (Cargo is the source) and the running platform.
- **Lock file**: whether the bridge lock file exists in the runtime directory, and the endpoint and pid recorded in it.
- **Server reachability**: a passive connect-and-drop probe against our own bridge socket (no bytes sent), reporting `reachable` / `not reachable`.
- **Kill switch**: engaged, clear, or unreadable. `doctor` exits non-zero while the switch is engaged or its state cannot be read.
- **Native-host registrations**: for each known browser (chrome, chromium, brave, edge, vivaldi, opera), whether it looks present on this machine and the state of its registration for `com.vivswan.chromium_bridge.host` in each scope, `user` and `system`: `ok`, `missing`, `stale` (ours, but its launch path dangles), or not ours.
- **The verdict follows the browser's lookup order**: the per-user entry when one exists, the system one only in its absence. The diagnosis comes from the same resolver `--fix` repairs with, so what doctor reports is exactly what `--fix` produces.

The options page's Host registration section shows the same rows (lock file, server, kill switch, policy baseline, the verdict), worded by the host, and its identity section shows where the host key lives, as `enclave-status` prints it.

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
- **That wrapper** bakes in `--native-host`, because Chrome's manifest format has no `args` field, plus `--label <browser>` when one browser alone launches the manifest (`run-host-<browser>.sh`); a manifest several browsers read gets the unlabeled `run-host.sh` (the rule is `Target`'s in `registration.rs`).
- **Overwrites a manifest another tool wrote at our host id** (the report names what it launched), refuses one it cannot read, and refuses a foreign pointer; `uninstall` leaves a foreign manifest.

Selecting browsers:

```text
chromium-bridge doctor --fix                      # every browser detected for this user
chromium-bridge doctor --fix --browser chrome,brave
chromium-bridge doctor --fix --all                # every known browser, detected or not
chromium-bridge doctor --fix --manifest-dir DIR   # exact NativeMessagingHosts dir
                                                  # (absolute; repeatable), for a Chromium
                                                  # variant we do not know by name
sudo chromium-bridge doctor --fix --system        # machine-wide, for every account (root only)
chromium-bridge doctor --list                     # read-only: detection + registration state
```

The scope is the command's: `--system` writes the directories every account's browser reads (`/etc/opt/chrome/native-messaging-hosts`, `/Library/Google/Chrome/NativeMessagingHosts`, `HKLM`) and needs root, while without it a root shell is refused, since root has no browser of its own.

Opera, and Brave on macOS and Linux, read Chrome's system directory rather than one of their own, and Brave on macOS reads Chrome's per-user directory as well. For them `doctor --fix` registers Chrome's manifest in that scope and `doctor` reports it on their rows as Chrome's.

- **No label on the shared manifest:** either browser may launch it, so its connections take the broker's default slot, as a `--manifest-dir` registration's do.
- **Own pointer per browser, per user on macOS:** Chrome and Brave each keep their own extension pointer there, so both prompt to enable the extension (machine-wide, macOS has one pointer directory for every browser).

Known browser keys: `chrome`, `chromium`, `brave`, `edge`, `vivaldi`, `opera`. "Detected" means the browser is actually installed, as far as a cheap local check can tell:

| Platform | The detection check | What it means |
| --- | --- | --- |
| macOS | the application bundle under `/Applications` or `~/Applications` | a leftover per-user config directory alone does not count (uninstalled browsers keep those forever, and some dev tools create them); a freshly installed browser counts before its first run |
| Linux | the per-user config directory; with `--system`, the vendor package's install directory (`/opt/google/chrome`, `/usr/lib/chromium`, and the like) | a per-user repair registers the browsers this account has run; the `.deb`'s post-install, from root, registers the ones installed for every account |
| Windows | the per-user profile directory | the best cheap signal there |

- **A non-standard install on macOS** reads as "not detected"; it can still be registered explicitly with `--browser <key>` or `--manifest-dir`.
- **Plain `doctor` counts only detected browsers,** so a healthy explicit registration for a non-standard install keeps the summary below "OK" even though the bridge works - the per-browser lines tell the real story.
- **Nothing detected:** `--fix` refuses and asks for an explicit selection instead of guessing, exiting 3 rather than 1 so an installer can tell "no browser yet" from a failure.
- **The options page's Host registration section** repairs the same two ways, for this account: every detected browser, or one named browser from its row. `--manifest-dir` and `--system` stay in the terminal: a directory is typed, and root is held, where the page has neither.

`chromium-bridge uninstall` reverses exactly what this project registers (via `--fix`) in one scope: the per-browser manifests, the extension pointers, and the wrapper scripts. Re-pass any `--manifest-dir` you registered, and `--system` (as root) for a machine-wide registration.

Before deleting a manifest or pointer it verifies the content is ours (our host id and description marker; the Web Store update url alone). Anything else, or anything it cannot read, is reported and left in place as a warning, never a failure, so a package removal completes; the other artifacts of ours beside it still go, and only one of ours that cannot be removed fails the command.

It never touches this binary or your browsers. A browser drops the extension it installed from the pointer on its next start; an unpacked extension is yours to remove.

`uninstall` has no options-page twin by design. The frame asking for it would delete the manifest that launched the very host answering it.

The extension pointer, beside each manifest:

| OS | Where `--fix` writes it | What the browser does with it |
| --- | --- | --- |
| macOS | `<user data dir>/External Extensions/<extension id>.json`, naming the Web Store; with `--system`, `/Library/Application Support/Google/Chrome/External Extensions/` for every browser (Chromium's one machine-wide directory) | asks "Enable Chromium Bridge?" on its next start |
| Windows | `HKCU\<vendor>\Extensions\<extension id>`, value `update_url`; `HKLM` with `--system` | the same prompt |
| Linux | nothing; `doctor` prints `pointer n/a` | it would install from a pointer silently, which the threat model refuses: add the extension from the Web Store yourself |

Chrome's own locations come from its documentation. The other vendors are derived from the same user-data root and registry root they keep their manifests under, and Edge is pointed at the Chrome Web Store too (a residual: unverified on those browsers).

The pointer informs `doctor` and never decides its verdict: the bridge works with an unpacked extension and no pointer. It is written for the browsers `--fix` names or detects; a `--manifest-dir` registration gets none, since its browser cannot be named.

Whether the listing exists yet, and what to load until it does, is [quickstart.md](./quickstart.md#the-cli-macos-linux-windows) step 4's.

Platform notes:

- **Linux AppImage / temp paths**: a registration pointing into an AppImage's FUSE mount (or any temp dir) breaks when that path disappears. `--fix` warns when it detects this. Copy the binary to a stable location first, for example `~/.local/lib/chromium-bridge/chromium-bridge`, and run `doctor --fix` from there.
- **Windows**: registration is an `HKCU` registry key per browser plus a manifest file under `%LOCALAPPDATA%\chromium-bridge` (with `--system`, `HKLM` and `%ProgramFiles%\chromium-bridge`). The code path compiles and mirrors what the retired `install.ps1` script did, but it has not yet been verified on a real Windows machine; treat Windows registration as best-effort until then. Browser detection on Windows (per-user profile directories; Opera under the roaming profile) carries the same caveat.

## Enrollment: pair / revoke / enclave-status

The host-key ceremony gives the extension one host identity to pin:

- `chromium-bridge pair` asks for a confirmation typed on the terminal (a piped stdin is refused before any prompt), mints a P-256 host key, keeps it in the OS credential store (the Keychain, the Credential Manager, or the Secret Service), and prints the key's SHA-256 fingerprint. Compare that fingerprint with the one the extension shows on its enrollment screen; a mismatch means something sits between them.
- `chromium-bridge pair --file-store` keeps the key in a 0600 file in the runtime directory instead, for a machine with no usable credential store. The choice is explicit: a store failure is reported, never silently redirected to the file.
- `chromium-bridge pair --reset` asks for the confirmation first, then removes the previous key (from whichever store holds it) and mints a fresh one; the extension must re-pin. Browser enrollments and client pairings stay.
- When the credential store does not answer, a `--file-store` reset proceeds with a warning that an entry the store may hold stays behind. Run `pair --reset` again once the store answers; `revoke --all` would also forget every browser and client.
- `chromium-bridge enclave-status [--json]` reports the current state read-only: whether a key is present, which store holds it, and its fingerprint.

User presence for the browser's own acts (releasing the kill switch, enrolling a second browser) is a WebAuthn tap on the browser's authenticator, verified by the host. The options page's identity section enrolls the authenticator; its kill panel, its policy editor, and its trusted-clients form each answer the host's presence request with the proof the kill-switch table below describes.

Forgetting is friction-free, because it only removes capability:

- `chromium-bridge revoke <browser>` forgets every authenticator enrolled under that label. The browser's acts fall back to the confirmation window until it enrolls again from its options page; when it was the last enrolled browser, the next enrollment is first-time again.
- The label is the browser's host manifest `--label` (`brave`, `chrome`), or `default` for every browser on a shared unlabelled manifest (Windows, the shared Chrome manifest), so `revoke default` forgets all of them. An unknown label is refused with the labels the record holds.
- The options page offers the same for its own browser: Forget this browser, in the identity section's authenticator block. It acts on that host's label, so browsers sharing a manifest are forgotten together.
- `chromium-bridge revoke --all` starts over in one step: the host key is deleted, the policy record goes (the signed baseline and any restriction overlay), every browser is forgotten, and every trusted client is revoked, so a paired machine admits no client until `pair-client` trusts one again. The kill switch is not touched; release it with `unkill`.
- After `revoke --all` a connected extension fails closed either way: by the revocation push when the credential store confirmed the key gone and the record write landed, otherwise at its next key verification. `revoke <browser>` leaves the host key and the pin alone.
- A bare `chromium-bridge revoke` names neither and is refused with the usage.

The CLI never raises that prompt: its own grants (`pair`, `pair-client`, `unkill`, `policy set`) are confirmed by the typed phrase on a real terminal.

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
- The options page's Trusted MCP clients section pairs a client the same way (a name plus a hash or signer anchor) behind this browser's presence proof; `--this-parent` exists only on the CLI, because a page has no parent process to measure.

Once the allowlist exists, anything unmatched fails closed, including an identity that cannot be measured and an unreadable allowlist. The Windows measurement is in [SECURITY.md](../.github/SECURITY.md#platform-support).

## Kill switch (kill / unkill)

`chromium-bridge kill` is the emergency brake: one command that stops every MCP client from driving every connected browser, at once.

- Live browser connections are severed within about a second, and new ones are refused. In-flight tool calls fail fast with `CONNECTION_LOST`.
- Every subsequent tool call, from every attached client, is refused with the stable `BRIDGE_KILLED` error code. Clients stay connected so they can show you the refusal instead of dying silently.
- The state is persisted (in `trust.json`, next to the lock file) and survives restarts, reconnects, and reboots.
- The extension's options page shows the state; engaging the switch works from any surface. Releasing it from the options page is answered by the host with a presence request, which the page settles with the WebAuthn tap (or the software confirmation it offers only on a browser with no enrolled credential); a web page cannot see or touch any of it.

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
chromium-bridge policy rollback --revision <n> [--entry <id>] [--json]
```

**Field flags.** `set` and `restrict` share one flag per policy field, spelled as the kebab-case of its camelCase wire name: `--cdp-mode`, `--file-upload`, `--handle-dialog`, `--page-eval`, `--confirm-high-risk-click`, `--confirm-page-eval`, `--presence-confirm`, `--confirm-tab-close`, `--warn-precise-snapshot`, `--eval-mask`, `--host-reverify-ms`, `--confirm-grace-ms`, `--click-toast-timeout-ms`, `--eval-toast-timeout-ms`, and `--disabled-tools`.

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
- **The options page's Security policy section runs the same two lanes:** a tightening applies at once, a loosening signs a fresh baseline behind this browser's presence proof, and a keyless host refuses it up front with the same words. Before any baseline exists every edit there is a grant, since there is nothing to restrict yet.

**Rollback never replays.** `policy rollback --revision <n>` re-derives that revision's effective policy, diffs it against the current one, and applies the difference as a FRESH write.

- **A rollback that only tightens** rides the free restrict lane with no prompt.
- **One that relaxes anything** is one fresh terminal confirmation and signature, exactly like any other grant.
- **The old signed artifact is never written back:** a lower revision must keep failing the extension's ratchet, which is the anti-replay property, not a limitation.
- **One revision, several records:** every restriction made while a revision was current pushed a record at that revision, so `policy history` lists each record's `entry` id and `--entry <id>` names the one to restore; a bare `--revision` is refused where it is ambiguous. The page's roll-back buttons name the record the same way.
- **The options page's Previous revisions list** shows the same ring as `policy history` and rolls back the same way, taking the lane the direction decides.

**`--json` contracts.** `show`, `history`, `set`, and `rollback` accept `--json`, which swaps the prose for a versioned report on stdout (and, for the write lanes, a versioned error object on refusal). Check the `v` field first and refuse a newer value before reading anything else (fail closed).

Every policy transition is audited with the surface and, for grants, the presence path that authorized the signature (`auth=tty`).

## Display language (lang)

The extension's display language is shared state the host keeps (`lang.json` in the runtime directory) and pushes to every connected browser, so one choice reaches them all. The options page sets it with the Display language picker in its header; the terminal twin is:

```text
chromium-bridge lang              # the current value (same as `lang show`)
chromium-bridge lang set zh_TW    # one of: auto, en, zh_CN, zh_TW
```

- **Language is not policy:** not signed, not ratcheted, and unable to affect any security decision, which is why it needs no confirmation on either surface.
- **A value outside the list is refused** at argv and at the page's frame alike, and the previous value stands; setting the current value changes nothing and pushes nothing.
- **A connected browser swaps on the host's next push** (within its poll interval); an offline one adopts the value when it next connects.

## Logging and audit (BB_LOG / BB_LOG_FORMAT)

Diagnostics in both modes go to **stderr** (stdout carries protocol frames). Two environment variables control the output:

| Variable | Values | Effect |
|------|------|------|
| `BB_LOG` | `error` \| `warn` \| `info` (default) \| `debug` | Log threshold. `info` and above print audit lines; set `warn`/`error` to silence auditing. |
| `BB_LOG_FORMAT` | `text` (default) \| `json` | Format of audit lines. `json` emits one JSON object per line, convenient for machine collection. |

**Audit events (stderr)**: every security decision emits one audit line: tool calls (with `req`, `tool`, `outcome`, and on error the stable `code` from [`ERROR_SPECS`](../src/packages/core/src/error.rs), plus `dur_ms`), harness admissions and refusals, client pairing and revocation, host-key revocations, kill-switch transitions, WebAuthn enrollments and presence verdicts, policy writes, and the extension's confirmation and enrollment decisions (forwarded over the port).

The same events are appended as strict JSON records to a durable, size-capped `audit.log` (0600, in the runtime directory next to the lock file), which survives the short-lived processes that write it. Each record names its event in `event_kind`; the JSON stderr form wraps the record in a `"kind":"audit"` envelope, so a collector keys on `kind` and reads the event from `event_kind`.

- **No sensitive content is recorded:** no page text, cookie or storage values, eval return values, or form fill values; masking happens on the extension side ([trust boundaries](./security/trust-boundaries.md)).
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

The options page reads the same trail: its Recent activity section lists the host trail (the default page above, the host's own words per line) beside this browser's ring of local decisions.

Error codes and the error taxonomy are in [architecture.md section 11.1](./architecture.md#111-error-taxonomy-error_specs).

## Related

- Install and first use: [quickstart.md](./quickstart.md).
- Connection lifecycle and disconnect/reconnect semantics: [architecture.md section 5.2](./architecture.md#52-native-host-reconnect).
- Error taxonomy (`NOT_CONNECTED` / disconnect class): [architecture.md section 11.1](./architecture.md#111-error-taxonomy-error_specs).
