# Trust boundaries

The reviewer's ledger: for each of the four hops, the mechanism that enforces it and every residual accepted at it, then the trust record the hops share, the host-owned policy ledger, and the invariants a change must not regress. The reader-grade model, with the hop diagram, is [security.md](../security.md#the-four-hops-and-what-gates-each).

Every residual here is accepted and tracked. An entry states what can happen, the precondition, what bounds it, and why it is accepted.

## Boundary 1: MCP client <-> Rust MCP server  (stdio, JSON-RPC 2.0)

The client harness is trusted only once it is admitted. This hop carries protocol correctness and authorization both.

- **Protocol engine:** the official `rmcp` SDK serves JSON-RPC and MCP behind the serve loop's own line caps and parse gates; the trust-surface decision is in the [rationale](rationale.md#mcp-server-behavior). Unknown methods get `-32601`, parse errors are surfaced, never fatal, and stdout carries only protocol.
- **Admission:** before serving any tool call the server attests the process that spawned it and checks that identity against the paired clients in the trust record. Admission keys on the attested anchor (code signer or image hash), never the self-asserted client name: `CHROMIUM_BRIDGE_CLIENT_NAME` is a log label.
- **What is measured:** on Unix, the running image of the parent `getppid()` names (macOS: a validated `cdhash` plus the signing Team ID; Linux: the SHA-256 of `/proc/<pid>/exe`). On Windows, the creator of the server's stdin pipe (image SHA-256 plus the Authenticode publisher as the signer), since the recorded parent is caller-selectable at `CreateProcess`.
- **Posture:** no client paired yet means admission is not enforced, logged at ERROR level on every start. Once one client is paired, anything unmatched fails closed, including an identity that cannot be measured and a record that cannot be read.
- **Relays:** a second MCP-server instance attaches to the broker over the socket at boundary 2 and reports its own attested parent in its attach frame, trusted because the relay connection itself proved it runs this binary. The broker decides admission for every relay the same way.
- **Revocation:** admission is not decided once. The trust record is re-read before every in-session request (the broker's per-request gate) and on a one-second timer for idle connections, so a revoke from any surface refuses the revoked harness's next request and its re-attach.
- **Kill switch:** while the latch is set, or the record is unreadable, every `tools/call` from every harness is answered with the stable `BRIDGE_KILLED` code before any routing. The harness connection stays up so the refusal is a typed error, not an opaque disconnect.
- **Release:** explicit only. `unkill` on the CLI, or the extension's release frame behind the presence exchange at [boundary 3](#boundary-3-chrome---native-host--native-messaging-framing). Both transitions are audited, and a release carries the auth path that authorized it.

Residuals at this hop:

- **The attested party is who spawned the server, not who writes its stdin.** stdin is an anonymous pipe with no kernel peer credentials, and a pipe end can be inherited or passed on, so spawner and writer are not provably the same. The pid-keyed measurement carries the usual microsecond pid-reuse race (on macOS the image is still signature-validated).
  - **Measured once:** the parent is measured at process start and the cached identity is re-decided against the trust record on every request. A reparent before the measurement names the reaper, refused once clients are paired; a spawner that exits mid-session while another process holds the pipe leaves requests served under the admitted identity.
- **Attestation identifies a binary, not an intention.** A paired harness that is compromised stays trusted until revoked.
- **Windows: a holder of the harness's pipe end can run a server on it.** A child the harness spawned with a piped stdin holds that end by inheritance and can start a server that attests the harness. Anonymous pipes are one-way, so it reads only the harness's own requests; a same-user process with `PROCESS_DUP_HANDLE` on the harness can duplicate the write end and inject requests.
- **Windows: the harness is measured as the creator of the stdin pipe.** The server requires both pipe ends to name one process other than itself and fails closed on a console or on ends from two processes.
- **Windows: the publisher anchor skips revocation.** `WinVerifyTrust` runs with no revocation check, the policy a browser's own installer verification uses: an online check stalls startup offline, a cache-only check fails on a machine that never fetched the CRL. A revoked publisher certificate keeps its anchor until `revoke-client` removes it; a catalog-signed image has no embedded signature and anchors by hash alone.

## Boundary 2: Rust MCP server <-> native host  (bridge socket, NDJSON)

The one hop defended against local peers: any process that could try to reach the bridge.

- **Ownership:** the first MCP-server instance to bind the socket and the lock is the broker. Later attested instances attach as relays over the same socket, browser native hosts attach alongside them, and one shared session multiplexes every harness's tool calls through the browser connections.
- **Lifetime:** the broker is ref-counted on harness clients (its own stdio harness plus relays; browsers deliberately do not count) and exits when the last one detaches. The shutdown protocol is model-checked with loom: shutdown exactly at zero, no attach after the terminal decision.
- **No listening port:** on Unix the bridge is a 0600 Unix-domain socket inside a 0700 per-user directory. On Windows it is a named pipe whose security descriptor admits the current user alone, enforced by the kernel at open.
- **Peer-UID check (Unix):** on `accept` the server reads the connecting peer's UID from the kernel (`getpeereid` or `SO_PEERCRED`) and drops any connection not from its own UID, before authentication.
- **Mutual executable attestation:** still before authentication, each end takes a kernel-attested identity for the peer and requires it to match its own running image, so a different same-user program is rejected here. The server attests the host after `accept`, the host attests the server after `connect`. Self identity is measured at startup, before bind, accept, or dial.

| OS | Peer identity | Binding |
| --- | --- | --- |
| Linux | the peer pid from `SO_PEERCRED`, then the SHA-256 of `/proc/<pid>/exe` | the running inode; a narrow pid-reuse race on resolution |
| macOS | the peer's kernel audit token (`LOCAL_PEERTOKEN`), validated with `SecCodeCheckValidity`, compared by `cdhash` | the running image, which closes the path re-open TOCTOU and the pid-reuse race; only `ENOPROTOOPT` (older systems) falls back to a pid-identified `SecCode`, where the narrow pid-reuse race remains, and any other error fails closed |
| Windows | the pid the kernel recorded for the pipe's other end, then the SHA-256 of the image file that pid runs | the file path, re-opened; the residual below |

- **HMAC challenge-response:** the server sends a fresh random nonce, the host replies with `HMAC-SHA256(secret, nonce)`, verified in constant time. The per-run secret lives in the lock file, private per [the owner-only rule](#the-trust-record), and never travels on the wire; the per-connection nonce defeats replay.
- **Attach frame:** immediately after the handshake every peer sends one role-declaring frame (browser, or relay client), read fail-closed; a relay's carries its attested harness identity for the boundary 1 decision. A browser reconnect under the same label replaces that label's previous writer.
- **Bounds:** at most 16 distinct browser labels and 8 harness clients, at most 32 connections mid-handshake, a 10 s handshake-plus-attach read timeout cleared for admitted idle connections, and a per-relay GCRA rate limiter (burst 128, refill 128/s) that drops a flooding relay. Each connection is size-checked NDJSON.
- **Kill switch:** while the latch is set, the broker's watcher severs every live browser connection within its one-second tick, draining in-flight calls into typed failures, and browser attaches are refused at admission. An unreadable trust record gets the same treatment. Relays stay attached; their calls are refused typed at boundary 1.

Residuals at this hop:

- **The same binary, re-run by a same-user attacker, is indistinguishable from the legitimate host.** The bytes and the `cdhash` are identical, so neither a hash nor a code signature can tell them apart. On macOS trust is pinned to one exact `cdhash`; Team-ID or designated-requirement pinning, to also accept a separate trusted build, is a deferred follow-up.
- **Windows measures an image by path.** The pipe peer's pid resolves to an image path, and the hash and signature are read from that file, not from the mapped image, which user mode has no handle to. A running executable can be renamed, so a same-user process can place another file at the path between launch and measurement; the pid-reuse race applies too.
- **Windows: the lock file gets no explicit mode.** The per-run secret relies on the default permissions of the per-user runtime directory (`LOCALAPPDATA`, or `USERPROFILE\AppData\Local`; the temp-directory last resort is not guaranteed per-user). The secret is one gate of four, not the only one.
- **The broker aggregates blast radii.** One process fronts all clients, mitigated but not eliminated by the caps, and it is a single point of failure whose crash EOFs every attached harness; the survivors' restarts elect a new broker.

## Boundary 3: Chrome <-> native host  (Native Messaging framing)

Chrome spawns the host per the host manifest, whose `allowed_origins` pins the extension id, so only our extension can open it. The extension, in turn, pins the host it paired.

- **Framing:** a 4-byte little-endian length prefix plus JSON, a 64 MB inbound clamp, a 1 MB outbound cap, a single writer with a flush per frame, and `panic = "abort"` with a stderr panic hook so a panic cannot corrupt the frame stream. The host shuts down on stdin EOF.
- **Fuzzed:** cargo-fuzz targets in `src/packages/core/fuzz/` cover the wire parsers (native-messaging framing, MCP JSON-RPC, the bridge and handshake decoders) and the semantic validators behind them (the handshake MAC verifier, the frame classifier, the host-key challenge builder, the manifest ownership decision).
- **Host-handled control frames** are answered by the host itself and never forwarded to the MCP server; the same kinds arriving from the server leg are dropped as injections. The [architecture page](../architecture.md) owns each exchange's sequence; the ledger names what the host terminates:

| Family | From the extension | From the host |
| --- | --- | --- |
| host key | `enclave_challenge`, `enclave_revoke` | `enclave_proof`, `enclave_error` (`not_enrolled` when no key exists), `enclave_revoked` |
| client admin | `client_list`, `client_revoke` | `client_list_result`, `client_revoke_result` |
| kill switch | `kill_status`, `kill_engage`, `kill_release` | `kill_status_result` |
| WebAuthn | `enroll_begin`, `enroll_finish`, `presence_assert`, `presence_confirm`, `browser_revoke` | `enroll_options`, `enroll_result`, `presence_request`, `presence_result`, `browser_revoke_result` |
| registration | `registration_status`, `registration_repair` | `registration_status_result` |
| policy and language | `policy_get`, `policy_restrict`, `lang_get`, `lang_set` | `policy_current`, `policy_restrict_result`, `lang_current` |
| audit | `audit_event` (fire-and-forget) | - |

- **`audit_event`** is kind-whitelisted (the extension-owned confirmation and enrollment kinds only) and the host stamps the surface itself, so the browser leg cannot forge a host-side event into the trail.
- **The audit trail:** security decisions (admissions, refusals, confirmations shown, allowed, and denied, revocations per surface, kill transitions, policy writes, tool calls) are recorded to stderr and to a private `audit.log` with size-capped rotation, read by `chromium-bridge audit`. The [CLI page](../cli.md#logging-and-audit-bb_log--bb_log_format) owns the format; the extension mirrors its own events into a bounded ring (200 entries) behind the confined storage at boundary 4, read by the read-only options panel.
  - **Not every decision reaches the host's trail:** the two extension-local kinds, `policy_refused` and `policy_compromised`, stay in the ring by design, and a failed storage write drops the record (the compromise-mark entry in the [policy ledger](#host-owned-policy-residual-ledger)).
- **Killed mode:** while the latch is set, or the trust record is unreadable, the host runs control-plane only. It never dials the broker, drops bridge frames, and keeps the control frames working so status, engage, and the policy pull stay reachable. The brake (`kill_engage`) is one frame with no gate; the release opens the presence exchange below.

**Host identity.** The extension pins the host's P-256 public key, which `chromium-bridge pair` mints behind a confirmation typed on a real terminal into the OS credential store through `keyring` (the Keychain, the Credential Manager, or the Secret Service), or with `--file-store` into a file in the runtime directory, private per [the owner-only rule](#the-trust-record). The file's presence is that choice; a store failure is reported, never redirected to the file.

- **The pin:** the user compares the fingerprint `pair` printed with the one the extension shows, which defeats a host sitting between them. A host that cannot read its key fails the pin closed; `revoke --all` deletes the key and, once the store confirms it gone and the host-key marker moved, pushes a host-originated revocation, so a pinned extension fails closed without waiting for a reverify.
- **The key's one job:** identifying the installation to the extension, and signing the policy baseline. Signing is not presence-gated; presence is the browser's authenticator, below.

**The WebAuthn presence exchange.** Every act the extension asks for that restores or grants capability (releasing the kill switch, enrolling another browser) runs behind a request the host mints and verifies.

```text
host    statement = domain || 0x00 || browser label || 0x00 || action || 0x00 || nonce
        challenge = sha256(statement)                                      -> presence_request
ext     navigator.credentials.get({ publicKey: { challenge, rpId: <extension id>, ... } })   <- the human gesture
host    verify: rpIdHash, the user-present flag, the challenge echoed in clientDataJSON,
        ECDSA P-256 over authenticatorData || sha256(clientDataJSON), against the key stored at enrollment
```

- **Who may answer:** one request is outstanding per browser connection and a newer one supersedes it. A kill release accepts only a credential enrolled under this browser's label (`wrong_browser_label` otherwise); enrolling another credential accepts any enrolled credential, which is what lets a second browser enroll; an unknown credential is `credential_not_enrolled`.
- **The window:** the extension's confirmation window may answer, echoing the request's nonce, only when no enrolled credential satisfies the request's rule as the enrollments stand at the answer (`software_confirmation_not_allowed` otherwise). A browser's own act: no credential under its label. An enrollment: no credential on the machine, so a second browser enrolls by another's tap, never a click.
- **The counter:** the sign counter must advance once either side counts, persisted under the trust-record lock, so a replay or a cloned counting authenticator fails closed. An authenticator that never counts reports zero on both sides, and the counter does not catch a clone of one.
- **Enrollment:** `navigator.credentials.create` is accepted with `attestation: "none"` only, ES256 (P-256) only; the credential key comes from the attested credential data and no attestation chain is trusted. The first enrollment on a machine with none is trust on first use, re-checked under the lock at the write; every later one needs an assertion from an enrolled credential.
- **Forgetting the last enrolled browser reopens first use.** `revoke <browser>` and the browser's own Forget action need no proof, since they only remove capability; on the last enrollment they return the machine to trust on first use, so the next `enroll_begin` from any browser enrolls unchallenged, the fresh-machine residual again. The CLI says so when it happens.
- **A failed assertion** is refused and audited, the request is consumed, and the credential stays enrolled. The attestation that results from a verified answer is a linear witness only the presence module mints, so the release path cannot run with presence unchecked.
- **The CLI's floor:** `pair`, `pair-client`, `unkill`, and `policy set` have no WebAuthn client, so their proof is a phrase typed on a stdin proven to be a terminal, refused before any prompt when stdin is piped. The CLI never raises the browser prompt.

Residuals at this hop:

- **Native-messaging manifest substitution.** The manifest sits in a user-writable directory, so a same-user attacker can rewrite its `path` to a binary that speaks native messaging straight to the real extension, bypassing the socket at boundary 2. `allowed_origins` pins which extension may open the host, not which host the extension accepts.
  - **What the pin closes:** a substituted host that cannot read the host key (another user's process, an impostor behind a locked credential store) cannot answer the challenge, and a pinning extension fails closed.
  - **What stays open:** the key is a software key the same user can read, MV3 respawns the host on every service-worker restart (roughly every five idle minutes), and presence cannot be demanded per reconnect, so a same-user attacker who swaps the manifest or re-executes our binary is indistinguishable at reconnect time.
  - **What it cannot forge:** a WebAuthn assertion from the browser's authenticator. It can forge the revocation push and fail a pinned bridge closed: a denial of service against the user's own bridge that grants nothing. A substituted host that skips its own verification is the same-user process the IPC layer already does not defend against.
- **The host key is a software key.** A same-user reader of the key can sign a policy baseline the pin verifies, without the terminal confirmation the CLI demands. This is the narrowing accepted when per-use presence moved to the browser's authenticator, which exists on every platform; the key identifies the installation and nothing stronger.
- **The hardware behind the tap is the authenticator's.** The user verification is the platform authenticator's (a biometric, a PIN, a security key), and the browser suite's virtual authenticator proves the protocol, not the hardware.
- **The floors attest intent, not hardware.** The window for a request no enrolled credential may answer and the terminal for the CLI stop silent, scripted, and accidental grants, not a same-user process that drives a pty. Every audited act records the path that authorized it (`auth=tty`, `auth=confirm_window`, `auth=webauthn:<fingerprint>`), so a software-attested grant is always distinguishable.
- **`pair` leaves no audit record of its own.** Its evidence is the extension's re-pin; for `--reset`, the revoke record and the epoch bump.
- **Key disposal's epoch bump is best-effort.** `revoke --all` and `pair --reset` clear the signed baseline and bump the host-key epoch in the disposal critical section, but the epoch write can fail: disposal warns at once, other surfaces notice only at their next key verification, and a first-write baseline signed mid-disposal can then land.
  - **`revoke --all` is the exception:** that same write forgets the enrollments and clients, and a failed baseline clear or record write is reported as a failed reset, never warned past.
  - **Bounds:** landing it still costs a presence attestation, and the next pairing's pre-mint baseline clear removes it before a new key exists; that clear is itself best-effort and warns on failure.
- **A credential-store entry the store would not answer for outlives a file-store pairing.** `pair --reset --file-store` and `revoke --all` proceed when the store does not answer (a locked or absent Secret Service), warning that an entry it may hold stays behind; the file key shadows it only while the file exists.
  - **Sequence:** the store becomes unreachable, the user pairs into a file, later revokes that file key while the store is still unreachable, and the store comes back: the old key is live again.
  - **Bounds:** an extension that re-pinned to the file key holds no pin the resurfaced key matches. One still pinned to the old store key (the re-pin never finished, or the revocation push was withheld because the host pushes it only on a clean absence) trusts it again.
  - **Either way** `chromium-bridge enclave-status` reports a key the user believed gone, and `policy set` signs with it, until `pair --reset` (or `revoke --all`, which also forgets every browser and client) runs again once the store answers.
- **Registration repair is not presence-gated.** The options page's repair frame re-registers the detected browsers through the same seam as `doctor --fix`: idempotent, pointing browsers at this binary and nothing else, the same posture as the CLI path, which has no gate either. A compromised extension gains only what any same-user process already has.
  - **The one difference:** a manifest another tool wrote at our host id is replaced by the CLI's explicit `--fix` and left by the frame.

## Boundary 4: Extension <-> web page  (Chrome API / content script / DOM)

The page is untrusted. This is the security-critical boundary.

- **Allowlist:** page-level tools run only on origins the user approved; a new origin prompts the user and requests the host permission. The page cannot self-approve. `allowAllSites` is an explicit opt-in.
- **Confirmation:** submit and link clicks, `page_press`, `page_select`, `page_eval`, `tab_close`, and `page_upload` confirm on an extension-owned popup window (`confirm.html`), a `chrome-extension://` document in its own process the page cannot read, focus, overlay, auto-click, or auto-dismiss. The router accepts its ready and resolve messages only from that exact document. A timeout, a close, and a missing provider all deny.
- **Scope of the prompt:** only these high-risk tools confirm. Navigation, `page_text`, `tab_list`, and masked cookie or storage reads run with no per-action prompt, so a driver that already reaches the extension can navigate, read masked content, and enumerate tabs without the user seeing each step. The confirmation gates the dangerous actions; it does not promise that nothing happens silently.
- **Binding:** a navigation racing an open confirmation is caught by an origin assertion run in the page atomically with the act; a click is bound to the approved target descriptor. `page_upload` re-checks the tab's origin after the confirmation and binds the attach to the document node it resolves then, so a same-origin navigation during the prompt passes that check.
- **Grace window:** after an approved submit or link click, a repeat under the [per-tab key](../../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe) skips the prompt for `confirmGraceMs`, whose default the same section owns. `page_eval` is excluded and reconfirms on every call; `page_upload` reconfirms every call with its path shown unmasked on purpose, so the user sees which file would leave the disk.
- **Presence routing:** the policy field `presenceConfirm` routes `page_eval` and `page_upload` to a presence provider only where one is installed. None is today, so the window confirms whatever the field says; the routing verdict is snapshotted into the decision so a policy change while the prompt waits cannot re-route it.
- **Masking:** page text, cookies, storage, and eval output are masked in the service worker at egress, once for both page backends. The rules are the [security policy's](../../.github/SECURITY.md#masking-is-heuristic-and-best-effort).
- **Trust-state isolation:** Chrome exposes `storage.local` to content scripts by default, so the extension confines `storage.local` and `storage.session` to extension contexts with `setAccessLevel(TRUSTED_CONTEXTS)`. A content script then cannot read or write the enrollment pin, the compromised marker, the enforced policy state (the ratchet and the cutover flag), or the allowlist, and the enrollment gate fails closed until the restriction lands.
- **The router is gated too:** every runtime message whose sender is not one of the extension's own pages is refused, so a content script cannot seed the allowlist or read the pinned key id and fingerprint.
- **Kill mirror and audit ring:** the worker-only mirror of the host's kill state and the extension's audit ring live in the same confined storage. The gate refuses while the mirror reads killed, unknown, or malformed; garbage never maps to the permissive absent state.
  - **Who writes and reads it:** the mirror is written only from the host's kill-status frames, never from a runtime message, and only the extension's own pages may read the state, toggle the switch, or read the trail.
- **Isolation:** content scripts run in the isolated world; `page_eval` uses a `Function` constructor, not the content script's scope, and its result is serialized safely (cycles, DOM nodes, exotic types) before masking. Both page backends run one shared DOM implementation (`src/apps/extension/src/lib/dom/page-api.ts`); the CDP path ships its stringified source, so the two cannot diverge.
- **Read-only credentials:** no cookie or storage writes.

Residuals at this hop:

- **Read exfiltration on approved origins.** Once an origin is on the allowlist, `page_text`, `cookie_get`, and `storage_get` run with no per-action confirmation, protected only by heuristic masking. A page that prompt-injects the model on an approved, logged-in origin can silently read page content and any secret the masking misses (it matches token-like shapes, not meaning).
  - **Rejected alternative:** per-action prompts on reads would add a confirmation to nearly every agent step, teaching users to click through the prompts that guard the genuinely dangerous actions.
  - **Bounds:** the origin allowlist (the page must already be somewhere the user approved), masking as a best-effort layer, and the audit trail.
- **The grace window lets unrelated same-origin code run.** One approved click covers whatever the same origin does next in the same action kind for the window's duration; `page_eval` never rides it.
- **The window proves a click, not presence.** It proves a click on a page-unreachable surface, not user presence in a cryptographic sense.
- **`page_eval` and `page_upload` have no WebAuthn route.** Both confirm on the window until the extension asks the host for a presence request for them. Opting `presenceConfirm` out stays a signed, presence-gated policy write.
- **`page_upload` can attach any local file the caller names.** When the tool is enabled (off by default), it attaches whatever absolute path the call supplies, so a model induced to call it can hand a page a file the user never picked, such as an SSH key.
  - **Gates:** the opt-in, the origin allowlist, and a per-call confirmation showing the exact path on the page-unreachable window.
  - **Open:** the path is not constrained to a picked file or a safe directory; an approved call attaches exactly what it names. Tracked for hardening (an OS file picker, so the model names no path) before file upload is recommended for general use.
- **History navigation is gated on the current origin, not the destination.** `page_back` and `page_forward` check the allowlist against the tab's current origin; the page they land on is wherever history points.
- **The trust-state cold-start window.** `setAccessLevel` is asynchronous and applied after the worker starts, so for under a millisecond at cold start a content script from a prior worker life, in a compromised renderer, could write a tampered value before the restriction lands.
  - **Bound:** with the router gated, this is the only remaining content-script path to the trust state. No user-space API closes it, and the pin's cryptographic checks bound, but do not erase, what a planted pin achieves.
- **`page_snapshot_precise`** briefly attaches the debugger, so the infobar flashes.
- **CDP mode** (`cdpMode`, a host-owned grant, off by default) routes every page-level tool through `chrome.debugger` in the page's main world. Enabling it is a signed, presence-gated policy write, refused where no host key exists.
  - **Cost:** it bypasses page CSP (so `page_eval` runs on strict-CSP sites) and holds a persistent debugger attach, so the "Started debugging this browser" banner stays up. The allowlist, confirmations, and masking are unchanged; the wider surface and the removed CSP layer are the price of the opt-in.

## The trust record

`trust.json` in the runtime directory, next to the lock file: owner-only, written atomically under the runtime lock, parsed fail-closed (`deny_unknown_fields`, a version check, a 256 KiB size cap). Every enforcement point reads enrollments, the kill latch, and the client allowlist from the same snapshot.

**Owner-only means Unix.** Every private file the host writes (`trust.json`, the lock file, `audit.log`, the `--file-store` key) is created with mode 0600 under Unix: a record written atomically is created 0600 and renamed over its destination, and a file opened in place is re-tightened on the open handle, so a pre-planted looser file cannot keep its bits.

On Windows there is no mode branch: the file inherits the per-user runtime directory's ACL, the residual boundary 2 names.

| Field | Meaning | Writers |
| --- | --- | --- |
| `epoch` | bumped by every write: the record's global ordering, the value a scoped marker copies when its scope changes. Never an authority: no decision or push keys on it (the broker reads it only to deduplicate a log line), and every decision is re-read from the record | every writer |
| `kill_epoch` | the `epoch` of the last kill-latch write, engage or release, whether or not the latch changed (0 = never), stamped in the same atomic write as the latch; the native host's watch pushes the kill status when it moves between polls | the writers of `killed` |
| `host_key_epoch`, `policy_epoch`, `lang_epoch` | the `epoch` of the last host-key disposal (a revoke or reset, never a minting), host-owned policy write, or language change (0 = never). The watch compares each between polls and pushes only its frame (revocation, `policy_current`, `lang_current`); the revocation push also needs the store to confirm the key is gone, so a scribbled marker cannot fake one. A client or enrollment write stamps none and triggers no push | the writer of that scope's change, in a second write after its own store |
| `killed` | the global kill latch | `kill` and `unkill` on the CLI; the extension's engage and release frames |
| `clients` | `null` means never paired (admission not enforced); a list, even empty, means enrolled and locked | `pair-client`, `revoke-client`, and `revoke --all` (which empties a paired list and leaves `null` as it is) on the CLI; the extension's host-mediated client revoke frame (its client list frame only reads) |
| `enrollments` | the WebAuthn credential each browser enrolled, under its label, with its sign counter | the enrollment exchange at boundary 3; the presence verifier, advancing a credential's counter on every accepted assertion; `revoke <browser>` and `revoke --all` on the CLI, and the extension's `browser_revoke` frame for the connected browser's own label, all forgetting without a proof since that only removes capability |

- **Three stamps are best-effort.** `host_key_epoch`, `policy_epoch`, and `lang_epoch` land in a second write under the same lock hold, after the scope's own store. When it fails the change stands, the host warns, and only the watcher's push is lost.
  - **Who still learns it:** the browser that asked gets the reply frame; a change made elsewhere reaches a connected extension at its next connect, where the policy and language frames are pushed unconditionally. The disposal case is a [boundary 3](#boundary-3-chrome---native-host--native-messaging-framing) residual.
- **Re-pair replaces:** `pair-client` replaces a same-named entry, the re-pair path for hash anchors after a re-sign. `revoke-client` leaves the list in place even when it empties.
- **Both halves on unpair:** unpairing from either side deletes both credentials; the extension's revoke also asks the host to delete its key, durably re-sent until acknowledged.
- **Revocation latency:** the socket leg is immediate; the extension reflects a host-key revoke at its next service-worker wake.
- **Enforcement:** file permissions on the 0700 runtime directory, the atomic-write discipline, and the record re-read at every admission and in-session request.

Residuals of the record:

- **A same-user writer owns the record.** A same-user process that can run our CLI can pair itself, plant an enrollment, or flip the latch, exactly as it can delete the record. Deleting `trust.json` reverts to the ERROR-logged bootstrap: the irreducible same-user residual, since no user-space marker survives a writer who can delete any file we can write.
- **Tampering with the epoch or a scoped marker** can force a spurious push or fail every read closed, but cannot admit anyone the paired list, the host key, or the enrollments do not.
- **Engagement has a sub-second window** (one watcher tick) for in-flight work, which the severed sockets then drain. Nothing clears the latch on its own: no timeout, restart, or reconnect; a refused assertion never falls back to the window, and both transitions refuse on an unreadable record, because releasing from an unknown state would fail open.

## Host-owned policy residual ledger

The security policy is host-owned: a signed baseline, an unsigned restriction overlay, an extension-side value ratchet, and a per-connection dispatch barrier. The [architecture page](../architecture.md#113-host-owned-policy-and-language-sync) owns the mechanism; this ledger owns the residuals, each accepted deliberately.

Read the entries together; they compose. The first entry's bound (only a genuine baseline at or above the stored revision) anchors on the stored ratchet record, and the cold-start entry makes that record deletable in its window: with the anchor deleted, the most-permissive genuine baseline the key ever signed applies as a first-ever policy, at any revision.

- **A failed compromise-mark persist plus a worker restart reopens the barrier to a captured genuine policy.** When a push fails signature verification against the pin, the extension latches an in-memory compromise flag at once, then writes the durable mark. If that write fails and the worker restarts, the fresh worker starts unlatched, so a replayed byte-identical push verifies, ratchets as an idempotent replay, and reopens the dispatch barrier.
  - **Precondition:** a durable-storage write failure, a worker restart, and a captured genuine frame.
  - **Bounds:** the barrier reopens only to some genuine policy the pinned key signed at or above the stored revision. The attacker picks among captured documents and cannot forge a fresh relaxation past the ratchet and the signed touched-set rule without the host key, which a same-user reader of the software key has (boundary 3).
  - **Re-attestation** narrows it only where the user opted into periodic re-verification (`hostReverifyMs`; at the default of 0 no reconnect is challenged). Within one worker life the in-memory latch holds regardless.
  - **Evidence:** the failed persist is logged, never swallowed, but no durable evidence survives: the audit event writes to the storage that just failed, and the compromise kind is extension-local, never forwarded to the host's trail.
  - **Accepted** because an in-memory latch cannot survive a restart; closing it fully needs durable-write-before-proceed or boot-time re-attestation, not a wider latch.
- **One microtask window in the same-key undo path.** The write-undo that restores a superseded stored policy record re-checks the pin-reset epoch immediately before its restoring write, but `chrome.storage` is not transactional, so a same-key re-pair completing between that check and the write can see the undo restore a record the reset just removed.
  - **One-directional by construction:** the epoch is captured before the prior-record read, so a misfire on the other side turns a restore into a remove (fail-closed), and the surviving direction can only resurrect an inert record the scope checks keep out of enforcement under any other pin. Accepted: unfixable without transactional storage.
- **One-push disagreement.** The two enforcement points (host dispatch, extension gate) can disagree transiently around a policy change; the window is one push, and the extension is authoritative at its boundary.
- **Requests racing a bad push's verification.** Policy frames route before the request gates but are not ordered against the request queue, so between a bad-signature push arriving and its verification failing (a frame hop, two parses, a base64 decode, a pin read, an ECDSA verify), requests already past the gate can still dispatch under the still-open barrier.
  - **Bounds:** the in-life compromise latch is set synchronously the moment verification fails and is read twice per request (at the gate and again at dispatch's own policy read), so a request must clear both reads before the failure lands; the requests that slip through ran under the stored effective policy, the ratcheted floor never laxer than what the user last saw applied.
- **A throwing presence probe denies the op, with no window fallback: a rule kept for the WebAuthn route.** When the extension gains a presence route for `page_eval` and `page_upload`, a probe that throws must deny the operation; a probe that cleanly reports no capability routes to the window, the documented degraded surface.
  - **Today:** no presence provider is installed, provider selection is synchronous with no probe, and an absent or compromised pin denies page operations at the enrollment gate before any confirmation.
  - **Why no fallback:** a fallback would let any probe failure downgrade a presence-required (`presenceConfirm`) approval to an ordinary window click, the presence ladder's no-downgrade rule inverted. The cost is availability on an anomalous path, never capability.
- **A hostile unpinned host can occupy the confirmation FIFO with relaxation prompts.** On a machine with no pin, a relaxation is held for the user's window approval. Byte-identical replays of the pending push (same baseline bytes, same overlay, same connection) collapse onto its prompt; distinct candidates serialize one prompt each, so a hostile host can keep the FIFO busy as long as the user keeps not answering.
  - **The FIFO is global** across all confirmation kinds, so the occupancy also starves `page_eval`, `page_upload`, and click confirmations queued behind it.
  - **Two sharpenings:** the collapse keys on a JSON-stringified overlay, so a key-reordered or trivially varied restriction defeats it (costing an extra prompt, never suppressing a distinct push); and a forged unsigned restriction applies silently with no prompt at all, the forged-restriction denial of service the policy design concedes, since it only removes capability.
  - **Bounds:** one prompt at a time, each denial audited, nothing relaxes without an explicit approval, and pinned machines are unaffected (no approval window exists there).
  - **One spillover:** the language lane shares the frame lane, so on an unpinned machine a queued 120 s approval prompt can delay a language-choice response. Benign: the local `uiLanguage` write already landed and the UI already swapped before the relay; only the diagnostic `sent` flag is delayed, and the language choice reports `false` on an unpinned machine anyway.
  - **Accepted** because the unpinned approval window is inherently occupiable by the one peer allowed to request it.
- **An explicit "en" choice re-offers first-pairing language adoption on every reconnect.** The host's language store maps an absent record to the default (`"en"`, seq 0), and a `lang_set` carrying the stored value is a deliberate no-op that bumps nothing, so an explicit `"en"` against a never-set store leaves seq at 0.
  - **Effect:** the host cannot distinguish "never set" from "explicitly set to the default", and such an extension re-sends its one adoption frame on every reconnect.
  - **Bounds:** one frame per connect (the per-connection adoption latch ends it within a connection), the frame is a no-op host-side, and the lane is cosmetic: language is browser-owned display state, never policy. Accepted as-is: folding "explicitly set to the default" into a seq bump would ripple through the echo-suppression semantics the seq exists for, a real risk for a cosmetic gain.
- **A corrupted compromise mark reads as not-compromised.** The durable mark's reader returns null on a record it cannot parse, so a corrupted mark reads as "no evidence" across every read site that inherits it, including the enrollment gate, the presence-capability probe, and the pairing-notice suppression.
  - **Bounds:** the write path is confined to trusted-context storage, so producing the corruption needs extension contexts or the cold-start window, not a web page or a steady-state content script. The pin record's own self-check (its key id must match its stored public key) is internal consistency, not authenticity, but a corrupt mark cannot forge or alter the pin.
- **The cold-start window also fronts the policy state.** The sub-millisecond `setAccessLevel` window at boundary 4 covers the policy ratchet, the cutover flag, the durable compromise mark, and the prior-pin record. One honest difference from the enrollment gate: policy frames route before the gates and the policy path does not itself wait on the restriction landing, so the policy state relies on the restriction being applied early, not re-checked at use.
- **"A pinned extension refuses unsigned baselines" is a pinned-case bound only.** On a machine whose extension has no pin, the approval-window lane accepts an unsigned document behind a fresh, explicit user approval. No host path writes an unsigned baseline, so the window lane's own concession (software driving the extension's pages could answer its prompts) is the whole exposure.
- **A decision racing a `cdpMode` revocation can produce a transient debugger attach.** The attach for a new CDP session resolves before the post-attach policy recheck reads the grant, so an in-flight decision that snapshotted `cdpMode: true` can still attach after a revocation lands.
  - **Bound:** no CDP command is sent on that session; the recheck tears it down and fails the op, with the caveat that the session layer swallows detach errors, so the teardown is best-effort. Rechecking pre-attach broke pinned attach-protocol orderings.
- **A pin revoke leaves live CDP attachments in place.** The policy-driven teardown fires on storage writes, and the revoke path deliberately retains the stored policy record (the same-key anti-replay anchor), so no write fires and an existing attachment, banner included, survives until the tab closes.
  - **Bound:** post-cutover the dispatch barrier stops all new work immediately; a pre-cutover extension has no barrier and enforces the deny baseline. The attachment can only linger, not act.

## Invariants that must not regress

- stdout on either binary mode is protocol bytes only; diagnostics go to stderr.
- The bridge never serves a connection that failed the same-user check (the peer UID on Unix, the pipe's descriptor on Windows), the executable attestation, the HMAC handshake, or the mandatory role-declaring attach frame.
- Once a trusted-client allowlist exists, no harness is served unless its attested identity matches an entry; an unmeasurable identity and an unreadable allowlist both fail closed, and the self-asserted client name is never the authorization key.
- The host manifest's `allowed_origins` always pins exactly our extension id. That pins extension-to-host; the host-to-extension hop is the pinned host key at boundary 3.
- No page-level tool runs on a non-allowlisted origin, absent `allowAllSites`.
- No tool writes cookies or web storage; there is no `cookie_set` or `storage_set` by design.
- The confirmation gates are on by default, and relaxing one is a signed, presence-gated policy write.
- While the kill switch is engaged, or its record is unreadable, no tool call is served and no browser connection stands; the switch clears only by an explicit, presence-attested release from a trusted surface, never automatically.
- The audit trail never gates a decision: recording is log-after-decide, and a failed write drops the record visibly (the `dropped` counter) rather than failing the operation in either direction.

Changing any of these is a security-relevant change under the [review bar](../../.github/SECURITY.md#security-relevant-changes-review-bar).
