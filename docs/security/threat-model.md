# Threat model

What chromium-bridge protects, from whom, and what it explicitly does not defend
against. Pairs with [trust-boundaries.md](trust-boundaries.md) and the
[tool risk matrix](tool-risk-matrix.md).

## Assets

- The user's **authenticated browser sessions** (cookies incl. httpOnly, web
  storage tokens) - i.e. the ability to act *as the user* on sites they're
  logged into.
- **Page content** the user can see.
- The ability to **execute actions** (click/fill/navigate/eval) as the user.
- Integrity of the **wire protocols** (a corrupted stream can hang or crash the
  bridge).

## Actors

| Actor | Trusted? | Notes |
|-------|----------|-------|
| The user | yes | owns the machine and Chrome profile |
| The MCP client (Claude Code, Codex, ...) | **yes, by design** | the user configured it; it drives the tools |
| The Rust binary (MCP server + native host) | yes | the thing we're securing |
| The MV3 extension | yes | but runs alongside untrusted page code |
| **The web page** | **NO** | may be attacker-controlled; may host prompt-injection |
| Other local users / processes | **NO** | may try to connect to the bridge socket |
| The network | out of scope | no remote surface - everything is localhost/stdio |

## Trust assumptions

- **Single-user machine.** The bridge is a 0600 Unix-domain socket (no
  listening port) in a 0700 per-user directory, gated by a kernel peer-UID
  check, kernel-attested executable identity, and an HMAC challenge-response
  over a per-run secret; the model assumes no hostile local user with the same
  UID. Attestation additionally rejects a *different* same-user binary, but
  cannot stop a same-user attacker who re-runs *our own* binary (see threat #4
  and [ADR-0020](../adr/0020-kernel-attested-peer-identity.md)). (See also
  [ADR-0019](../adr/0019-authenticated-ipc.md).)
- **The MCP client is trusted.** A malicious client the user themselves
  installed is out of scope - it already has whatever the user granted it. The
  tools exist to be driven by that client.
- **Chrome's sandbox and extension model hold.** We rely on MV3 isolation
  between content scripts and page JS, and on Chrome enforcing host permissions.

## Primary threats & mitigations

1. **A web page influences the agent into acting on it without approval.**
   -> Page-level ops require an **allowlisted origin**; a new origin triggers an
   explicit user prompt + `chrome.permissions.request`. The page can't add
   itself to the allowlist.

2. **Prompt injection: page content tricks the model into a dangerous tool
   call** (e.g. "run this eval", "read cookies and post them").
   -> Observed page content is *data*, not commands, to the agent. Independently,
   high-risk actions (submit/link click, `page_eval`, tab close) require a
   **user confirmation in an extension-owned window** the page cannot forge,
   read, or auto-dismiss (ADR-0027), and
   `page_eval` confirms **every call** showing the full code. This per-action
   prompt covers the high-risk ops only. Low-risk ops (navigate, `page_text`,
   `tab_list`, and masked cookie or storage reads) run with no per-action
   prompt, so a driver that already reaches the extension can navigate, read
   masked page content, and enumerate tabs without the user seeing each step.
   The confirmation is a gate on the dangerous actions, not a promise that
   nothing happens silently. The gates are on by default; each is a
   documented setting whose opt-out residuals are tabulated in
   [SECURITY.md](../../SECURITY.md#page_eval-and-confirmation-defaults-fail-safe).

3. **Credential/token exfiltration.**
   -> Cookies/storage are **read-only** (no set), **allowlist-scoped**, and
   **masked** (JWT/hex/long-digit/token-like) before leaving the extension.
   `storage_get` masking is not user-toggleable. `page_text` masks passwords and
   card-like numbers.

4. **Another local process hijacks the bridge** to issue tool calls or read
   responses.
   -> On Unix there is **no listening port**: the bridge is a 0600 Unix-domain
   socket in a 0700 directory. Every connection is gated by a **kernel peer-UID
   check** (rejecting other users), **kernel-attested executable identity**
   (Linux: the peer's `/proc/<pid>/exe` must SHA256-match ours; macOS: the peer's
   running image, identified by its kernel audit token, must `cdhash`-match ours
   via the Security framework -- so a *different* same-user program is rejected
   before it can authenticate), and an **HMAC-SHA256 challenge-response** in which
   the per-run secret never crosses the wire and a fresh nonce defeats replay.
   Attestation is mutual (host and server attest each other). The peer-UID check
   and the executable attestation are Unix only. On Windows the bridge is a
   loopback TCP socket with neither check (both are compiled only for Unix), so
   any local process can reach the port and the only barrier is the HMAC secret
   in the lock file. That lock file gets no explicit restrictive mode on Windows;
   it relies on whatever permissions the directory it lands in confers
   (`LOCALAPPDATA`, or `USERPROFILE\AppData\Local` when `LOCALAPPDATA` is
   unset, both per-user by default; or the temp directory as a last resort,
   which is not guaranteed per-user; see `runtime_dir()` in
   `src/packages/core/src/ipc/`). So on Windows the protection rests on the secret staying
   confidential, not on kernel-attested peer identity: a local user who reads
   the lock file can drive the bridge. See
   [ADR-0019](../adr/0019-authenticated-ipc.md) and
   [ADR-0020](../adr/0020-kernel-attested-peer-identity.md). **Not covered:** a
   same-user attacker who re-executes *our own* binary is byte-identical to the
   legitimate host (same hash, same cdhash), so neither the hash nor a code
   signature can tell them apart. The enrollment ceremony
   ([ADR-0021](../adr/0021-enrollment-ceremony.md), threat #6) makes the
   *pairing* of extension to bridge presence-gated, but does not distinguish
   same-user processes post-enrollment (see the manifest-substitution
   residual). Team-ID pinning on macOS (to also trust a separate signed
   build) is a deferred follow-up (see ADR-0020).

5. **A malformed/oversized message crashes or corrupts the bridge.**
   -> Native-messaging framing is length-checked (64 MB inbound clamp, 1 MB
   outbound cap); a `panic = "abort"` profile + stderr panic hook keep panics
   off the protocol stream; parse errors are surfaced, not fatal; and
   cargo-fuzz targets (`src/packages/core/fuzz/`) cover both the wire
   parsers (native-messaging framing, MCP JSON-RPC, the bridge and handshake
   decoders) and the semantic validators behind them (the handshake MAC
   verifier, the frame classifier, the DER signature parser, the enclave
   challenge builder, and the manifest ownership decision).

6. **Silent pairing: a malicious `claude mcp add` (or any process able to
   write an MCP client config) stands up the whole chain without the user
   noticing.**
   -> The **enrollment ceremony**
   ([ADR-0021](../adr/0021-enrollment-ceremony.md), on by default on macOS):
   `chromium-bridge pair` mints a P-256 key inside the Secure Enclave whose
   every use requires user presence (Touch ID / password), and performs a
   presence-gated self-test signature; declining it leaves the machine
   unenrolled. The extension pins the public key and verifies
   `enclave_proof` frames against it; on an unenrolled machine a challenge
   gets `enclave_error: not_enrolled` and a pinning extension fails closed.
   Re-pinning (`pair --reset`) requires presence again, and `revoke` deletes
   the key so no proof can be produced at all. The user compares the SHA-256
   fingerprint printed by `pair` with the one the extension shows, which
   defeats a man-in-the-middle host between them. **Scope:** this closes
   silent *first* pairing and silent re-pinning; it does **not** close
   post-enrollment same-user substitution (see the residual below).

7. **A revoked client or a revoked host keeps acting because revocation does
   not reach the enforcement point.**
   -> The **any-side revocation epoch**
   ([ADR-0025](../adr/0025-any-side-revocation-epoch.md)): a single monotonic
   counter at `runtime_dir()/revocation.json`, bumped in the same critical
   section as the trust-state change it describes, re-read by every enforcement
   point. A `revoke-client` (from the CLI or the extension's host-mediated
   `client_revoke` frame) rewrites the allowlist and bumps the epoch; a live
   broker's per-request epoch guard and its idle-connection watcher then drop
   the revoked harness fail-closed and refuse its re-attach. A host-key
   `revoke` / `pair --reset` deletes the enclave key and bumps the epoch; the
   native host confirms the key is gone in the keychain and pushes a
   host-originated `enclave_revoked` frame, so a pinned extension fails closed
   without waiting for the opt-in reverify. Unpairing from either side now
   deletes BOTH halves of the credential (the extension's revoke also asks the
   host to delete its key, durably re-sent until acknowledged). The epoch is a
   change notice, never an authority: a same-user writer who tampers with it
   can force a spurious re-check or fail every read closed, but cannot admit
   anyone the allowlist or the keychain does not. **Scope:** the socket leg is
   immediate; the extension's reflection of a host-key revoke is bounded to the
   next service-worker wake. A compromised-but-allowlisted client stays trusted
   until revoked (attestation identifies a binary, not an intention). A
   substituted native host (threat #4's manifest-substitution residual) can
   forge the `enclave_revoked` push and fail a pinned bridge closed, a
   denial-of-service against the user's own bridge that grants no capability
   and cannot be authenticated away in user space; see
   [ADR-0025](../adr/0025-any-side-revocation-epoch.md).

## Explicit non-goals

- Defending against a compromised OS account, or a same-user attacker who runs
  *our own* binary. Peer-UID and executable attestation reject other users and
  other binaries, but a same-user process executing the genuine binary is
  byte-identical to the legitimate host and remains out of scope for the IPC
  layer (see threat #4).
- Defending against a malicious MCP client the user configured.
- Multi-user / shared-machine isolation.
- Remote attackers (there is no remote attack surface).

## Residual risks (accepted, tracked)

- **Native-messaging manifest substitution (the host-to-extension hop is
  unauthenticated).** The bridge authenticates the host-to-server socket hop
  with the peer-UID check, attestation, and HMAC, but nothing authenticates the
  native host to the extension. The host manifest sits in a user-writable
  directory, so a same-user attacker can rewrite its `path` to point the browser
  at a malicious host binary. The browser then launches that binary, and it
  speaks native messaging straight to the real extension, issuing `BridgeReq`s
  without ever touching the authenticated socket. `allowed_origins` pins which
  extension may open the host, but nothing pins which host the extension will
  accept. The enrollment ceremony
  ([ADR-0021](../adr/0021-enrollment-ceremony.md)) narrows this: with the
  extension-side pin in place, a substituted host cannot present a valid
  `enclave_proof` without raising a Touch ID prompt the user did not expect,
  so substitution at *enrollment time* is no longer silent. What remains open
  is substitution *between* presence checks: MV3 respawns the host on every
  service-worker restart (roughly every five idle minutes), presence cannot be
  demanded per reconnect (a Touch ID prompt every five minutes is not
  shippable), and any silent per-reconnect credential can be exercised by any
  same-user process. So post-enrollment, a same-user attacker who swaps the
  manifest or re-executes our binary is indistinguishable at reconnect time.
  The opt-in per-action presence tier (tracked separately) is the mechanism
  that would close this remainder.
- **Read exfiltration on approved origins (accepted).** Once an origin is on
  the allowlist, reads are unprompted by design: `page_text`, `cookie_get`,
  and `storage_get` run with no per-action confirmation, protected only by
  heuristic masking. A page that successfully prompt-injects the model on an
  approved, logged-in origin can therefore silently read page content, and
  any secret the masking heuristics miss (they match token-like shapes, not
  meaning, so a novel format can slip through). Gating reads behind per-action
  prompts was considered and rejected: it would add a confirmation to nearly
  every agent step, teaching users to click through the prompts that guard the
  genuinely dangerous actions. This is a consciously accepted residual; the
  mitigations are the origin allowlist (the page must already be somewhere the
  user approved), masking as a best-effort layer, and the audit log.
- The **high-risk click grace window** lets *unrelated* same-origin code run
  without re-prompting: after one approved submit or link click, the same origin
  and action kind skip the confirmation for 60s (see
  [ADR-0006](../adr/0006-toast-confirmation-for-high-risk.md), surface superseded
  by [ADR-0027](../adr/0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md)).
  `page_eval` is not in this window; it reconfirms on every call.
- **Trust-state isolation has a cold-start window (#32, ADR-0027).** The
  enrollment pin, the compromised marker, `requireEnrollment`, and the
  allowlist live in `storage.local`, which Chrome exposes to content scripts by
  default. The extension confines both storage areas to extension contexts with
  `setAccessLevel(TRUSTED_CONTEXTS)` and fails the enrollment gate closed until
  that lands. The runtime message router (the mediated path to the same state)
  refuses every message whose sender is not one of the extension's own pages, so
  a content script cannot seed the allowlist via `add_allow` or read the pinned
  key id/fingerprint via `get_enrollment`. Because `setAccessLevel` is
  asynchronous and applied after the service worker starts, a sub-millisecond
  window remains at cold start in which a content script from a prior worker
  life, in a compromised renderer, could write a tampered value directly to
  `storage.local` before the restriction lands; the restriction then locks it
  in. With the router gated, that cold-start window is the ONLY remaining
  content-script path to the trust state. No user-space API closes it; the
  enclave ceremony's cryptographic checks bound, but do not erase, what a
  planted pin achieves.
- **High-risk confirmations now render off the page-reachable DOM
  (ADR-0027).** Every high-risk confirmation (a submit click, `page_press`,
  `page_select`, `page_eval`, `tab_close`, `page_upload`) shows in a dedicated
  `confirm.html` popup window, a `chrome-extension://` document in its own
  process. A guarded page cannot read, focus, overlay, or click it, and the
  message router accepts the confirmation's ready/resolve messages only from
  that exact document. This closes the earlier residual, where the toast was
  drawn in the page's own DOM (or its MAIN world under CDP) and a
  prompt-injected page could watch for it with a `MutationObserver` and click
  Allow itself. A navigation that races the pipeline while a confirmation is
  open is caught by an origin assertion run in the page atomically with the
  act, and a click is additionally bound to the target descriptor the user
  approved. Residual: the window proves a click on a page-unreachable
  surface, not user presence in a cryptographic sense; ADR-0031 closes that
  remainder for the two crown-jewel tools by routing `page_eval`/`page_upload`
  approval through the host Secure Enclave on an enrolled Mac, where the
  verdict is an unforgeable, host-signed user-presence check (Touch ID or
  the login password). The window remains the confirmation surface for the
  other high-risk kinds, on non-macOS platforms, on an un-enrolled Mac, and
  when `touchIdConfirm` is opted out.
- **`page_upload` can attach any local file the caller names.** When the tool
  is enabled (it is off by default), it attaches whatever absolute path the
  call supplies to a file input, so a model induced to call it on a page can
  hand that page a file the user never picked, such as an SSH key or a private
  document. Three gates stand in front of it: the opt-in, the origin
  allowlist, and a per-call confirmation that shows the exact path (on an
  enrolled Mac, a Secure Enclave user-presence check; elsewhere the
  page-unreachable extension window). What remains open is that the path
  itself is not constrained to a picked file or a safe directory: an approved
  call attaches exactly what it names. Tracked for hardening (an OS file
  picker, so the model names no path) before file upload is recommended for
  general use.
- `page_snapshot_precise` briefly attaches the debugger (infobar flash).
- **CDP mode** (`cdpMode`, opt-in, off by default - see
  [ADR-0017](../adr/0017-cdp-mode-all-ops.md)) routes all page ops through
  `chrome.debugger`. When enabled it **bypasses page CSP** (letting `page_eval`
  run on strict-CSP sites) and holds a **persistent debugger attach** for the
  tab (the "Started debugging this browser" banner stays up). The allowlist,
  per-action confirmations, and masking are unchanged; the residual risk
  is the wider surface and the removed CSP defense-in-depth layer, accepted as
  the explicit price of the opt-in.

## Rebuild delta: new trust boundaries

The workspace/Tauri rebuild
([ADR-0023](../adr/0023-workspace-monorepo-tauri-app.md)) introduced six
boundaries that do not exist in the model above, all now delivered.
Boundaries 1-3 shipped with the broker
([ADR-0024](../adr/0024-multi-client-attested-pairing-and-broker.md) has the
full treatment), boundary 4 with the desktop app
([ADR-0029](../adr/0029-desktop-app-management-surface.md)), boundary 5 with
the Touch ID presence gates
([ADR-0031](../adr/0031-touch-id-confirmations-and-presence-grants.md)), and
boundary 6 with the kill switch
([ADR-0030](../adr/0030-global-kill-switch-and-audit.md)). Each is described
as delivered: mechanism, enforcement point, residual.

1. **Harness -> MCP server stdio admission (delivered, ADR-0024).** The
   server no longer trusts whatever spawned it. Before serving a single tool
   call, it measures the code identity of its parent process --
   `attest_parent()` takes `getppid()` and measures that pid's running image
   (macOS: a `SecCodeCheckValidity`-validated `cdhash` plus the signing Team
   ID; Linux: the SHA256 of `/proc/<pid>/exe`) -- and checks it against the
   trusted-client allowlist at `runtime_dir()/clients.json`. Enforced by:
   the MCP server at startup (`admit_own_harness`), and again by the broker
   for every relay attach (the relay reports its attested parent identity in
   `AttachRequest::Client`, trusted because the relay connection itself
   passed `attest_peer` and is therefore our own binary). Enforcement is
   opt-in like the enrollment ceremony: no allowlist file means unenrolled,
   admission not enforced, logged at ERROR level on every start (the
   pre-existing threat #4 same-user residual, unchanged). Once the file
   exists, everything unmatched fails closed -- including an identity that
   could not be measured, and including an unreadable or corrupt allowlist
   (a load error is never treated as unenrolled). Authorization keys on the
   attested anchor (Team ID where signed, image hash otherwise); the
   self-asserted client name (`CHROMIUM_BRIDGE_CLIENT_NAME`) is a log label
   only. Residual: stdio is an anonymous pipe with no kernel peer
   credentials, so this attests who *spawned* the server, not who writes its
   stdin. At startup `getppid` names the genuine spawner (the OS just forked
   us) and a later reparenting makes it name the reaper, which fails admission
   closed; but an anonymous pipe's write end can be inherited or passed on, so
   spawner and stdin-writer are not provably the same, and the pid-keyed
   measurement carries the usual microsecond pid-reuse race (on macOS the
   running image is still signature-validated). It raises the bar; it is not
   kernel attestation of the pipe. And attestation identifies a binary, not an
   intention: a trusted-but-compromised harness is still trusted. Exercised
   live by adversarial tests A14/A15/A16.

2. **The ref-counted broker (delivered, ADR-0024).** The first MCP-server
   instance binds the 0600 socket and the lock and becomes the broker; later
   attested instances attach as relays instead of SIGTERMing the owner (the
   old newest-wins `supplant_prior_server` takeover was removed). One shared
   `Session` holds the browser connections and multiplexes every attached
   harness's tool calls. The broker is ref-counted on harness clients (its
   own stdio harness plus relays; browsers deliberately do not count) and
   exits when the last harness detaches -- the shutdown protocol is
   model-checked with loom (shutdown exactly at zero, no attach after the
   terminal decision). Enforced by: the broker process; every attach is
   individually gated by the peer-UID check, `attest_peer`, the HMAC
   handshake, a mandatory role-declaring attach frame, and (for relays) the
   allowlist decision; the socket stays 0600 in the 0700 runtime dir. Its
   DoS posture is explicit: at most 8 harness clients and 16 distinct
   browsers, at most 32 connections mid-handshake, a 10 s handshake+attach
   read timeout (cleared for admitted, legitimately idle connections), and a
   per-relay token-bucket rate limit (burst 128, refill 128/s) that drops a
   flooding relay. Residual: the broker aggregates what were separate blast
   radii (one process fronts all clients), mitigated but not eliminated by
   the caps; and it is a single point of failure whose crash EOFs every
   attached harness (the survivors' restarts elect a new broker, exercised
   by chaos tests C4/C9). On Windows it degrades with the rest of the IPC
   layer to secret-only.

3. **Host-allowlist writers (delivered, ADR-0024/0025).** The trusted-client
   set is persisted at `runtime_dir()/clients.json`: 0600, written atomically
   under the runtime lock, parsed fail-closed (`deny_unknown_fields`,
   version check, size cap). Writers: the CLI (`pair-client`,
   `revoke-client`), and the extension through host-mediated `client_list` /
   `client_revoke` control frames (ADR-0025); the control-panel app arrives in
   a later phase and goes through the same `core` write path). `pair-client`
   replaces a same-named entry (the re-pair path for hash anchors after a
   re-sign) and sets a one-way enrollment latch in `runtime_dir()/revocation.json`;
   `revoke-client` leaves the file in place even when it empties (a
   present-but-empty list means enrolled-and-locked) and bumps the revocation
   epoch so a live broker drops the revoked client and refuses its re-attach
   (ADR-0025). Enforced by: file permissions on the 0700 runtime dir, the
   atomic-write discipline, and the epoch re-read at every admission and
   in-session request. Residual: the allowlist file inherits the same
   same-user-writer exposure as the native-messaging manifest (threat #4's
   class) -- a same-user process that can run our CLI can pair itself. The
   ADR-0024 silent-revert-on-deletion residual is narrowed by the ADR-0025
   enrollment latch: deleting `clients.json` alone now fails closed as
   tampering; only deleting both it and `revocation.json` reverts to the
   ERROR-logged bootstrap, the irreducible same-user residual.

4. **The app as issuer (delivered, ADR-0029).** The Tauri control panel can
   mint pairings and revocations. It is a writer over the allowlist and a
   requester of enclave operations, never a third trust root: nothing
   accepts "the app said so" as authorization. Enforced by: the app going
   through the same `core` write paths and the same presence-gated
   ceremonies as the CLI; the UI carries no security weight. Residual: a
   compromised webview can lie about state it displays, can ask for
   operations, and can decline to request a confirmation at all (denying
   the operation, which fails closed); what it cannot do is forge or answer
   the Enclave user-presence prompt that dangerous operations terminate in.

5. **The Touch ID confirmation surface (delivered, ADR-0031).**
   Confirmations for the crown-jewel tools (`page_eval`, `page_upload`)
   move off the page-reachable DOM to a host-side Secure Enclave
   user-presence gate. This closes the "toast defeatable by the page it
   guards" residual above for those tools. Enforced by: a Secure Enclave
   signing operation on the enrolled key, whose `kSecAccessControlUserPresence`
   ACL forces Touch ID (or the login password) and cannot complete without a
   live user action; the extension verifies the resulting signature against
   its pinned key over a presence-specific domain. Deliberately NOT
   LocalAuthentication's `LAContext.evaluatePolicy`, which was measured to
   return success without fresh user interaction and is therefore no proof of
   presence. The page and the extension can request the prompt but cannot
   satisfy it, and the extension window renders display-only for these kinds
   (no Allow button). Residual: macOS-and-enrolled-only; other platforms and
   an un-enrolled Mac degrade to an off-DOM, fail-closed extension surface
   that is better than the in-page toast but not unspoofable in the same way.
   Per-action Touch ID is a user setting (`touchIdConfirm`, default on);
   opting out returns those two kinds to the window confirmation. Prompt
   fatigue is a real cost and is why only the highest-risk tools route here.

6. **The global kill switch and the audit trail (delivered, ADR-0030).**
   One latch (`killed` in `runtime_dir()/revocation.json`, flipped
   atomically with an epoch bump) halts all bridge activity from any
   trusted surface: the CLI (`kill`/`unkill`), the extension options page
   (host-mediated `kill_engage`/`kill_release` control frames), and the
   desktop app through the same `core` calls. Enforced independently at
   four layers so no single check is load-bearing: every `tools/call` from
   every harness is refused with the stable `BRIDGE_KILLED` code at the
   shared dispatcher; the broker's watcher severs every live browser
   connection within a tick and browser attaches are refused at admission;
   a native host that starts while killed (or with the record unreadable)
   never dials the broker and serves only the control plane, which is what
   keeps the extension's release reachable; and the extension's own gate
   refuses on its SW-only mirror. Release is explicit, never automatic, and
   requires proof of user presence (`kill::release` demands a
   `PresenceAttestation` only `src/packages/core/src/presence/` can construct):
   a Secure Enclave Touch ID tap on an enrolled Mac (ADR-0031); where no
   Enclave key exists, a typed confirmation on a real terminal for the CLI
   (a piped stdin is refused outright) and the options page's confirmation
   dialog for the extension, attested by the native-messaging channel. A
   hardware refusal never falls back to a floor, and failed or unavailable
   auth leaves the switch engaged. Both transitions refuse on an unreadable record (releasing from
   an unknown state would fail open). Alongside it, every security decision --
   admissions, refusals, confirmations shown/allowed/denied, revocations
   per surface, kill transitions, tool calls -- is recorded to stderr and
   to a bounded 0600 `audit.log` (strict-parsed JSON lines, size-capped
   rotation), read by `chromium-bridge audit` and, for the extension's own
   events, mirrored into a bounded ring behind #32 for the read-only
   options panel. The trail is strictly log-after-decide and can never fail
   a decision (drop-on-failure with a visible counter). Residuals: the
   latch shares the revocation record's same-user-writer exposure (a
   same-user process can release the switch, exactly as it can delete the
   trust files -- threat #4's class); the presence floors (used where no
   Enclave key exists) attest intent rather than hardware (a same-user
   process can drive a pty, and the extension floor is a channel-attested
   claim), so they stop silent, scripted, and accidental unkills, not that
   hostile process -- every release is audited with the rung that authorized
   it; engagement has a
   bounded sub-second
   window (one watcher tick) for in-flight work, which the severed sockets
   then drain; and the audit trail is best-effort by design, so a broken
   sink yields visible gaps rather than blocked decisions.

