# Threat model

What chromium-bridge protects, from whom, and what it explicitly does not defend
against. Pairs with [trust-boundaries.md](trust-boundaries.md) and the
[tool risk matrix](tool-risk-matrix.md).

## Assets

- The user's **authenticated browser sessions** (cookies incl. httpOnly, web
  storage tokens) — i.e. the ability to act *as the user* on sites they're
  logged into.
- **Page content** the user can see.
- The ability to **execute actions** (click/fill/navigate/eval) as the user.
- Integrity of the **wire protocols** (a corrupted stream can hang or crash the
  bridge).

## Actors

| Actor | Trusted? | Notes |
|-------|----------|-------|
| The user | yes | owns the machine and Chrome profile |
| The MCP client (Claude Code, Codex, …) | **yes, by design** | the user configured it; it drives the tools |
| The Rust binary (MCP server + native host) | yes | the thing we're securing |
| The MV3 extension | yes | but runs alongside untrusted page code |
| **The web page** | **NO** | may be attacker-controlled; may host prompt-injection |
| Other local users / processes | **NO** | may try to connect to the bridge socket |
| The network | out of scope | no remote surface — everything is localhost/stdio |

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
  installed is out of scope — it already has whatever the user granted it. The
  tools exist to be driven by that client.
- **Chrome's sandbox and extension model hold.** We rely on MV3 isolation
  between content scripts and page JS, and on Chrome enforcing host permissions.

## Primary threats & mitigations

1. **A web page influences the agent into acting on it without approval.**
   → Page-level ops require an **allowlisted origin**; a new origin triggers an
   explicit user prompt + `chrome.permissions.request`. The page can't add
   itself to the allowlist.

2. **Prompt injection: page content tricks the model into a dangerous tool
   call** (e.g. "run this eval", "read cookies and post them").
   → Observed page content is *data*, not commands, to the agent. Independently,
   high-risk actions (submit/link click, `page_eval`, tab close) require an
   **in-page user confirmation** the page cannot forge or auto-dismiss, and
   `page_eval` confirms **every call** showing the full code. This per-action
   prompt covers the high-risk ops only. Low-risk ops (navigate, `page_text`,
   `tab_list`, and masked cookie or storage reads) run with no per-action
   prompt, so a driver that already reaches the extension can navigate, read
   masked page content, and enumerate tabs without the user seeing each step.
   The confirmation is a gate on the dangerous actions, not a promise that
   nothing happens silently.

3. **Credential/token exfiltration.**
   → Cookies/storage are **read-only** (no set), **allowlist-scoped**, and
   **masked** (JWT/hex/long-digit/token-like) before leaving the extension.
   `storage_get` masking is not user-toggleable. `page_text` masks passwords and
   card-like numbers.

4. **Another local process hijacks the bridge** to issue tool calls or read
   responses.
   → On Unix there is **no listening port**: the bridge is a 0600 Unix-domain
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
   `src/ipc.rs`). So on Windows the protection rests on the secret staying
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
   → Native-messaging framing is length-checked (64 MB inbound clamp, 1 MB
   outbound cap); a `panic = "abort"` profile + stderr panic hook keep panics
   off the protocol stream; parse errors are surfaced, not fatal. (Protocol
   fuzzing is a planned hardening — see the roadmap.)

6. **Silent pairing: a malicious `claude mcp add` (or any process able to
   write an MCP client config) stands up the whole chain without the user
   noticing.**
   → The **enrollment ceremony**
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
   post-enrollment same-user substitution (see the residual below), and the
   host side ships first: until the extension-side pin lands, the host
   answers challenges but nothing yet enforces them.

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
  ([ADR-0021](../adr/0021-enrollment-ceremony.md)) narrows this: once the
  extension-side pin lands, a substituted host cannot present a valid
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
  and action kind skip the toast for 60s (see
  [ADR-0006](../adr/0006-toast-confirmation-for-high-risk.md)). `page_eval` is not
  in this window; it reconfirms on every call.
- **The in-page confirmation is defeatable by the page it guards.** The
  toast that asks the user to approve a high-risk action (a submit click,
  `page_press`, `page_select`, `page_upload`, and the rest) is drawn in the
  page's own DOM through a content script, or in the page's MAIN world under
  CDP mode. A page that has already prompt-injected the model can watch for
  that toast with a `MutationObserver` and click Allow itself, or overwrite
  the globals the toast is built from, so consent is bypassed exactly on the
  hostile origin where it matters most. The gate holds against an ordinary
  page and an honest user; it does not hold against a page that owns the DOM
  the toast lives in. Closing it needs a confirmation surface the page cannot
  reach, such as a browser-action popup or `chrome.notifications`. This is the
  same shape as the manifest-substitution residual: the boundary is real but
  not enforced against an attacker who already controls that layer.
- **`page_upload` can attach any local file the caller names.** When the tool
  is enabled (it is off by default), it attaches whatever absolute path the
  call supplies to a file input, so a model induced to call it on a page can
  hand that page a file the user never picked, such as an SSH key or a private
  document. Three gates stand in front of it: the opt-in, the origin
  allowlist, and a per-call confirmation that shows the exact path. The
  confirmation, though, is the page-defeatable one above, so on a hostile
  allowlisted origin the last check can be auto-clicked, and the path itself
  is not constrained to a picked file or a safe directory. Tracked for
  hardening (a page-unreachable confirmation plus an OS file picker, so the
  model names no path) before file upload is recommended for general use.
- `page_snapshot_precise` briefly attaches the debugger (infobar flash).
- **CDP mode** (`cdpMode`, opt-in, off by default — see
  [ADR-0017](../adr/0017-cdp-mode-all-ops.md)) routes all page ops through
  `chrome.debugger`. When enabled it **bypasses page CSP** (letting `page_eval`
  run on strict-CSP sites) and holds a **persistent debugger attach** for the
  tab (the "Started debugging this browser" banner stays up). The allowlist,
  per-action confirmation toasts, and masking are unchanged; the residual risk
  is the wider surface and the removed CSP defense-in-depth layer, accepted as
  the explicit price of the opt-in.

## Rebuild delta: new trust boundaries (stubs)

The workspace/Tauri rebuild
([ADR-0023](../adr/0023-workspace-monorepo-tauri-app.md)) introduces five
boundaries that do not exist in the model above. These entries are stubs:
each names the boundary, who enforces it, and the residual we already know
about. The full treatment (mechanism, failure modes, adversarial tests)
lands in the ADR of the phase that builds the component, and this section
gets folded into the main model then. Until a component ships with its
mechanism, it must be treated as unenforced.

1. **Harness -> MCP server stdio admission.** Today anything that spawns the
   binary in MCP mode owns its stdin and is trusted unconditionally (the
   "MCP client is trusted" assumption). The rebuild adds admission control:
   the server must identify the client driving it before serving tool
   calls, keyed against a host-side client allowlist. Enforced by: the MCP
   server at startup. The mechanism is an open design problem for the
   pairing ADR: stdio is an anonymous pipe, so the socket layer's kernel
   peer credentials do not exist here (a pipe endpoint can be inherited or
   relayed, and a parent PID proves who spawned us, not who is writing to
   us). If no unforgeable stdio-level check exists on a platform, admission
   must move to a channel that has one, or the gap must be recorded here as
   a residual, not papered over. Residual (already known): attestation of
   any kind identifies a binary, not an intention; a trusted-but-compromised
   harness is still trusted, and the self-asserted client name is a label,
   never the authorization key.

2. **The ref-counted broker.** Concurrent multi-client support replaces
   newest-wins takeover with a broker that owns the browser-facing socket
   and multiplexes attested clients, exiting when the last one detaches.
   This is a new persistent same-user surface that did not exist when the
   server's lifetime equaled one harness's lifetime. Enforced by: the broker
   process itself; every attach is individually attested, and the socket
   stays 0600 in the 0700 runtime dir. Residual: the broker aggregates what
   were separate blast radii (one process now fronts all clients), and it
   needs its own DoS posture (connection caps, timeouts) because it outlives
   any one client. On Windows it degrades with the rest of the IPC layer to
   secret-only.

3. **Host-allowlist writers.** The set of trusted client binaries becomes a
   persisted allowlist, which means something writes it. Writers: the CLI
   (`pair`/`revoke`) and the control-panel app. Enforced by: file
   permissions on the 0700 runtime/config dir, atomic writes under the
   runtime mutex, and pairing ceremonies for additions. Residual: the
   allowlist file inherits the same same-user-writer exposure as the
   native-messaging manifest (threat #4's class); a same-user process that
   can win a pairing ceremony can add itself. More writers also means more
   code with write capability to audit.

4. **The app as issuer.** The Tauri control panel can mint pairings and
   revocations. It is a writer over the allowlist and a requester of
   enclave operations, never a third trust root: nothing accepts "the app
   said so" as authorization. Enforced by: the app going through the same
   `core` write paths and the same presence-gated ceremonies as the CLI;
   the UI carries no security weight. Residual: a compromised webview can
   lie about state it displays, can ask for operations, and can decline to
   request a confirmation at all (denying the operation, which fails
   closed); what it cannot do is forge or answer the Enclave
   user-presence prompt that dangerous operations terminate in.

5. **The Touch ID confirmation surface.** Confirmations for the
   crown-jewel tools (`page_eval`, `page_upload`) move off the
   page-reachable DOM to a host-side Secure Enclave user-presence gate.
   This closes the "toast defeatable by the page it guards" residual above
   for those tools. Enforced by: LocalAuthentication / `SecAccessControl`
   user-presence on the enrolled Enclave key; the page and the extension
   can request but cannot satisfy it. Residual: macOS-only; other platforms
   degrade to an off-DOM, fail-closed extension surface that is better than
   the in-page toast but not unspoofable in the same way. Prompt fatigue is
   a real cost and is why only the highest-risk tools route here.

