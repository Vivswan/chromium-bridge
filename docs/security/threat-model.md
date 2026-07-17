# Threat model

What browser-bridge protects, from whom, and what it explicitly does not defend
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
   `browser-bridge pair` mints a P-256 key inside the Secure Enclave whose
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
- Masking is heuristic — it can miss a novel secret format or over-mask benign
  data.
- `page_snapshot_precise` briefly attaches the debugger (infobar flash).
- **CDP mode** (`cdpMode`, opt-in, off by default — see
  [ADR-0017](../adr/0017-cdp-mode-all-ops.md)) routes all page ops through
  `chrome.debugger`. When enabled it **bypasses page CSP** (letting `page_eval`
  run on strict-CSP sites) and holds a **persistent debugger attach** for the
  tab (the "Started debugging this browser" banner stays up). The allowlist,
  per-action confirmation toasts, and masking are unchanged; the residual risk
  is the wider surface and the removed CSP defense-in-depth layer, accepted as
  the explicit price of the opt-in.
