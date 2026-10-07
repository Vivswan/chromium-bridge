# Security

What the bridge promises about your browser, what gates each promise, and where the promise stops. The mechanism detail and every accepted residual are the [trust boundaries ledger](security/trust-boundaries.md); what each tool can reach is the [tool risk matrix](security/tool-risk-matrix.md).

## The bar, in one line

**A program you installed cannot use your browser without you noticing.**

What the bar is not: "nothing can ever touch your browser". You installed this bridge so an agent can drive your browser. The bar is the standard the project holds itself to, not a claim that it is met everywhere today.

One place falls short, on purpose. On an approved origin, reads including masked cookies and storage run without a per-action prompt, and tab titles and URLs are readable with no approval at all. [Where we deliberately stop](#where-we-deliberately-stop) names the gaps a reader meets first; the [ledger](security/trust-boundaries.md) carries every residual.

## What is at stake, and who is trusted

The assets:

- **Your authenticated browser sessions:** cookies including httpOnly, and web storage tokens. Whoever holds them acts as you on the sites you are logged into, past the password and the second factor you already entered.
- **Page content** you can see.
- **The ability to act as you:** click, fill, navigate, run code.
- **The wire protocols:** a corrupted stream can hang or crash the bridge.

| Actor | Trusted? | Notes |
|-------|----------|-------|
| You | yes | own the machine and the browser profile |
| The MCP client (Claude Code, Codex, ...) | yes, by design, once paired | you configured it; it drives the tools |
| The Rust binary (MCP server and native host) | yes | the thing being secured |
| The MV3 extension | yes | runs alongside untrusted page code |
| **The web page** | **no** | may be attacker-controlled; may carry prompt injection |
| Other local users and processes | **no** | may try to reach the bridge socket |
| The network | out of scope | no remote surface; everything is localhost or stdio |

Three assumptions the model rests on:

- **A single-user machine.** No hostile local user shares your UID. Other users and other same-user binaries are rejected; a same-user attacker running this very binary is not (the [non-goals](#explicit-non-goals)).
- **The MCP client is trusted.** A malicious client you installed yourself already has whatever you granted it. The tools exist to be driven by that client.
- **Chrome's sandbox and extension model hold.** The bridge relies on MV3 isolation between content scripts and page JS, and on Chrome enforcing host permissions.

## Do not become the cheapest door

Stealing cookies directly already costs an attacker something on every OS. A bridge that any local program can reach for free costs less than that, and an attacker takes the cheapest door.

| Platform | Reading the cookie store directly | A low-bar localhost bridge |
| --- | --- | --- |
| macOS | the cookie key sits in the login Keychain; another app reading it raises a Keychain prompt unless the user already allowed that app | silent |
| Windows | app-bound encryption: a SYSTEM-privileged service releases the key to the browser alone, so a same-user process needs SYSTEM or code injection into the browser | silent |
| Linux | the key sits in the session's secret store, or a fixed fallback; a same-user process in an unlocked session reads it with no prompt | silent |

The left column describes the browser vendors' published protections. It is a claim about other software, not something this project tests.

The conclusion: a silent bridge lowers the bar the machine already had. Where that bar is already low, as on Linux, the bridge must at least not add a second free door.

## Who attacks, and what answers each

Ranked by this project's judgment of real-world frequency, not a measurement: a page the agent is reading comes first, software you installed that is not the paired harness second, and persistent malware already running as you third. The third is out of scope by design; the bridge only refuses to make its job easier.

| Threat | What answers it | Detail |
| --- | --- | --- |
| A page influences the agent into acting on it without approval | page-level tools run only on an origin you approved; a new origin prompts you and requests the host permission; the page cannot add itself | [boundary 4](security/trust-boundaries.md#boundary-4-extension---web-page--chrome-api--content-script--dom) |
| Prompt injection: page content tricks the model into a dangerous tool call | page content is data to the agent, not commands; the dangerous actions confirm on a window the page cannot reach, and `page_eval` confirms every call showing the full code | [what you confirm](#what-you-confirm-and-what-counts-as-presence) |
| Credential or token exfiltration | cookies and storage are read-only, allowlist-scoped, and masked before they leave the extension; `page_text` masks passwords and card-like numbers | [tool risk matrix](security/tool-risk-matrix.md) |
| Another local process hijacks the bridge | every connection passes a same-user check, mutual executable attestation (the [platform table](../.github/SECURITY.md#platform-support) owns what each OS measures), and an HMAC challenge-response whose per-run secret never crosses the wire | [boundary 2](security/trust-boundaries.md#boundary-2-rust-mcp-server---native-host--bridge-socket-ndjson) |
| A malformed or oversized message crashes or corrupts the bridge | length-checked framing, a panic hook that keeps panics off the protocol stream, parse errors surfaced rather than fatal, fuzzed parsers | [boundary 3](security/trust-boundaries.md#boundary-3-chrome---native-host--native-messaging-framing) |
| Silent pairing: a process able to write an MCP client config stands up the whole chain unnoticed | two ceremonies you run: `pair` mints the host key behind a confirmation typed on a terminal, and the browser enrolls a WebAuthn credential; every later grant needs a presence proof | [boundary 3](security/trust-boundaries.md#boundary-3-chrome---native-host--native-messaging-framing) |
| A revoked client or host keeps acting because revocation does not reach the enforcement point | one trust record, re-read with its epoch at every enforcement point. A revoked client's relay is dropped and its next request and re-attach refused; a revoked host key is pushed to the extension, which marks its pin compromised and closes its own request gate until the user re-pairs | [boundary 1](security/trust-boundaries.md#boundary-1-mcp-client---rust-mcp-server--stdio-json-rpc-20) |

## The four hops, and what gates each

```text
MCP client --(1)-> Rust MCP server --(2)-> native host --(3)-> extension --(4)-> web page
   (trusted)         (trusted)           (trusted)         (trusted)        (UNTRUSTED)
```

| Hop | Who may cross it | What gates it |
| --- | --- | --- |
| 1. MCP client to MCP server, over stdio | the harness that spawned the server, once paired | the server attests the spawning process and checks it against the paired clients; unmatched, unmeasurable, or an unreadable record all fail closed |
| 2. MCP server to native host, over the bridge socket | this binary, run by this user, holding the run secret | no listening port; a kernel peer-UID check; mutual executable attestation; an HMAC challenge-response; a role-declaring attach frame |
| 3. Browser to native host, over native messaging | our extension alone, by the manifest; the host the user paired, by its pinned key | the manifest pins the extension id; the extension pins the host's P-256 key; capability-granting acts need a presence proof the host verifies: a WebAuthn assertion, or the window where the rule admits no credential |
| 4. Extension to web page | nothing the page asks for | the origin allowlist; confirmations on a window off the page's DOM; masking at egress; trust state in storage the page cannot read |

One record ties the hops together: `trust.json` in the runtime directory holds the paired clients, the kill latch, and the browsers' enrolled credentials, and every enforcement point reads it fail-closed. [The trust record](security/trust-boundaries.md#the-trust-record) in the ledger owns it.

## What you confirm, and what counts as presence

**The confirmation window.** Submit and link clicks, `page_press`, `page_select`, `page_eval`, `tab_close`, and `page_upload` confirm on an extension-owned window in its own process, which the page cannot read, focus, overlay, auto-click, or auto-dismiss. A timeout, a closed window, or a missing provider all deny.

- **Every `page_eval` and `page_upload` call reconfirms.** The [fail-safe defaults](../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe) own what each confirmation shows and how long the grace window lasts.
- **One approved click covers repeats** within the window's [per-tab key](../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe). `page_eval` is never in it.
- **Low-risk tools run unprompted** on an approved origin: navigation, `page_text`, `tab_list`, masked cookie and storage reads.

**Presence.** Removing capability is friction-free: `kill`, `revoke`, and `uninstall` need no proof, because fail-closed is the safe state. Granting or restoring capability demands one proof of a human present, consumed by exactly one act:

| Surface | The proof | What it stops |
| --- | --- | --- |
| the extension, on a browser with an enrolled credential | a WebAuthn tap on the browser's authenticator (a platform biometric, a PIN, a security key), verified by the host against the credential enrolled under this browser | any answer not signed by that enrolled credential; what the gesture itself proves is the authenticator's business, the [ledger's hardware residual](security/trust-boundaries.md#boundary-3-chrome---native-host--native-messaging-framing) |
| the extension, where the rule admits no credential: the browser has none for its own acts, the machine has none for enrolling | a click on the confirmation window, labelled a software confirmation | silent and scripted acts, not a hostile same-user process |
| the CLI (`pair`, `pair-client`, `unkill`, `policy set`) | a phrase typed on a real terminal; a piped stdin is refused before any prompt | scripted, piped, and accidental grants, not a same-user process that allocates a pty |

An enrolled browser is never demoted to the window. The acts behind the gate, and who answers each:

- releasing the kill switch: the browser's own credential;
- enrolling another browser: any enrolled credential;
- `page_eval` and `page_upload` where the policy's `presenceConfirm` is on: the browser's own credential, the request naming the op and the page's origin;
- minting the host key: the CLI's terminal;
- pairing a client, and relaxing the policy (a `policy set`, a rollback that relaxes, or the first baseline): the browser's own credential from the options page, the window where that browser enrolled none, or the CLI's terminal. A tightening over an existing baseline needs no proof on either surface.

**Two policy lanes.** A policy change that grants capability is signed by the host key behind the presence proof above, from the options page or the CLI; a change that only restricts travels unsigned and free from either surface, because a forged restriction can only remove capability. The [CLI page](cli.md#host-owned-policy-policy) owns the commands; the [defaults table](../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe) owns what relaxing each gate costs you.

## Where we deliberately stop

Each gap below is accepted on purpose. The ledger entry it links to states what bounds it.

- **No per-read prompts on approved sites.** A prompt on nearly every step teaches you to click through the prompts that guard the dangerous actions. Owner: [read exfiltration](security/trust-boundaries.md#boundary-4-extension---web-page--chrome-api--content-script--dom).
- **A click grace window on approved sites.** The cost of the window [above](#what-you-confirm-and-what-counts-as-presence): unrelated same-origin code can ride one approval for its duration. Owner: [the defaults table](../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe).
- **Same-user re-execution of our own binary is accepted.** Attestation rejects a different program, not the genuine binary started by a same-user attacker. Owner: [boundary 2](security/trust-boundaries.md#boundary-2-rust-mcp-server---native-host--bridge-socket-ndjson).
- **A compromised paired harness keeps its admitted identity.** Attestation identifies a binary, not an intention, so a paired client that turns hostile stays trusted until revoked. Owner: [boundary 1](security/trust-boundaries.md#boundary-1-mcp-client---rust-mcp-server--stdio-json-rpc-20).
- **The software floors are labelled, not hidden.** The window for an unenrolled browser and the terminal for the CLI attest intent on a trusted surface, not hardware, and every audited grant names the path that authorized it, `pair`'s included. Owner: [boundary 3](security/trust-boundaries.md#boundary-3-chrome---native-host--native-messaging-framing).
- **A credential deleted from the authenticator stays enrolled.** The host never learns that an authenticator or an OS passkey store dropped a credential, so that browser keeps refusing the window and loses its presence-gated acts until `revoke <browser>` forgets the enrollment. Owner: [boundary 3](security/trust-boundaries.md#boundary-3-chrome---native-host--native-messaging-framing).

## Where the bar holds today, per OS

On every OS, harness admission is enforced only once one client is paired; before that the server serves whatever spawned it and logs that posture at ERROR level on every start.

| OS | Client attestation | User presence | Policy grant lane | Where the bar holds |
| --- | --- | --- | --- | --- |
| macOS | the spawning harness's code identity, checked against the paired clients | the browser's authenticator on an enrolled browser; the window otherwise; the terminal for the CLI | `pair` mints the host key into the Keychain, so a grant from either surface signs here | the bridge admits only this binary, run by this user, holding the run secret |
| Linux | the spawning harness's image hash, checked against the paired clients | the same ladder | `pair` mints the key into the Secret Service, or a 0600 file with `--file-store` | holds on the same gates |
| Windows | the spawning harness's image hash and Authenticode publisher, checked against the paired clients; pairing is the [CLI page's](cli.md#trusted-clients-pair-client--revoke-client--list-clients) | the same ladder | `pair` mints the key into the Credential Manager | a named pipe only this user can open, mutual image attestation, the run secret |

The grant lane needs a host key, and `pair` mints one on every OS, so a signed policy baseline is available on all three. The Windows residuals behind that row are in [boundary 2](security/trust-boundaries.md#boundary-2-rust-mcp-server---native-host--bridge-socket-ndjson); the [platform table in the security policy](../.github/SECURITY.md#platform-support) owns the per-mechanism state.

## Against the convenience-first design class

A common design for browser automation puts convenience first. The left column describes that design class by the choices that define it; what the browser does in response is a claim about other software, and the column names no product.

| Point | Convenience-first design class | This project |
| --- | --- | --- |
| Who can reach the bridge | a localhost port open to any local process | only this binary, run by this user, holding the run secret |
| The debug port and its banner | a debug port open to any local process at all times; the browser's debugging banner shows only while a client is attached | no debug port; the banner shows only while a debugger-backed tool or the opt-in CDP mode holds an attach ([the matrix](security/tool-risk-matrix.md) marks which tools) |
| Default access | full access to every site from the first call | page actions and reads run only on a site you approved, except tab titles and URLs; the riskiest tools are off by default under host-owned policy |
| Per-action confirmation | none | the confirmation-gated actions confirm on a window the page cannot reach; `page_eval` and `page_upload` reconfirm every call; relaxing a gate is a signed, presence-gated policy change |
| Local malware | declared out of scope, and nothing is done about it | out of scope too, but the bridge refuses to be the cheapest door: a different same-user program is rejected at the socket, and once one client is paired every harness must match the allowlist |

## Explicit non-goals

- A compromised OS account, or a same-user attacker who runs this very binary: byte-identical to the legitimate host, so neither a hash nor a code signature can tell them apart.
- A malicious MCP client you configured yourself.
- Multi-user or shared-machine isolation.
- Remote attackers: there is no remote attack surface.

## Changing something, or reporting something

A change that moves any of this is security-relevant and goes through the [review bar](../.github/SECURITY.md#security-relevant-changes-review-bar), which names the row of this page it moves. A suspected breach goes to the [reporting channel](security/incident-response.md#reporting-channel), never a public issue.
