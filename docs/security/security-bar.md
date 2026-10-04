# The security bar

What this project promises about your browser, and what it does not. The mechanisms are owned by the [threat model](threat-model.md) and the [trust boundaries](trust-boundaries.md); this page says what they are for.

## The bar, in one line

**A program you installed cannot use your browser without you noticing.**

What the bar is not: "nothing can ever touch your browser." You installed this bridge so an agent can drive your browser. The bar is the standard the project holds itself to, not a claim that it is met everywhere today.

One place falls short, on purpose. On an approved origin, reads including masked cookies and storage run without a per-action prompt, and tab titles and URLs are readable with no approval at all ([tool risk matrix](tool-risk-matrix.md)). [Where we deliberately stop](#where-we-deliberately-stop) and [the per-OS table](#where-the-bar-holds-today-per-os) carry it; the [threat model's residual risks](threat-model.md#residual-risks-accepted-tracked) own every accepted gap.

## Why the browser is the asset

A logged-in browser holds live session cookies. Whoever holds them is signed in as you on those sites, past the password and the second factor you already entered. The [threat model's asset list](threat-model.md#assets) puts the sessions first for that reason.

## Do not become the cheapest door

This section is the design argument behind the bar, not a mechanism. Stealing cookies directly already costs an attacker something on every OS. A bridge that any local program can reach for free costs less than that, and an attacker takes the cheapest door.

| Platform | Reading the cookie store directly | A low-bar localhost bridge |
| --- | --- | --- |
| macOS | the cookie key sits in the login Keychain; another app reading it raises a Keychain prompt unless the user already allowed that app | silent |
| Windows | app-bound encryption: a SYSTEM-privileged service releases the key to the browser alone, so a same-user process needs SYSTEM or code injection into the browser | silent |
| Linux | the key sits in the session's secret store, or a fixed fallback; a same-user process in an unlocked session reads it with no prompt | silent |

The left column describes the browser vendor's published protections. It is a claim about other software, not something this project tests.

The conclusion the project draws: a silent bridge lowers the bar the machine already had. Where that bar is already low, as on Linux, the bridge must at least not add a second free door.

## Who attacks, and what answers each

The ranking is this project's judgment of real-world frequency, not a measurement.

| Rank | Attacker | What answers it | Owner |
| --- | --- | --- | --- |
| 1 | prompt injection from a page the agent is reading | the site allowlist; confirmations on an extension-owned window off the page's DOM; masking of what leaves the browser | [primary threats](threat-model.md#primary-threats--mitigations), [boundary 4](trust-boundaries.md#boundary-4-extension---web-page--chrome-api--content-script--dom) |
| 2 | sloppy or compromised software you installed that is not the paired harness (an npm package, another MCP server, an IDE extension), running as your user under a different executable identity | attestation of the harness that spawned the server; the paired-client allowlist, enforced once one client is paired; pairing gated on user presence | [boundary 1](trust-boundaries.md#boundary-1-mcp-client---rust-mcp-server--stdio-json-rpc-20), [new trust boundaries](threat-model.md#rebuild-delta-new-trust-boundaries) |
| 3 | persistent malware already running as you | out of scope by design; the project only refuses to make its job easier | [explicit non-goals](threat-model.md#explicit-non-goals) |

## Where we deliberately stop

- **No per-read prompts on approved sites.** Reads on an allowlisted origin, masked cookies and storage included, run unprompted, because a prompt on nearly every step teaches the user to click through the prompts that guard the dangerous actions. Owners: the [residual risks](threat-model.md#residual-risks-accepted-tracked) and the [tool risk matrix](tool-risk-matrix.md).
- **A click grace window on approved sites.** After one approved submit or link click, the same origin and action kind skip the prompt for a short default window; `page_eval` never does. Owner: the [confirmation defaults in the security policy](../../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe).
- **Same-user re-execution of our own binary is accepted.** Attestation rejects a different program, not the genuine binary started by a same-user attacker. Owner: the [explicit non-goals](threat-model.md#explicit-non-goals).
- **A compromised paired harness keeps its admitted identity.** Attestation identifies a binary, not an intention, so a paired client that turns hostile stays trusted until revoked. Owner: the harness admission entry under [new trust boundaries](threat-model.md#rebuild-delta-new-trust-boundaries).
- **A software presence fallback is labelled where hardware presence is absent.** Without a Secure Enclave key, presence is a software confirmation, which stops silent and scripted acts but not a hostile same-user process. Owner: the kill switch entry under [new trust boundaries](threat-model.md#rebuild-delta-new-trust-boundaries).

## Where the bar holds today, per OS

On every OS, harness admission is enforced only once one client is paired; before that the server serves whatever spawned it.

| OS | Client attestation | User presence | Where the bar holds |
| --- | --- | --- | --- |
| macOS | the spawning harness's code identity, checked against the paired-client allowlist ([boundary 1](trust-boundaries.md#boundary-1-mcp-client---rust-mcp-server--stdio-json-rpc-20)) | hardware presence on an enrolled Mac; the software fallback otherwise | holds: the bridge admits only this binary, run by this user, holding the run secret ([boundary 2](trust-boundaries.md#boundary-2-rust-mcp-server---native-host--bridge-socket-ndjson)) |
| Linux | the spawning harness's code identity, checked against the allowlist ([boundary 1](trust-boundaries.md#boundary-1-mcp-client---rust-mcp-server--stdio-json-rpc-20)) | the software fallback only | holds for the bridge, on the same gates; presence is software-attested |
| Windows | the spawning harness's image hash and Authenticode publisher, checked against the allowlist ([boundary 1](trust-boundaries.md#boundary-1-mcp-client---rust-mcp-server--stdio-json-rpc-20)) | the software fallback only | holds for the bridge: a named pipe only this user can open, mutual image attestation, the run secret ([boundary 2](trust-boundaries.md#boundary-2-rust-mcp-server---native-host--bridge-socket-ndjson)); presence is software-attested |

Windows measures an image by re-opening its path, a window the [threat model's residual risks](threat-model.md#residual-risks-accepted-tracked) own; the [platform table in the security policy](../../.github/SECURITY.md#platform-support) owns the per-mechanism state.

## Against the convenience-first design class

A common design for browser automation puts convenience first. The left column describes that design class by the choices that define it, and what the browser does in response is a claim about other software; it names no product.

| Point | Convenience-first design class | This project |
| --- | --- | --- |
| Who can reach the bridge | a localhost port open to any local process | only this binary, run by this user, holding the run secret ([boundary 2](trust-boundaries.md#boundary-2-rust-mcp-server---native-host--bridge-socket-ndjson)) |
| The debug port and its banner | a debug port open to any local process at all times; the browser's debugging banner shows only while a client is attached, so the user sees nothing between attachments | no debug port; the banner shows only while a debugger-backed tool or the opt-in CDP mode holds an attach (the [tool risk matrix](tool-risk-matrix.md) marks which tools) |
| Default access | full access to every site from the first call | page actions and reads run only on a site the user has approved, except tab titles and URLs, which need no approval; the riskiest tools are off by default under host-owned policy ([tool risk matrix](tool-risk-matrix.md)) |
| Per-action confirmation | none | by default, the confirmation-gated actions confirm on a window the page cannot reach (the [tool risk matrix](tool-risk-matrix.md) lists them), and the two riskiest take hardware presence on an enrolled Mac; relaxing a gate is a presence-gated policy change ([confirmation defaults](../../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe)) |
| Local malware | declared out of scope, and nothing is done about it | out of scope too, but the bridge refuses to be the cheapest door: on macOS and Linux a different same-user program is rejected at the socket, and once one client is paired every harness must match the allowlist, where pairing needs user presence |

## The rule for future changes

This page adds one rule to the review bar: every security-relevant change names the row of this page it moves and the direction, or states that no row moves and why. The [review bar in the security policy](../../.github/SECURITY.md#security-relevant-changes-review-bar) defines which changes count.
