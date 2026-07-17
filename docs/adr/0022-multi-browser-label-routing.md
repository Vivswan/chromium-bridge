# ADR-0022: Multiple browser connections, keyed by a label in the authenticated handshake

- Status: Accepted
- Date: 2026-07-16
- Extends: [ADR-0019](0019-authenticated-ipc.md) and
  [ADR-0020](0020-kernel-attested-peer-identity.md) (per-connection
  authentication is unchanged; this ADR only changes how many authenticated
  connections the server holds and how requests pick one)

## Context

The MCP server used to hold exactly one bridge connection in an
`Option<Conn>`. A new dial-in replaced the old one, whichever browser it came
from. That made a second browser useless: installing the host manifest for
both Chrome and Brave meant the two native hosts fought over the single slot,
and the model could never say which browser a tool call was meant for.

The wave-1 handshake already carried an optional `label` field in the
client's response frame, reserved for exactly this phase.

## Decision

1. **A label-keyed registry.** `Session` holds `HashMap<label, Conn>`. Each
   browser's native host dials in with `--label <name>` (the Unix installer
   bakes the label into a per-browser wrapper, `run-host-<browser>.sh`). A
   dial-in with a label already in the map replaces that entry, which is the
   same reconnect semantics the single slot had, now scoped to one browser.
   Different labels coexist. A host that sends no label lands in the
   `default` slot, so a single-browser install works with zero configuration
   and old wrappers keep working. On Windows, manifests point straight at
   the executable (they cannot carry arguments and there is no wrapper), so
   every Windows browser shares the `default` slot and a new dial-in
   replaces the old one there, exactly the pre-phase-3 behavior.

2. **The label is authenticated, then validated.** When a label is present,
   the handshake MAC covers the nonce and the label together
   (`HMAC(secret, nonce || 0x00 || label)`); without a label it covers the
   nonce alone, and the two forms cannot collide because the fixed-width hex
   nonce never contains a NUL. The label therefore cannot be altered
   separately from the proof of secret knowledge. The server trusts the
   label only after the MAC verifies, and then only if it passes a strict
   shape check (1-32 chars of `[A-Za-z0-9._-]`, starting alphanumeric).
   Anything else fails the whole handshake. The validation exists because
   the label ends up in registry keys, log lines, and tool output.

3. **Routing never guesses.** Every bridge-backed tool takes an optional
   `browser` argument. An explicit label routes there or fails with
   `BROWSER_NOT_FOUND` (naming what is connected). No argument routes to the
   sole connection when exactly one browser is attached, and fails with
   `BROWSER_AMBIGUOUS` when several are. A non-string `browser` value fails
   with `INVALID_ARGUMENT` instead of being ignored. The refusal is
   deliberate: acting in the wrong logged-in browser is worse than making
   the caller name one.

4. **`list_browsers` enumerates.** A server-answered tool returns each live
   label with its open-tab count. Tab counts come from a routed `tab_list`
   per browser with a 5-second enumeration timeout and no connect-wait, so
   one wedged browser delays discovery by seconds, not by the interactive
   120-second call timeout.

5. **Responses stay on their own connection.** Request ids are process-global
   and each pending request records the connection generation it was sent
   over. A reader delivers a response only when that generation is its own;
   a connection that answers another browser's id is dropped as a protocol
   violator. Without this, a hostile extension in one browser could satisfy
   or cancel calls addressed to another.

## What is NOT changed

Every dial-in is still individually gated by the same per-connection chain
as before: on Linux and macOS that is the full ADR-0019/0020 stack (kernel
peer-UID check, executable attestation, then the HMAC challenge-response);
on Windows it remains the HMAC over loopback only, the documented downgrade
from the threat model. The registry holds N connections that each passed
their platform's chain. No check was weakened or amortized across
connections.

## Residual risks, named honestly

- **The label says which browser the host claims to front.** On Linux and
  macOS the handshake proves the peer is this same binary, run by this same
  user, holding the per-run secret, and that the label arrived unmodified
  from that peer (on Windows only the secret-and-label binding holds). It
  does not prove Chrome (rather than Brave, or a script) launched the
  process. A same-user process that runs this binary with a forged `--label`
  can occupy or replace a label. This is the pre-existing same-user
  substitution residual from the threat model, not new exposure: before this
  change the same process could replace the single connection outright. The
  enrollment ceremony (task #13) and the parked per-action presence tier
  (task #12) are the planned mitigations.
- **Windows browsers cannot be told apart.** Native-messaging manifests on
  Windows launch the executable directly with no arguments, so every
  Windows browser lands in the `default` slot and the last one to connect
  wins it. Labeled multi-browser operation is Unix-only until the Windows
  installer gains a per-browser launch mechanism.
- **The extension's disable toggle does not cover `list_browsers`.** The
  tool is answered by the MCP server from its own registry and never reaches
  the extension, so the per-tool toggle in the options page has no effect on
  it. What it exposes is modest: tab counts are already visible via
  `tab_list`, and the labels come from the local install's own
  configuration.
- **Enumeration can be stale by a few seconds.** A browser that disconnects
  mid-enumeration shows up with `tabCount: null` and an error string rather
  than disappearing instantly.
