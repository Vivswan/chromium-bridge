# ADR-0030: Global kill switch and audit surfaces

- Status: Accepted
- Date: 2026-07-17
- Extends: [ADR-0025](0025-any-side-revocation-epoch.md) (the revocation
  record and its epoch; the kill latch lives in that record and rides its
  machinery), [ADR-0024](0024-multi-client-attested-pairing-and-broker.md)
  (the broker whose connections a kill severs),
  [ADR-0027](0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md) (the #32
  SW-only trusted storage that holds the extension's mirror, and the
  confirmation surface whose decisions the audit trail records)

## Context

Phase 5 gave the bridge fine-grained revocation: untrust one client, delete
one key. What it did not give the user is a brake. If something looks wrong -
a tool call they do not recognize, a confirmation prompt they did not expect,
a harness gone haywire - the honest advice was "revoke each client, then
close Chrome", which is several steps at the exact moment the user wants
zero. The rebuild plan therefore called for one switch that stops everything,
reachable from every surface the user actually has in front of them: the
extension's options page, the CLI, and (through the same library call) the
future desktop app.

Separately, the bridge made security decisions - admissions, refusals,
confirmations, revocations - and kept no durable record of any of them. The
only trace was stderr, which dies with the process that wrote it. A user who
wonders "what did this thing do while I was away?" had nothing to read.

This record covers both: the kill switch, and the audit trail that (among
other things) records every use of it.

## Decision

### 1. The kill latch lives in the revocation record

`revocation.json` gains two fields: `killed` (the latch) and `kill_epoch`
(the epoch of the last transition, either direction). A transition is one
atomic write that flips the latch, stamps the marker, and bumps the global
epoch, performed under the runtime lock by `kill::engage` / `kill::release`
(`src/packages/core/src/kill.rs`, over `revocation::set_killed_locked`).

Placing the latch inside the record the epoch machinery already guards buys
two properties for free. First, every enforcement point that already reads
this file fail-closed now reads the kill state with the same posture: a
corrupt record was already a refusal everywhere. Second, the latch and its
epoch bump are one write, so no reader can observe one without the other -
which is what keeps the broker's per-request fast path (skip re-reading while
the epoch is unchanged) sound in the face of a kill.

Unlike the epoch, which ADR-0025 is careful to keep a change notice rather
than an authority, the latch IS the authority for the kill state. There is no
second file to re-read; `killed: true` is the decision. The same-user writer
who can edit the file can therefore clear it, which is named in the residuals
rather than papered over.

### 2. What a kill does

Engaging the switch halts all bridge activity, at four distinct layers, so no
single bypassed check re-opens the browser:

- **Tool dispatch.** Every `tools/call`, from every harness (the broker's own
  stdio harness and every attached relay share one dispatcher,
  `mcp_server::handle`), passes `kill::check` before any routing or bridge
  traffic. While killed the call is answered with the stable `BRIDGE_KILLED`
  taxonomy code (`ERROR_SPECS` in error.rs; `CallError::Killed`). The harness
  connection deliberately stays up: a typed, deliverable refusal tells the
  user's agent what happened, where a dropped connection would just look like
  a crash and invite blind respawning.
- **The browser leg is severed.** The broker's watcher (the ADR-0025
  once-a-second sweep) also reads the latch; while it is set, every live
  browser connection is shut down (`Session::shutdown_all_browsers`), which
  drains in-flight calls into `CONNECTION_LOST` rather than letting them ride
  out their timeout. New browser attaches are refused at admission. Between
  the two, no path from any harness to any browser exists while killed, even
  if a dispatch-layer bug were found.
- **The native host stops bridging.** A host that starts while the latch is
  set (or unreadable) never dials the broker at all. It runs a control-plane
  mode instead: host-handled control frames keep working, bridge frames are
  dropped, and the process exits into a clean respawn when it observes the
  release. This mode is what keeps the extension's unkill reachable - the
  release frame travels through this very process - so the switch cannot
  strand the user with no way back short of the CLI.
- **The extension refuses locally.** The SW-only mirror (decision 4) closes
  the extension's own request gate while killed, ahead of the enrollment
  checks. Defense in depth; the host side is authoritative.

### 3. Unkill is explicit, user-present, from a trusted surface, never automatic

Nothing clears the latch on its own: no timeout, no restart, no reconnect, no
"grace period". The release paths are `chromium-bridge unkill`, the options
page's toggle, and the future app through `kill::release`. All of them are
the same library call, the same atomic write, the same audit record.

Release is also the one act in the bridge that RESTORES capability, so it
carries a gate engagement does not: proof of user presence. The user's
directive is that releasing require Touch ID; the hardware plumbing
(LocalAuthentication) arrives with Phase 8, and until it does, per-surface
interactive floors hold the line. `src/packages/core/src/presence.rs` is the seam
the hardware plugs into. `kill::release` demands a `PresenceAttestation`, a
type only that module can construct, so no code path can clear the latch with
presence unchecked. The ladder inside `require_presence` tries hardware
first and uses the surface's interactive floor ONLY when hardware is
unavailable; a hardware check that ran and REFUSED never falls back, so an
attacker who can make Touch ID fail cannot demote the gate to a softer
prompt. Failed or unavailable auth leaves the bridge exactly as killed as it
was.

The pre-Phase-8 floors, one honest option per surface:

- The CLI floor is an explicit typed confirmation on a real terminal.
  `unkill` refuses a non-terminal stdin outright, so
  `echo release | chromium-bridge unkill` from a script or another program
  cannot silently reopen the bridge, and then requires the exact phrase.
- The extension floor is the options page's confirmation dialog. The native
  host cannot raise a prompt of its own (its stdin/stdout are the
  native-messaging protocol), so it accepts the surface's confirmation,
  attested by the channel that delivered the `kill_release` frame:
  `allowed_origins` pins which extension can open the host, and the #32
  sender gate pins which of its contexts can make the service worker send
  the frame.

Engagement stays zero-friction on every surface, deliberately: the brake
must be one action, and a spurious kill costs one authenticated release. The
asymmetry is the design.

Every release attempt is audited with the rung that decided it: `ok` with
`auth=touch_id` / `auth=cli_confirm` / `auth=extension_confirm` when the
latch cleared, `refused` with the presence error when the gate stopped it,
and `error` with the auth rung plus the write error when presence passed but
the record refused the write (a corrupt record; the bridge stays killed). A
floor-authorized release is therefore always distinguishable from a
hardware-authorized one, and no unkill attempt - silent, declined, or
half-failed - is invisible to the trail.

Both transitions refuse on an unreadable record rather than rebuilding it
(the ADR-0025 posture: silently replacing a corrupt security record would
mask tampering). For `engage` this is harmless honesty - a corrupt record
already fails every enforcement read closed, so the kill's goal holds either
way, and the CLI says so. For `release` it is load-bearing: an unkill from a
state you cannot read would be a fail-open. The recovery path for a corrupt
record is documented in docs/operations.md and it is deliberately manual.

The extension deserves a note, because `kill_release` is the one control
frame that RESTORES capability where every other admin frame only reduces it
(ADR-0025's client_revoke, enclave_revoke). It is accepted because the
options page is a trusted surface on par with the CLI, and the gauntlet in
front of it is real: the runtime-message router accepts `set_kill` only from
the extension's own pages (#32 sender gate, so no content script and no page
can send it), the SW only relays a control frame, and the host performs the
transition and answers with the resulting state. A web page has no path to
any of those steps; the vitest suite pins it.

### 4. The extension mirror

The extension keeps a mirror of the kill state in the #32 SW-only trusted
storage: `{state: alive | killed | unknown, at}`. It is written from exactly
one source, the host's `kill_status_result` frames - the reply to a
status/engage/release request, or an unsolicited push. The gate refuses on
`killed`, on `unknown` (the host said it cannot read its own state), and on a
malformed stored value (tampering evidence must not read as "absent"); an
ABSENT mirror allows, because a fresh install has never heard from a host and
bricking it locally would add nothing the host does not already enforce.

Freshness is push-and-pull. The host pushes on observed transitions and at
startup when the news is bad (killed, or unreadable). The extension pulls
with a `kill_status` query on every port connect. The pull direction is what
clears a stale "killed" mirror after a CLI unkill that happened while the
service worker slept; the push direction is what flips the mirror promptly
while a port is up. A deliberate asymmetry: a healthy host startup pushes
nothing, so the first frame on a fresh connection is never a surprise to a
consumer that did not ask.

### 5. The audit trail

Every security-relevant decision is recorded, after it is made, in two sinks:

- **stderr**, through the existing leveled logging (`BB_LOG_FORMAT` selects
  text or JSON), where the harness or Chrome already captures diagnostics;
- **`runtime_dir()/audit.log`**, 0600 in the 0700 runtime directory: one JSON
  record per line (`AuditRecord`, versioned, `deny_unknown_fields`), written
  by whichever of our processes made the decision - the CLI for a pair or a
  kill, the broker for an admission, the native host for an
  extension-initiated revoke. The file is size-capped with a single rotation
  (`audit.log` -> `audit.log.1`), so the trail is bounded at roughly half a
  megabyte and survives the short-lived processes that produce it.

Recorded events: tool calls (with outcome, taxonomy code, duration, and the
browser connection they routed to), harness admissions and refusals, attach
refusals before a role was declared, browser attaches and kill-time refusals,
client pairing and revocation (with the surface that did it), host-key
revocations, kill and unkill (with the surface), and the extension's own
user-facing decisions: confirmations shown, allowed, and denied, and
enrollment approvals, rejections, and revokes. The extension events arrive
over a new fire-and-forget `audit_event` control frame; the host accepts only
those extension-owned kinds and stamps `surface: extension` itself, so the
browser leg cannot forge an admission or a kill into the trail.

Three rules govern the writers, and they are the security content of this
decision:

- **Log after deciding.** Recording happens strictly after the decision has
  been applied. No decision waits on the trail.
- **Never fail the decision because logging failed.** A full disk, an
  unwritable file, a poisoned path: the record is dropped, a process-local
  counter increments, and the next successful record carries `dropped: n` so
  the gap is visible in the trail instead of silent. An attacker who can
  fill the disk must not be able to hold enforcement hostage through its own
  bookkeeping - and the audit trail must never become a fail-OPEN either,
  which is why it gates nothing.
- **Read fail-closed.** The CLI reader (`chromium-bridge audit`) parses each
  line strictly and renders anything else as an explicit unrecognized record,
  counted at the end. Corruption is shown, not smoothed over.

The extension keeps its own bounded ring (200 entries, strict-parsed, in the
#32 storage) feeding a read-only options panel, event-driven off
storage.onChanged and translated in all three locales. The ring is display
only; the durable trail is the host file.

### 6. Surfaces

- CLI: `chromium-bridge kill`, `chromium-bridge unkill`, `chromium-bridge
  audit [--limit <n>]`; `doctor` prints the kill state and goes non-zero
  while killed or unreadable.
- Extension: a kill-switch panel (engage/release, current state, live
  updates) and the audit panel, both on the options page, both behind the
  extension-page sender gate.
- App (future): `kill::engage`, `kill::release`, `kill::is_killed`,
  `audit::record` - the same core functions every surface above uses.

## Why these choices

- **Why the latch rides in `revocation.json` instead of its own file.** A
  separate `kill.json` would need its own fail-closed read at every
  enforcement point, its own atomicity story against the epoch bump, and its
  own tamper analysis; the record that already has all three was sitting
  there. The cost is coupling: an old binary reading a post-kill file refuses
  (deny_unknown_fields), which is the strict posture ADR-0025 already chose
  for this record during upgrade windows.
- **Why killed harnesses get typed errors instead of dropped connections.**
  Dropping severs the messenger. The refusal is the message: the user's
  agent should print "bridge kill switch is engaged", not "server
  disconnected, retrying...". The dangerous capability is the browser leg,
  and that IS severed.
- **Why the native host gets a whole mode instead of just being refused.**
  If the broker simply refused browser attaches, the host would exit, the
  extension would respawn it every two seconds, and each respawn would die
  again: a kill would turn the bridge into a crash loop whose only exit is
  the CLI. The control-plane mode holds the port open and quiet, keeps the
  options page's unkill working, and converts the release into one clean
  respawn.
- **Why the mirror's absent state allows.** The mirror is defense in depth
  over storage only the SW can write; the host enforces regardless. Treating
  "never heard from a host" as killed would brick fresh installs for zero
  security gain. Malformed is different: garbage where a record should be is
  evidence someone wrote there, and it refuses.
- **Why the audit file is JSON lines and not the stderr format.** The stderr
  line is for a human tailing a log; the file is for a reader (`audit`, the
  future app) that must parse records strictly years of versions later. One
  canonical serde shape with `deny_unknown_fields` keeps the reading side
  honest, and rotation keeps it bounded without a daemon.

## Consequences

### Positive

- One user action stops everything, from any surface, in at most one watcher
  tick for idle connections and immediately for active ones - and the state
  survives restarts, respawns, and reboots until an equally explicit release.
- Every trust decision now leaves a durable, bounded, tamper-evident-on-read
  record, queryable offline (`chromium-bridge audit`) and visible in the
  extension.
- The kill state is enforced by mechanism at each layer independently:
  dispatch check, severed sockets, attach refusal, host control-plane mode,
  extension gate. No single check is load-bearing.

### Negative / accepted

- **A same-user process can release the switch** by editing
  `revocation.json`, exactly as it can delete the trust files (ADR-0025's
  conceded boundary). The kill switch is a brake for the user, not a defense
  against a hostile local process; SECURITY.md's threat model owns that
  boundary.
- **The presence floors attest intent, not hardware, until Phase 8.** A
  same-user process can allocate a pty and type the CLI phrase, and the
  extension floor is a claim the channel attests rather than one the host
  can verify. Both are named residuals of the same conceded boundary as the
  record itself; what the floors buy today is that no unkill can be silent,
  scripted, or accidental, and the audit trail names the rung behind every
  release. Touch ID (Phase 8) upgrades the gate to hardware without an API
  change.
- **A sub-second window exists at engagement.** A request already past the
  dispatch check, or a browser attach between its admission check and the
  watcher's next tick, can complete while the kill is landing. Bounded by
  one poll interval; the severed sockets drain everything in flight.
- **Killed-while-running hosts bridge for up to one tick** before the broker
  severs them; their own poll is the same interval. Named, bounded, and the
  reason the watcher exists.
- **The audit trail is best-effort by design.** Drop-on-failure with a
  counter means a sufficiently broken disk yields gaps (visible ones). The
  extension's forwarded events additionally require a live port; while the
  port is down they exist only in the extension ring. The alternative,
  blocking decisions on bookkeeping, fails the wrong way.
- **`CallError::KillStateUnknown` is currently unreachable on the broker
  path**, because the per-request epoch guard reads the same record first
  and drops the connection on a corrupt read before dispatch runs. It exists
  so that any future dispatch path without the guard still fails closed
  typed. Layered checks over shared state overlap; that is the point.
- **An old binary refuses a post-kill revocation record** (unknown fields).
  Fail-closed during upgrade windows, consistent with ADR-0025's decision 7.

## Verification

- Rust units and proptests: the kill/epoch interleaving invariants
  (revocation.rs), the dispatch verdict matrix (kill.rs), the presence
  ladder's no-downgrade rule and the CLI floor's confirm matrix
  (presence.rs), the watcher's kill sweep and unreadable-record sweep
  (broker.rs), session-wide browser shutdown (session.rs), audit rotation,
  permissions, truncation, strict parsing, and the extension-kind whitelist
  (audit.rs), frame classification and injection filtering for the new
  control frames (protocol.rs, native_host.rs).
- e2e: kill/refuse/release/recover against a live broker, control-plane host
  behavior, the extension-surface release (audited with its auth path),
  audit-file contents, modes, and the `audit` subcommand.
- adversarial A20 (kill reaches dispatch, the browser leg, fresh hosts, and
  relays), A21 (corrupt record: everything refuses, unkill refuses, doctor
  reports), A22 (unkill demands user presence: a piped stdin and a wrong
  phrase are refused, the switch stays engaged, refusals are audited, and
  the typed confirmation releases with auth=cli_confirm).
- chaos C12 (kill mid-dispatch: in-flight call fails fast and typed, full
  recovery after release), C13 (audit sink broken mid-run: decisions
  unaffected, gap surfaces as a dropped counter after healing).
- vitest: the router's sender gate over get_kill/set_kill/get_audit, the
  mirror's fail-closed matrix, mirror updates from host frames only, the
  bounded strict-parsed ring, and the gate integration in enrollment.
- Isolated browser (CHROME_BIN, not part of the required gate): kill/unkill
  from the options page reflected across an SW restart; the audit panel in
  en, zh_CN, and zh_TW.

## Implementation pointers

- `src/packages/core/src/kill.rs`: `engage` / `release` / `is_killed` / `check`,
  the CLI handlers.
- `src/packages/core/src/presence.rs`: the user-presence ladder (`require_presence`,
  `PresenceAttestation`), the Phase 8 hardware seam, the CLI and extension
  floors.
- `src/packages/core/src/revocation.rs`: `killed`, `kill_epoch`,
  `set_killed_locked`.
- `src/packages/core/src/audit.rs`: `AuditRecord`, `record`, rotation,
  `extension_kind`, `run_audit`.
- `src/packages/core/src/broker.rs`: the kill-aware `watch_tick`, `admit_browser`
  refusal; `src/packages/core/src/session.rs`: `shutdown_all_browsers`.
- `src/packages/core/src/mcp_server.rs`: the dispatch gate in `handle`.
- `src/packages/core/src/native_host.rs`: `run_control_plane`,
  `handle_control_frame`, `spawn_revocation_watch`, the kill frame handlers.
- `src/packages/core/src/protocol.rs`: `AdminControl::{KillStatus, KillEngage,
  KillRelease, KillStatusResult, AuditEvent}`.
- `extension/src/lib/background/kill.ts`, `audit-log.ts`; the gate hook in
  `enrollment.ts`; `extension/src/entrypoints/options/KillSwitchPanel.tsx`,
  `AuditPanel.tsx`.
- `tests/e2e.py::test_kill_switch_round_trip`; `tests/adversarial.py`
  A20/A21/A22; `tests/chaos.py` C12/C13;
  `extension/tests/background/kill.test.ts`.
