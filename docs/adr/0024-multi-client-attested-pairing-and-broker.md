# ADR-0024: Multi-client attested pairing and the ref-counted broker

- Status: Accepted
- Date: 2026-07-17
- Extended by (2026-07-17): [ADR-0025](0025-any-side-revocation-epoch.md) makes
  a `revoke-client` reach the broker's live connections (drop + refuse
  re-attach) via the revocation epoch, and closes the
  deleting-`clients.json`-reverts-to-open residual named below for the
  single-file case with a one-way enrollment latch.
- Extends: [ADR-0019](0019-authenticated-ipc.md), [ADR-0020](0020-kernel-attested-peer-identity.md)
  (the UDS + peer-UID + attestation + HMAC design stands; this adds the
  harness-admission boundary and the broker)

## Context

Two problems, one surface.

First, only one harness could drive the browser at a time. A fresh MCP-server
instance ran `supplant_prior_server`: it attested the prior owner and SIGTERMed
it, newest wins. That was the right shape for one trusted client, but the user
wants concurrent multi-client -- Claude Code, Copilot, and Codex driving the
same browser at once. Takeover cannot deliver that: every new client killed the
previous one's working bridge.

Second, nothing established *who is driving the MCP server*. ADR-0020 attests
that a bridge-socket peer is our own binary, which is the right identity for
the browser leg. It says nothing about the harness on the other end of the
server's stdio, because stdin is an anonymous pipe and an anonymous pipe
carries **no kernel peer credentials**: there is no `SO_PEERCRED`, no audit
token, nothing to `getsockopt`. The socket layer's attestation does not
transfer. Until this phase, anything that spawned the binary in MCP mode owned
its stdin and was trusted unconditionally -- the threat model carried this as
boundary stub #1, explicitly unenforced.

This ADR closes both: an allowlist of attested client identities decides which
harnesses may drive the bridge, and a ref-counted broker lets all of the
admitted ones drive it at the same time.

## Decision

### 1. A trusted-client allowlist, keyed on attested code identity

The set of permitted harnesses is persisted at `runtime_dir()/clients.json`:
0600, in the same 0700 per-user runtime directory as the lock file, written
atomically under the runtime lock (`ipc::with_runtime_lock` +
`write_private_atomic`), parsed fail-closed with `deny_unknown_fields` and a
version check, and size-capped on read (256 KB) so a foreign file is rejected
rather than slurped.

Each entry pairs a human-facing `name` (a validated label such as
`claude-code`) with an `Anchor`, and the anchor is the only authorization key.
The name exists for the user, the logs, and the audit surface; a harness cannot
admit itself by *claiming* to be `claude-code`. Admission requires that the
harness's kernel-attested code identity (macOS `cdhash`, Linux
`/proc/<pid>/exe` SHA256, plus the macOS signing Team ID when present) match an
anchor. This is the zero-trust rule applied to the client boundary: a
self-reported identity is not enforcement.

The user manages the list with `chromium-bridge pair-client`, `revoke-client`,
and `list-clients` (dispatched in `src/apps/host/src/main.rs`, implemented in
`src/packages/core/src/allowlist.rs`).

### 2. Anchors that survive re-signing

A raw image hash is precise but brittle on macOS: a free Apple Development
certificate re-signs roughly weekly, and every re-sign changes the `cdhash`.
Pinning only the hash would break admission every week and force a re-pair. So
there are two anchor kinds:

- `Anchor::TeamId` pins the macOS signing Team ID, which is stable across
  re-signs. It is the preferred anchor whenever the client image is Team-ID
  signed.
- `Anchor::Hash` pins the exact attested image hash. It is the only anchor
  available for unsigned / ad-hoc builds, and the only anchor on Linux (no
  Team ID exists there; `pid_client_identity` always reports `team_id: None`).
  Its explicit renewal path is a re-pair: `pair-client` with an existing name
  replaces that entry, so pairing the same client after a re-sign does not
  accumulate stale anchors.

The on-disk shape is a tagged `{kind, value}` pair, so a hash can never be
misread as a Team ID or vice versa.

### 3. Harness attestation at the stdio boundary

The identity fed to the allowlist comes from `attest_parent()`
(`src/packages/core/src/ipc/attest.rs`): the server takes `getppid()` and measures
that pid's running image the same way the bridge peers are measured -- on macOS
a pid-identified `SecCode` validated with `SecCodeCheckValidity`, yielding the
`cdhash` and the Team ID; on Linux the SHA256 of `/proc/<pid>/exe`. The server
runs this before serving a single tool call (`admit_own_harness` in
`mcp_server.rs`), and a refused harness gets no broker and no relay: the
process exits.

When an instance ends up a relay rather than the broker (decision 4), the relay
reports its measured parent identity to the broker in
`AttachRequest::Client { harness }`. The broker trusts that report not because
of the frame's contents but because the connection carrying it already passed
`attest_peer`: the relay is a genuine instance of our own binary, our own
binary measures its parent honestly via `getppid`, and a different same-user
process attempting the same attach is not our binary and fails `attest_peer`
before it can speak. The harness may also self-assert a name via the
`CHROMIUM_BRIDGE_CLIENT_NAME` environment variable; it is validated like a
browser label and used for logs only, never for authorization.

Stated plainly: this is **not** kernel attestation of the pipe itself. No such
mechanism exists for an anonymous pipe in user space; `getppid` names the
process that spawned us, which is the strongest identity available at this
boundary. What that leaves open is in the residuals.

### 4. The ref-counted broker replaces newest-wins takeover

The first instance to bind the 0600 socket and the lock becomes the **broker**
(`ipc::listen_and_publish` returns `Published`; `broker::run_broker`). A later
instance that loses that race does not SIGTERM the owner; it attaches to it as
a **relay** (`broker::run_relay`): it dials the socket, attests the broker
(`attest_peer`, mutual as ever), completes the HMAC handshake, sends
`AttachRequest::Client` with its attested harness identity, and -- once
accepted -- becomes a dumb NDJSON line pipe between its harness's stdio and the
authenticated socket, mirroring the native host's pumps (`pump_lines`, each
line capped at `MCP_MAX_LINE`, over-cap fails closed). The relay does not parse
the JSON it forwards; the broker is the single JSON-RPC brain.

One shared `Session` in the broker holds the browser connections and
multiplexes every harness's tool calls: `mcp_server::handle()` is the one
dispatcher, called by the broker's own stdio loop and by every relay serve
loop alike. Browsers declare themselves with `AttachRequest::Browser` on the
same socket; the browser leg's authentication is unchanged from
ADR-0019/0020/0022 (its label was already MAC-signed in the handshake).

The broker is **ref-counted on harness clients**: its own stdio harness counts
as the first client, each admitted relay adds one, and browser connections
deliberately do not count -- the broker outlives any one browser but not the
harnesses it serves. When its own stdin closes, the broker keeps serving
attached relays and exits only when the last one detaches (`RefCount`:
`wait_zero` latches a terminal flag under the lock, after which `try_incr`
refuses, so a racing relay can never attach to a broker that has committed to
tearing down its socket). There is no idle daemon.

The old `supplant_prior_server` / attest-and-SIGTERM takeover path was
**removed**, deliberately, with the pidfd machinery that supported it. Its
remaining descendant is stale-lock arbitration: `listen_and_publish` uses
`attest_pid` to tell a live genuine broker (defer and relay) from a dead or
foreign pid holding the lock (supersede the stale file).

The attach reply is explicit so a relay can tell its three outcomes apart:
`AttachReply::Accepted` proceeds; `AttachReply::Unavailable` (capacity, or
shutting down) means retry -- the loop in `mcp_server::run` sleeps 150 ms and
tries again, up to 6 attempts, and on a retry it may find the socket free and
become the broker itself; `AttachReply::Refused` (allowlist miss) means fail
closed, exit non-zero, no retry.

### 5. Enrolled vs unenrolled: opt-in, then fail closed

Like the enrollment ceremony (ADR-0021), harness admission is opt-in and
becomes strict the moment it is turned on:

- **No `clients.json`** means unenrolled. Admission is not enforced -- the
  bridge keeps the pre-Phase-4 posture, which is exactly the documented
  same-user residual of threat #4, no worse than before. Both the server
  admitting its own harness and the broker admitting a relay log this at ERROR
  level (`SECURITY: harness admission is NOT enforced ...`), so `BB_LOG=error`
  cannot silence it.
- **The file exists** means enrolled, and everything unmatched fails closed:
  a non-matching identity, and equally an identity that could not be measured
  at all. An unmeasured harness is refused, never waved through.
- **A load failure fails closed.** An unreadable, oversized, unknown-versioned,
  or corrupt allowlist is an error, not a silent `None`: treating a damaged
  file as "unenrolled" would fail open. The server refuses to serve
  (`process::exit(1)`); the broker refuses the relay
  (`Refused: allowlist unreadable`).
- **An empty enrolled list admits nobody.** `revoke-client` leaves the file in
  place when the last entry goes: "the user revoked every client" reads as a
  locked bridge, not a reset to the open posture.
- **But DELETING the file is not the same as revoking.** Enforcement is not
  monotonic against a same-user writer: `rm clients.json` reverts an enrolled
  bridge to the unenrolled bootstrap posture, because deletion is
  indistinguishable from never-enrolled and the bootstrap needs that (the
  absent-file case is what lets a first install work). So "a load failure fails
  closed" must not be read as "enforcement is durable against the same-user
  writer": corruption fails closed, deletion reverts to open. This is inside the
  conceded same-user boundary (a process that can delete the file can also plant
  a manifest or re-run our binary), and it is loudly ERROR-logged on the next
  start, but it is a real asymmetry -- named in the residuals below and a
  candidate for the Phase 5 tamper-evidence work (it is the same class as the
  trust-state-tampering residual, follow-up #32).

The decision itself is a pure function, `allowlist::decide(list, identity)`,
exhaustively unit-tested apart from any I/O.

### 6. DoS limits on the broker

The broker is one process fronting every client, so it gets an explicit
resource posture (constants in `src/packages/core/src/broker.rs`):

- `MAX_HARNESS_CLIENTS = 8`: concurrent harnesses (own stdio + relays). At the
  cap a relay attach is answered `Unavailable`, retryable, not denied.
- `MAX_BROWSERS = 16`: concurrent distinct browser labels. A same-label
  reconnect always replaces its slot; only a new label beyond the cap is
  refused.
- `MAX_PENDING_ATTACH = 32`: connections simultaneously in the handshake +
  attach phase, so a flood of half-open connections cannot exhaust threads
  before any is admitted.
- `ATTACH_TIMEOUT = 10s`: a read timeout covering the handshake and attach
  frames; a peer that connects and stalls is dropped rather than holding a
  pending slot. Cleared once admitted, because a steady-state browser or relay
  connection is legitimately idle for long stretches.
- A per-relay token bucket (`RATE_BURST = 128.0`,
  `RATE_REFILL_PER_SEC = 128.0`): a relay that floods past it is dropped, fail
  closed; it may reconnect. The bucket is per-connection and resets on
  reconnect, so the effective steady-state ceiling against a
  compromised-but-allowlisted harness is roughly the bucket size times the
  reconnect rate (itself bounded by the handshake + attestation cost of each
  new connection). That is deliberately a defense-in-depth bound on the damage
  rate, not the primary control: the relay is already attested and allowlisted,
  and revocation, not the rate limit, is the lever that removes its trust.

### 7. Verification

- **loom** model-checks the `RefCount` shutdown protocol (the `loom_model`
  tests): shutdown fires exactly when the count reaches zero, no attach
  succeeds after the terminal decision latches, and racing attach/detach pairs
  never underflow the count. loom explores the interleavings a unit test
  cannot.
- **cargo-fuzz** targets fuzz every wire parser this phase touches or trusts:
  native-messaging framing (`nm_frame`), MCP JSON-RPC (`mcp_jsonrpc`), the
  bridge envelope (`bridge_envelope`), the handshake (`handshake`), and the
  attach frames (`attach`).
- **adversarial.py** exercises the admission boundary live: A14 (enrolled +
  non-allowlisted harness is refused, fail closed), A15 (a spoofed client NAME
  does not admit a non-matching hash), A16 (a genuinely paired harness is
  admitted and drives the bridge). **chaos.py** exercises the broker's
  lifetime: C4 (concurrent starts settle to one broker plus relays, all
  serving) and C9 (relay attach/drop churn leaves the ref-count healthy and
  the broker owning the lock).

## Why these choices

- **Why key on an anchor and not the name.** A name is a string any process can
  put in an environment variable. The anchor is what the kernel and the
  Security framework testify to about the running image. Keeping the name
  purely cosmetic means there is nothing to get wrong later: no code path
  exists in which the name admits anyone (A15 checks this live).

- **Why Team ID over hash where available.** Weekly `cdhash` churn under a free
  development certificate would make hash anchors a weekly re-pair treadmill,
  and a security control that nags weekly gets disabled. The Team ID is issued
  by Apple, attested from the validated running signature, and stable. The cost
  is coarseness -- any binary signed by that team matches -- which is accepted
  and named in the consequences.

- **Why the relay reports the harness identity instead of the broker measuring
  it.** The broker cannot: the harness is the relay's parent, not the broker's,
  and no kernel interface lets one process take another's anonymous-pipe peer.
  The relay is the only process positioned to run `getppid`. The report is
  trustworthy exactly because the reporting channel is the ADR-0020-attested
  socket: only our own binary can deliver it, and our own binary has no code
  path that lies about its parent.

- **Why a broker instead of N independent servers.** The browser-facing socket,
  the lock, and the extension's native-host connections are singletons by
  construction (one endpoint in the lock file). Multiplexing through the first
  instance keeps ADR-0019/0020 intact -- one socket, one owner, every
  connection individually attested -- rather than inventing a second, shared
  rendezvous. It also keeps ADR-0022's per-connection label guarantees: the
  browser legs land in one `Session` registry, unchanged.

- **Why ref-counting on harnesses and not browsers.** The broker exists to
  serve harnesses; a browser with no harness attached is a bridge nobody is
  driving. Counting harnesses gives the no-idle-daemon property (the process
  tree dies with the last client) without tearing the bridge down while any
  client still needs it.

- **Why `Unavailable` is distinct from `Refused`.** They demand opposite
  reactions. Capacity and shutdown races are transient: the correct move is to
  retry, and the retry may legitimately win the bind and become the broker. An
  allowlist miss is an authorization decision: retrying it would be a
  tight loop knocking on a locked door, so the relay fails closed immediately
  and tells the user to pair. Collapsing both into a bare socket close would
  make the relay guess.

- **Why the takeover path was deleted rather than kept as a fallback.** Two
  arbitration mechanisms for one socket is a race generator, and a
  SIGTERM-on-sight fallback is exactly the kind of convenience bypass the
  zero-trust rules forbid: any code path that kills the attested owner could be
  induced by a hostile sibling. Coexist-or-retry has one owner at every
  instant, model-checked.

- **Why caps and a rate limit on an allowlisted client.** Attestation
  identifies a binary, not an intention. A trusted harness can still be
  compromised at runtime, and the broker now aggregates every client's blast
  radius, so it bounds handshake fan-out, connection counts, and per-relay
  request rates as depth behind the admission gate.

## Consequences

### Positive

- Several MCP clients drive one browser concurrently; starting a second one no
  longer kills the first one's bridge (C4 checks this live).
- Once the user enrolls, "who may drive the browser" is enforced by measured
  code identity at both places a harness can enter (the server's own stdio,
  and a relay's attach), fail closed including the unmeasurable and
  damaged-allowlist cases.
- The unenrolled posture is unchanged from before this phase and is logged at
  ERROR on every start, so the gap is loud until the user closes it.
- The broker's lifetime is deterministic and model-checked: it exits exactly
  when the last harness leaves, and never strands a relay on a half-dead
  socket.
- The wire surface this phase added (the attach frames) is fuzzed alongside
  the parsers it joins.

### Negative / accepted

- The broker is a single point of failure: if it crashes, every attached
  relay's harness sees EOF at once. Accepted -- the relays' harnesses can
  restart their servers, and the first to arrive becomes the new broker; C9
  exercises churn around this.
- A relay adds one local hop to every tool call. Negligible on a Unix socket.
- A Team-ID anchor trusts every binary signed by that team, not one image.
  This is the deliberate price of surviving re-signs; a user who wants
  image-exact pinning can pair a hash anchor and re-pair on renewal.
- Hash anchors on Linux and for ad-hoc macOS builds break on every client
  update, by design; the renewal path is a same-name re-pair.
- `clients.json` is one more security-relevant file in the runtime directory,
  with the same same-user-writer exposure class as the rest of it (threat
  model, boundary 3).
- Windows gets none of this enforcement: no attestation exists there, so
  harness admission degrades to the unenrolled / secret-only posture with the
  rest of the IPC layer, and the startup banner says so at ERROR level.

## Residual risks, named honestly

- **`getppid` names who spawned the relay, not who writes its stdin.** At
  process start the OS has just forked us from the harness, so `getppid` names
  the genuine spawner at that instant, and a later reparenting makes `getppid`
  return the reaper (commonly pid 1), whose identity does not match the
  allowlist -- so a stale parent fails admission closed rather than being
  trusted. What is NOT closed: an anonymous pipe's write end can be inherited or
  passed to another process, so "the harness that spawned us" and "the process
  feeding our stdin" are not provably the same, and the measurement is pid-keyed
  so it carries the same microsecond pid-reuse race as any pid-keyed attestation
  (ADR-0020); on macOS `pid_client_identity` still validates the running image
  via `SecCodeCheckValidity`. This raises the bar -- a random same-user process
  is not spawned by an allowlisted harness -- but there is no kernel attestation
  of an anonymous pipe in user space, and this ADR does not pretend the harness
  boundary is unforgeable.
- **The self-asserted name is never the authorization key.** Enforced by
  construction (the decision function never reads it) and tested (A15). Listed
  here because the log lines print it, and a reader of the audit surface must
  know it is a label, not a proof.
- **A trusted-but-compromised harness is still trusted.** Attestation
  identifies a binary, not an intention. If Claude Code itself is compromised,
  its anchor still matches. The caps and the rate limit bound the damage rate;
  they do not revoke trust. Revocation (`revoke-client`, and the any-side
  revocation epoch of the next phase) is the lever for that.
- **The broker aggregates blast radius.** One persistent same-user process now
  fronts all clients and all browsers, where previously each server's lifetime
  equaled one harness's. Mitigated by the DoS posture (decision 6) and by the
  socket staying 0600 in the 0700 directory with every attach individually
  attested; not eliminated.
- **Windows has no attestation**, so harness admission does not exist there;
  the boundary degrades to the secret-only model documented for the rest of
  the IPC layer (threat #4).
- **Unenrolled bootstrap admits any our-own-binary harness.** Until the user
  pairs a first client, any same-user process that runs our binary can drive
  the browser -- the pre-existing threat #4 residual, unchanged, now logged at
  ERROR on every start. Enrollment is the user's act; we do not auto-enroll
  the first spawner, because a silent trust-on-first-use would hand the slot
  to whichever process races first.
- **Deleting `clients.json` reverts to bootstrap; enforcement is not durable
  against the same-user writer.** Corruption fails closed, but deletion cannot:
  an absent file is how a first install legitimately starts unenrolled, so
  `rm clients.json` silently drops an enrolled bridge back to the open
  bootstrap posture (loudly ERROR-logged on the next start). This lives inside
  the conceded same-user boundary -- a process that can unlink the file can
  also plant a native-messaging manifest or re-run our binary -- but it means
  the allowlist is not tamper-evident. **Narrowed by
  [ADR-0025](0025-any-side-revocation-epoch.md):** a one-way enrollment latch in
  `revocation.json` makes deleting `clients.json` ALONE detectable, so the
  single-file deletion now fails closed as tampering rather than reverting.
  What remains is the two-file deletion (both `clients.json` and
  `revocation.json`), which is the irreducible same-user residual.
- **Wedged-broker liveness.** A broker that is alive and attested but stops
  accepting leaves a new instance retrying its bounded attempts (6, with
  150 ms sleeps) and then exiting with a clear error. It cannot and must not
  SIGTERM the owner (that path was removed on purpose). A wedged broker is a
  bug to fix, not a security hole: nothing unauthorized is admitted, the
  failure is loud, and the user can kill the wedged process themselves.

## Implementation pointers

- `src/packages/core/src/allowlist.rs`: `Anchor`, `ClientEntry`, `Allowlist`
  (load/pair/revoke/write), the pure `decide`, and the
  `pair-client` / `revoke-client` / `list-clients` handlers.
- `src/packages/core/src/broker.rs`: `RefCount`, `RateLimiter`, `run_broker`,
  `admit` / `admit_browser` / `admit_client`, `run_relay`, `pump_lines`, the
  DoS constants, and the `loom_model` tests.
- `src/packages/core/src/ipc/attest.rs`: `attest_parent`;
  `src/packages/core/src/ipc/platform/{macos,linux}.rs`: `pid_client_identity`
  (macOS `signing_identity_of_code` reads cdhash + Team ID; Linux hashes
  `/proc/<pid>/exe`, `team_id` always `None`).
- `src/packages/core/src/ipc/mod.rs`: `ClientIdentity`.
- `src/packages/core/src/protocol.rs`: `HarnessId`, `AttachRequest`, `AttachReply`.
- `src/packages/core/src/mcp_server.rs`: `admit_own_harness`, the
  become-broker-or-relay loop, `CLIENT_NAME_ENV`, the shared `handle()`.
- `src/packages/core/src/native_host.rs`: sends `AttachRequest::Browser`, reads the
  `AttachReply`.
- `src/packages/core/fuzz/fuzz_targets/`: `nm_frame`, `mcp_jsonrpc`, `bridge_envelope`,
  `handshake`, `attach`.
- `tests/protocol/adversarial.py` A14/A15/A16; `tests/protocol/chaos.py` C4/C9.
