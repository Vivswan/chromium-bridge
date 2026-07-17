# ADR-0025: Any-side revocation epoch

- Status: Accepted
- Date: 2026-07-17
- Extends: [ADR-0021](0021-enrollment-ceremony.md) (the enclave enrollment
  key and its host<->extension control frames; this adds the extension-driven
  deletion path and the host-originated revoked push),
  [ADR-0024](0024-multi-client-attested-pairing-and-broker.md) (the
  trusted-client allowlist and the broker; this makes a revocation reach the
  broker's live connections and closes the allowlist-deletion residual named
  there)

## Context

Phase 4 could enroll trust from several surfaces but could only half-revoke
it. `revoke-client` rewrote `clients.json`, yet a broker that had already
admitted that harness kept serving it: admission was decided once, at attach,
and never revisited. `chromium-bridge revoke` deleted the enclave key, but a
pinned extension only learned of it at the next opt-in reverify, which defaults
to off. And the two trust states each had their own, unsynchronized notion of
"current", with no shared signal that anything had changed.

ADR-0024 also named a concrete asymmetry as a residual: a corrupt `clients.json`
fails closed, but a DELETED one silently reverts an enrolled bridge to the open,
unenrolled bootstrap, because an absent file is exactly how a first install
legitimately starts. A same-user `rm clients.json` therefore turned enforcement
back off without a trace.

This record introduces one mechanism that addresses all of it: a shared,
monotonic revocation epoch that every surface bumps and every enforcement point
re-reads.

## Decision

### 1. A single monotonic epoch, persisted per machine

The revocation state lives at `runtime_dir()/revocation.json`: 0600, in the
same 0700 per-user directory as the lock file and the allowlist, written
atomically under the runtime lock (`ipc::with_runtime_lock` +
`write_private_atomic`), parsed fail-closed with `deny_unknown_fields`, a
version check, and a size cap. The shape is a `u64 epoch` plus two scope
markers (`clients_epoch`, `host_key_epoch`) and a one-way enrollment latch
(decision 5). An absent file reads as the bootstrap default (epoch 0, nothing
latched); a present-but-unreadable file is an error the caller must fail closed
on, never a silent zero, because treating a damaged record as "epoch 0" would
let a tamperer suppress a revocation.

Every revocation-relevant mutation increments the epoch. The authoritative
trust state does the same write, in the same critical section: `Allowlist::revoke`
rewrites the list and bumps the epoch under one runtime-lock hold, so no
enforcement point can ever observe the new epoch paired with the old list, or
the reverse, beyond its own next read.

### 2. The epoch is a change notice, not an authority

The epoch does not decide anything. The authoritative states stay exactly where
they were: the client allowlist (`clients.json`) and the Secure Enclave key. A
bump only tells an enforcement point "re-read the authority now"; the re-read
makes the decision. This keeps the failure analysis small. A same-user process
that scribbles on this file can force spurious re-checks (each re-admits whoever
is still authorized) or corrupt it (which fails every enforcement read closed).
Neither direction can admit anyone the authoritative state does not already
admit. The epoch buys promptness and a tamper signal, not a new grant of trust.

Enforcement compares by inequality, not order: any difference between the epoch
a connection was admitted under and the current epoch forces a re-decide,
including a file a tamperer rolled backward to an older value.

### 3. Client revoke reaches the live broker

`revoke-client` (CLI) and the extension's `client_revoke` control frame both
call `Allowlist::revoke`, which rewrites the list and bumps `clients_epoch` in
one critical section. Two mechanisms then carry that to a running broker:

- Per request: each admitted harness carries an `EpochGuard`. A relay (which
  the watcher covers, below) may take the fast path and re-read the allowlist
  only when the epoch changed; the broker's OWN stdio harness has no watcher
  (it serves on stdin/stdout, with no socket to shut down), so its guard
  re-decides on every request, and a revocation whose epoch bump failed to
  persist still drops it. A revoked harness's next call drops its connection,
  fail closed.
- Per idle connection: a watcher thread re-decides every registered relay
  UNCONDITIONALLY on a one-second timer, against a freshly loaded allowlist,
  not gated on an epoch change. So a revoke reaches a connection that is
  sitting idle without waiting for it to send anything, and correctness does
  not depend on the epoch counter advancing at all. The epoch is a promptness
  signal for the per-request fast path, not the authority; the allowlist is.

Re-attach is refused at once: a fresh server instance spawned by the revoked
harness reads the current allowlist at admission and fails closed, exactly as a
never-paired harness would. Every read of either file on these paths is
fail-closed, so an unreadable revocation record or allowlist drops the
connection rather than serving it on stale trust.

### 4. Host-key revoke pushes to the extension

`chromium-bridge revoke` and `pair --reset` still delete the enclave key
(deletion is not presence-gated: it only ever reduces capability, per ADR-0021)
and now also bump `host_key_epoch`. A connected native host watches that marker
and, when it moves, confirms the key is gone in the keychain and pushes a
host-originated `enclave_revoked` frame to the extension. The extension flips a
pinned bridge to its fail-closed compromised state immediately, without waiting
for the opt-in reverify.

The push is host-originated, which blocks one specific forgery: `native_host.rs`
drops any enclave control frame arriving on the server leg (ADR-0021), so a
server, ours or a substituted one behind the socket, cannot inject a false
`enclave_revoked`. What being host-originated does NOT authenticate is the host
itself. The frame carries no proof (the whole point is that the key is gone, so
nothing can sign it), and the native-messaging manifest is user-writable
(threat #4's manifest-substitution residual), so a same-user process that
substitutes the host binary is the process on the port and can emit
`enclave_revoked` directly. That is a false-compromised denial of service
against the user's own bridge: it fails the bridge closed, never open, and
grants no browser capability, but it is not prevented. It is named in the
residuals rather than claimed closed, and it is the same capability a same-user
attacker already has by simply refusing to answer challenges. The genuine
host's own push is gated twice, so an ordinary revocation is not mistaken for a
never-enrolled machine and a scribbled-on revocation file cannot make the
genuine host push: `host_key_epoch > 0` (a revocation was actually recorded)
AND a keychain-confirmed absent key. A startup check covers the common case
where the key was revoked while no host was running: MV3 kills the host with
the service worker, the extension's pinned state survives in its durable
storage, and the push on the next host spawn is what fails it closed.

### 5. Extension revoke deletes the host key, and closes the asymmetry

Before this record, unpairing from the extension cleared the pin but left the
host's keychain key alive, and revoking from the CLI deleted the key but left
the extension's pin. Both directions now converge on "no usable credential
remains". The extension's revoke clears the pin AND sends a host-directed
`enclave_revoke` control frame; the host deletes the key, clears the recorded
policy, and bumps `host_key_epoch`. The request is durable: it is stored in the
#32 SW-only trusted storage and re-sent on every connect until the host's
`enclave_revoked` acknowledgement clears it, so a service-worker death or a
down port cannot lose it (deletion is idempotent on the host side).

The extension also gains a managed path to the trusted-client allowlist through
two more host-handled control frames, `client_list` and `client_revoke`,
answered by the native host itself and never forwarded to the server. They add
no capability: enumerating and revoking trusted clients is already available to
any same-user process via the CLI (`list-clients`, `revoke-client`), so these
frames are a new path to capability reduction, not a new grant.

### 6. The enrollment latch makes single-file deletion tamper-evident

`revocation.json` carries a one-way boolean, `clients_enrolled`, set the first
time a client is paired and never cleared. Admission reads the allowlist through
`load_enforced(latched)`: with the latch set, an absent `clients.json` is no
longer the bootstrap posture. A client allowlist existed on this machine, so its
disappearance is a deletion, and deletion fails closed with a "tampering"
message instead of silently reverting to the open bootstrap.

This is deliberately bounded. A same-user attacker who deletes BOTH files still
reaches the bootstrap posture, because no user-space marker survives a writer
who can delete any file we can write. What the latch closes is the single-file
case: the accidental `rm clients.json`, and the lazy attack that deletes only
the obvious file. That is a real narrowing of the ADR-0024 residual, and the
two-file residual is named honestly below and pinned by an adversarial test.

### 7. On-disk parsing posture (routed from #103)

Two on-disk records had their `deny_unknown_fields` decision deferred to this
phase:

- `HostConfig` (`config.json`): now `deny_unknown_fields`, with a version field.
  It is written and read only by this binary on one machine, with no
  cross-version coexistence window, so strict parsing costs nothing and refuses
  a tampered or newer file rather than half-reading it.
- `LockFile` (`run.lock`): deliberately stays lenient. It is the one file read
  across binary versions at the same instant: during an upgrade a
  still-installed older build keeps reading a lock a newer broker wrote, and a
  strict parser would take the whole bridge down for the upgrade window if a
  field were ever added. Leniency is safe because the lock file is discovery,
  not authorization: whatever it says, every connection still passes the
  peer-UID check, mutual attestation, and the HMAC handshake, so an unknown
  field can admit nobody. The forward-compat rule is recorded in the type: a
  field may be added only such that old readers stay correct ignoring it; a
  change old readers must not survive gets a new filename (`run.v2.lock`), so an
  old binary sees "no lock" and fails closed to no-bridge rather than misreading.

`revocation.json` and `clients.json` are `deny_unknown_fields` for the same
reason as `HostConfig`: local, single-writer-version, security-relevant.

### 8. Verification

- **loom** model-checks that the sweep registry is empty by the time the
  broker's teardown decision latches, so no relay stream outlives the socket it
  hangs off. This joins the existing ref-count shutdown models.
- **proptest** covers the pure epoch arithmetic (strictly monotonic bumps,
  scope markers that never run ahead of the global counter) and the epoch
  guard's fail-closed matrix (unchanged epoch is a no-op; a changed epoch
  re-decides; only a measured, still-listed identity survives; any read error
  fails closed).
- **adversarial.py** exercises revocation from each surface live: A17
  (`revoke-client` drops a live broker's connection and refuses its re-attach),
  A18 (the extension's `client_revoke` reaches enforcement through the host
  control frames while a still-trusted client keeps serving), A19 (deleting
  `clients.json` alone is detected as tampering and fails closed, while the
  two-file deletion reverts to the logged bootstrap, the named residual).
- **chaos.py** C10 revokes mid-session and asserts the epoch guard drops the
  harness fail-closed and the bridge fully recovers for a re-paired client; C11
  documents the browser-gated SW-death interleaving, covered piecewise by C10,
  the Rust units, and the vitest fakeBrowser suites.
- **e2e.py** proves the `client_list` / `client_revoke` / `enclave_revoke`
  frames are answered by the host and never forwarded over the bridge socket.

## Why these choices

- **Why a change notice and not an authoritative epoch.** If the epoch itself
  granted or denied trust, a same-user writer who can edit the file could grant
  trust by editing it. Keeping the epoch a pure "re-read now" signal means the
  worst a tamperer achieves is a spurious re-check (which re-admits only the
  already-authorized) or a corrupt file (which fails closed). The authority
  stays the allowlist and the keychain, which a tamperer can only reduce.

- **Why inequality, not order, in the guard.** A monotonic counter tempts an
  ordering comparison, but a tamperer can write any value. Comparing for "did
  it change" rather than "did it advance" means a rolled-back file still forces
  a re-decide against the current allowlist, so lowering the number cannot
  suppress a revocation.

- **Why both a per-request guard and an idle watcher.** The guard is immediate
  but only fires when the harness sends something; an attacker's idle
  connection would otherwise linger until its next call. The watcher bounds that
  to the poll interval. Together they cover both the active and the idle
  connection without either being load-bearing alone.

- **Why the genuine host's push is gated on the keychain, not just the file.**
  The revocation file is same-user-writable. If the genuine host pushed on the
  file alone, a hostile process could scribble a bumped `host_key_epoch` and
  make the real host relay a false compromised mark without ever touching the
  key. Grounding the host's push in a keychain-confirmed absent key means the
  genuine host fails the extension closed only when the key is truly gone. This
  does not stop a *substituted* host from sending the frame itself (see the
  residual); it stops the genuine host from being turned into the messenger for
  a forged file.

- **Why the extension's key-deletion request is durable.** MV3 kills the
  service worker every few idle minutes and the native host with it. A
  best-effort send at revoke time would be lost if the port were down. Storing
  the request in the #32 trusted storage and re-sending until acknowledged makes
  the close-the-asymmetry guarantee hold across the service-worker lifecycle,
  and deletion being idempotent means the retries are harmless.

- **Why the latch and not a stronger tamper defense.** A cryptographic seal or
  an out-of-directory marker would still be deletable or forgeable by the same
  user who can delete the allowlist, so it would buy complexity without changing
  the two-file residual. A one-way boolean is the smallest thing that turns the
  common single-file deletion from silently-permissive into loudly-closed,
  which is the honest amount of ground there is to take in user space.

## Consequences

### Positive

- A revocation from any surface (CLI, extension, and a future app through the
  same `core` paths) reaches enforcement and fails closed: a live broker drops
  the revoked harness and refuses its re-attach; a pinned extension flips to
  compromised on a host-key revoke without an opt-in reverify.
- Unpairing from either side leaves no usable credential: the CLI-vs-extension
  asymmetry (each left the other half of the trust alive) is closed.
- Deleting `clients.json` alone is now detected and refused, narrowing the
  ADR-0024 silent-revert residual to the two-file case.
- The on-disk parsing posture is settled and recorded: strict where there is no
  cross-version window, lenient with a documented forward-compat rule where
  coexisting binaries read the same file.

### Negative / accepted

- **The two-file deletion still reverts to bootstrap.** A same-user process that
  deletes both `clients.json` and `revocation.json` reaches the open,
  ERROR-logged bootstrap posture. This is inside the conceded same-user boundary
  (that process can also plant a native-messaging manifest or re-run our binary)
  and cannot be closed in user space; it is pinned by adversarial A19.
- **A compromised-but-allowlisted client stays trusted until revoked.**
  Attestation identifies a binary, not an intention (ADR-0024). The epoch is the
  lever that removes trust once the user decides to; it does not detect that a
  trusted client turned hostile.
- **A substituted host can forge `enclave_revoked` (false-compromised DoS).**
  The host-originated push blocks a malicious *server* from injecting the frame,
  but not a same-user process that substitutes the native-messaging host binary
  or manifest (threat #4's substitution residual). Such a process is the peer on
  the port and can emit `enclave_revoked`, failing a pinned bridge closed until
  the user re-pairs. This is a denial of service against the user's own bridge,
  never a capability grant, and is the same power a same-user attacker already
  has by refusing to answer challenges. The frame cannot be authenticated (a
  revoked key can sign nothing), so this cannot be closed in user space; it is
  named here rather than claimed prevented.
- **Revoke latency is bounded, not instantaneous.** The socket leg is immediate
  (the per-request guard and the host push). The extension's reflection of a
  host-key revoke is bounded to the next service-worker wake, since MV3 can kill
  the worker between the push and its handling; the durable state is what makes
  the bound hold rather than the frame being lost.
- **`revocation.json` is one more security-relevant file** in the runtime
  directory, with the same same-user-writer exposure class as the rest of it,
  and the extension now has more writers to the trust state (#32).
- **The idle-connection watcher polls.** A one-second timer, not an event, so an
  idle revoked connection can persist up to that long; the per-request guard
  covers any connection that is actually being used.

## Implementation pointers

- `crates/core/src/revocation.rs`: `Revocation`, `Scope`, `bump` /
  `bump_locked` / `latch_clients_enrolled_locked`, the epoch proptests.
- `crates/core/src/allowlist.rs`: `Allowlist::revoke` (rewrite + bump in one
  critical section), `Allowlist::pair` (sets the latch), `load_enforced` /
  `apply_latch` (the tamper-evidence matrix), the CLI handlers.
- `crates/core/src/broker.rs`: `EpochGuard` (per-request re-decide),
  `ClientRegistry` + `watch_tick` (idle-connection sweep), the `OwnHarness`
  threading, the loom registry-drain model.
- `crates/core/src/mcp_server.rs`: `admit_own_harness` reads the epoch and
  threads it into the broker.
- `crates/core/src/native_host.rs`: `revoke_host_key`, `admin_client_list` /
  `admin_client_revoke`, `spawn_host_key_revocation_watch`, the host-originated
  `enclave_revoked` push.
- `crates/core/src/protocol.rs`: `EnclaveControl::{EnclaveRevoke, EnclaveRevoked}`,
  `AdminControl`, `classify_nm_frame`, `host_control_type`.
- `crates/core/src/enclave/{cli.rs,config.rs}`: `run_revoke` bumps
  `host_key_epoch`; `HostConfig` is `deny_unknown_fields` + versioned.
- `extension/src/lib/background/`: `clients.ts` (admin request/reply
  correlation), `enrollment.ts` (`handleRevoked`, durable
  `host-revoke-pending`), `enclave-pin.ts` (the durable flag).
- `extension/src/entrypoints/options/TrustedClientsPanel.tsx`: the revoke UI.
- `tests/adversarial.py` A17/A18/A19; `tests/chaos.py` C10/C11;
  `tests/e2e.py::test_admin_control_frames`.
