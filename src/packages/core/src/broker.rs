//! The ref-counted, attested broker and its relay clients.
//!
//! ## Why a broker
//!
//! Before Phase 4 a fresh MCP-server instance supplanted (SIGTERMed) any prior
//! one: only one harness could drive the browser at a time, newest wins. The
//! user asked for concurrent multi-client instead -- Claude Code, Copilot,
//! Codex and others driving the same browser at once. So the first instance to
//! start becomes the **broker**: it owns the 0600 bridge socket and the lock,
//! holds the browser connections in its [`Session`], and multiplexes the tool
//! calls of every attached harness. Later instances do not take it over; they
//! attest it and **attach as relays**, forwarding their harness's JSON-RPC over
//! the authenticated socket. The broker is **ref-counted**: it exits when the
//! last harness (its own plus every relay) detaches, so there is no idle
//! daemon. See ADR-0024.
//!
//! ## Two kinds of attach, one socket
//!
//! Every connection to the broker socket is, as before, gated by the peer-UID
//! check, `attest_peer` (the peer must be our own binary), and the HMAC
//! handshake (ADR-0019/0020). Immediately after the handshake the peer sends
//! one [`AttachRequest`] declaring its role:
//!
//! - [`AttachRequest::Browser`] -- a Chrome-spawned native host. Its browser
//!   label was already MAC-signed in the handshake `Response`, so the browser
//!   leg's authentication is unchanged; it joins the [`Session`] registry.
//! - [`AttachRequest::Client`] -- a sibling MCP-server instance relaying a
//!   harness. It carries the relay's `getppid`-attested parent identity, which
//!   the broker checks against the trusted-client allowlist ([`crate::allowlist`]).
//!
//! ## Trust chain for a relay's harness identity
//!
//! The relay reports its harness's attested hash/Team-ID. The broker trusts
//! that report because the relay connection itself passed `attest_peer`: the
//! relay is a genuine instance of our own binary, which measures its parent
//! honestly via `getppid` and cannot be made to lie about it by a same-user
//! process (that process would not be our binary and would fail `attest_peer`).
//! The self-asserted harness *name* is a log label only; authorization keys on
//! the attested hash/Team-ID, never the name. Residual: `getppid` names who
//! spawned the relay, not who writes its stdin, and the measurement races
//! reparenting/pid-reuse. A later reparent fails admission closed, but pipe fd
//! inheritance means spawner and stdin-writer are not provably the same.
//! Named honestly in ADR-0024; this is not kernel attestation of the pipe.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::allowlist::{self, Decision};
use crate::audit;
use crate::ipc::{self, BridgeStream, BrowserLabel, ClientIdentity};
use crate::protocol::{
    bridge_read, bridge_write, mcp_read, mcp_write, AttachReply, AttachRequest, HarnessId, JsonRpc,
    MCP_MAX_LINE,
};
use crate::revocation::{Revocation, REVOCATION_POLL};
use crate::session::Session;

// ---- DoS limits (generalizing the fail-closed-timeout posture) -------------

/// Maximum number of concurrent harness clients the broker serves (its own
/// stdio harness plus attached relays). Beyond this a relay attach is refused
/// as transiently unavailable, so it retries rather than being denied.
const MAX_HARNESS_CLIENTS: usize = 8;

/// Maximum number of connections simultaneously in the handshake/attach phase.
/// Bounds the fan-out of accept-time work so a flood of half-open connections
/// cannot exhaust threads before any of them is admitted.
const MAX_PENDING_ATTACH: usize = 32;

/// How long a peer has to complete the handshake and send its attach frame. A
/// connection that stalls in this phase is dropped rather than holding a slot
/// forever. Cleared once the peer is admitted, because a steady-state browser
/// or relay connection is legitimately idle for long stretches.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-relay request rate limit: burst capacity and steady refill per second.
/// A relay that exceeds it is dropped (fail closed); it may reconnect. The
/// relay is attested and allowlisted, so this is defense in depth against a
/// compromised harness flooding the shared broker, not the primary control.
const RATE_BURST: f64 = 128.0;
const RATE_REFILL_PER_SEC: f64 = 128.0;

// ---- Ref-count coordinator (loom-checked) ----------------------------------

#[cfg(loom)]
use loom::sync::{Condvar, Mutex};
#[cfg(not(loom))]
use std::sync::{Condvar, Mutex};

/// The broker's harness ref-count and its shutdown gate. Counts live harness
/// clients (the broker's own stdio harness plus attached relays); browser
/// connections are deliberately NOT counted, so the broker outlives any one
/// browser but not the harnesses it serves.
///
/// Correctness is model-checked with `loom` (see the `loom_model` tests): the
/// broker shuts down exactly once the count reaches zero and never while a
/// client is still attached, and a relay that races the shutdown either
/// attaches before the terminal decision or is cleanly refused afterwards.
struct RefCount {
    /// Guarded count + shutdown latch. `terminal` latches once [`wait_zero`]
    /// has observed zero under the lock, after which [`try_acquire`] refuses
    /// so a racing relay cannot revive a broker that has committed to exit.
    ///
    /// [`try_acquire`]: RefCount::try_acquire
    /// [`wait_zero`]: RefCount::wait_zero
    state: Mutex<CountState>,
    reached_zero: Condvar,
    max: usize,
}

/// The ref-count's guarded state, named so the two halves cannot be swapped
/// or misread the way an anonymous `(usize, bool)` tuple could.
struct CountState {
    /// Live harness clients (own stdio harness + relays), each represented by
    /// exactly one outstanding [`HarnessSlot`].
    live: usize,
    /// Latched by [`RefCount::wait_zero`] once it observes zero; refuses all
    /// later acquisitions.
    terminal: bool,
}

/// One live harness client's slot in the broker's [`RefCount`], released on
/// Drop. The ONLY way to increment the count is [`RefCount::try_acquire`], and
/// the only way to decrement it is dropping the returned slot, so an exit path
/// that forgets to release -- or releases twice -- is unrepresentable.
struct HarnessSlot<'a> {
    refcount: &'a RefCount,
}

impl Drop for HarnessSlot<'_> {
    fn drop(&mut self) {
        self.refcount.decr();
    }
}

impl RefCount {
    /// A fresh counter with no live clients. Every client -- including the
    /// broker's own stdio harness -- is counted by acquiring a slot.
    fn new(max: usize) -> Self {
        RefCount {
            state: Mutex::new(CountState {
                live: 0,
                terminal: false,
            }),
            reached_zero: Condvar::new(),
            max,
        }
    }

    /// Try to add a client, returning its slot (released on Drop). Fails
    /// (returns `None`) if the broker is at capacity or has already committed
    /// to shutting down (`terminal`).
    fn try_acquire(&self) -> Option<HarnessSlot<'_>> {
        // A poisoned count is untrustworthy state: refuse the attach (the
        // client redials) rather than admit past an unknowable count.
        let Ok(mut g) = self.state.lock() else {
            return None;
        };
        if g.terminal || g.live >= self.max {
            return None;
        }
        g.live += 1;
        Some(HarnessSlot { refcount: self })
    }

    /// Remove a client (the [`HarnessSlot`] Drop path). Wakes
    /// [`wait_zero`](RefCount::wait_zero) when the count reaches zero.
    fn decr(&self) {
        // Recover from poison rather than skip: failing to release a slot
        // would wedge wait_zero and keep the broker alive forever.
        let mut g = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(g.live > 0, "decr underflow");
        // saturating_sub: a (never-observed) double-release must not wrap the
        // count in release builds and wedge the zero detection forever.
        g.live = g.live.saturating_sub(1);
        if g.live == 0 {
            self.reached_zero.notify_all();
        }
    }

    /// Block until the client count is zero, then latch `terminal` and return.
    /// After this returns, no new client can attach (see
    /// [`try_acquire`](RefCount::try_acquire)), so the caller can tear the
    /// broker down without racing a fresh attach.
    fn wait_zero(&self) {
        // Shutdown path: recover from poison and keep waiting -- refusing here
        // would abandon the terminal latch and let a racing relay revive us.
        let mut g = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while g.live != 0 {
            g = self
                .reached_zero
                .wait(g)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        g.terminal = true;
    }
}

// ---- Rate limiter (per relay) ----------------------------------------------

/// A simple token bucket, one per relay connection (so it needs no locking).
struct RateLimiter {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn new() -> Self {
        RateLimiter {
            tokens: RATE_BURST,
            last: Instant::now(),
        }
    }

    /// Whether one more request is allowed right now, consuming a token.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * RATE_REFILL_PER_SEC).min(RATE_BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ---- Revocation-epoch enforcement (ADR-0025) --------------------------------

// The broker's watcher thread re-reads the revocation epoch every
// `revocation::REVOCATION_POLL`, so a revocation reaches even an IDLE
// connection without waiting for its next request. Requests themselves are
// checked inline (immediately), so that interval only bounds the lifetime of
// an idle revoked connection.

/// Per-connection revocation-epoch guard (ADR-0025). Each admitted harness
/// (the broker's own stdio harness and every relay) carries the epoch it was
/// admitted under; before EVERY dispatched request the guard re-reads the
/// persisted epoch and, on any difference, re-decides admission against the
/// freshly loaded allowlist. Every failure to read either file is fail-closed:
/// the connection is dropped, never served on stale trust.
///
/// This is the immediate, per-request path. For a backstopped relay it
/// short-circuits when the epoch is unchanged, so it does not read the
/// allowlist on every tool call; the broker's [`watch_tick`] watcher is the
/// correctness backstop that drops a revoked relay within a poll interval even
/// while it is idle and even if a revocation's epoch bump failed to persist.
/// The broker's own stdio harness is un-backstopped, so its guard re-decides
/// on every request instead: an idle revoked own harness stays connected (it
/// is driving nothing) but is refused before dispatch on its very next
/// request, with no dependence on the epoch advancing.
struct EpochGuard {
    /// The harness's attested identity, captured at admission. `None` means
    /// it could not be measured (admitted only while unenrolled).
    identity: Option<ClientIdentity>,
    /// The revocation epoch this connection was last (re-)admitted under.
    seen_epoch: u64,
    /// Whether a watcher backstop covers this connection. Relays are in the
    /// [`ClientRegistry`] and swept unconditionally each tick, so their guard
    /// may take the epoch fast path (skip the allowlist read when the epoch is
    /// unchanged). The broker's OWN stdio harness is NOT in the registry (it
    /// serves on stdin/stdout, which has no socket to shut down), so it has no
    /// backstop; its guard must re-decide on EVERY request. Otherwise a
    /// revocation whose epoch bump failed to persist would leave the owning
    /// harness served indefinitely.
    backstopped: bool,
}

/// One admitted peer of a serve loop, bundling the resources its role
/// entitles it to. The role is a single admission-time choice: a relay is
/// rate-limited AND carries a backstopped guard (the watcher sweeps it), the
/// broker's own stdio harness is unlimited AND carries an un-backstopped
/// guard (it re-decides every request). [`serve_jsonrpc`] takes one of these
/// instead of independent limiter/guard/label parameters, so a serve loop
/// with a relay's limiter but the own harness's guard - or any other
/// crossing - is unrepresentable rather than kept coherent by its two call
/// sites.
enum ServedPeer {
    /// The broker's own stdio harness.
    OwnHarness { guard: EpochGuard },
    /// An attached relay client.
    Relay {
        guard: EpochGuard,
        limiter: RateLimiter,
    },
}

impl ServedPeer {
    /// The broker's own stdio harness: un-backstopped guard, no rate limit.
    fn own_harness(own: OwnHarness) -> ServedPeer {
        ServedPeer::OwnHarness {
            guard: EpochGuard {
                identity: own.identity,
                seen_epoch: own.epoch,
                backstopped: false,
            },
        }
    }

    /// An admitted relay: backstopped guard (the watcher sweeps its
    /// registry slot) plus a fresh per-connection rate limiter.
    fn relay(identity: Option<ClientIdentity>, admitted_epoch: u64) -> ServedPeer {
        ServedPeer::Relay {
            guard: EpochGuard {
                identity,
                seen_epoch: admitted_epoch,
                backstopped: true,
            },
            limiter: RateLimiter::new(),
        }
    }

    /// The role's name for logs and the guard's refusal text.
    fn who(&self) -> &'static str {
        match self {
            ServedPeer::OwnHarness { .. } => "the broker's own harness",
            ServedPeer::Relay { .. } => "relay harness",
        }
    }
}

impl EpochGuard {
    /// Enforce the epoch before serving one request. Reads the revocation
    /// record and (for a backstopped connection, only when the epoch moved)
    /// the allowlist from disk.
    fn recheck(&mut self, who: &str) -> io::Result<()> {
        // Read order matters: the revocation record FIRST, then the
        // allowlist. A revocation writes the allowlist and bumps the epoch in
        // one critical section (allowlist first); reading the epoch first
        // means we can never cache a NEW epoch against a STALE list, so a
        // revoke is enforced no later than the first read that observes its
        // bump.
        let rev = Revocation::current();
        self.recheck_with(who, rev, allowlist::load_enforced)
    }

    /// The decision core of [`recheck`](Self::recheck), with the two disk
    /// reads injected so the fail-closed matrix is unit-testable without a
    /// runtime directory.
    fn recheck_with(
        &mut self,
        who: &str,
        rev: io::Result<Revocation>,
        load: impl FnOnce(&Revocation) -> io::Result<Option<allowlist::Allowlist>>,
    ) -> io::Result<()> {
        let rev = rev.map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("revocation record unreadable ({e}); failing closed"),
            )
        })?;
        // A backstopped connection may skip the allowlist read on an unchanged
        // epoch (the watcher covers a stuck epoch). An un-backstopped one (the
        // own harness) always re-decides, so a failed epoch bump cannot leave
        // it served.
        if self.backstopped && rev.epoch == self.seen_epoch {
            return Ok(());
        }
        let list = load(&rev).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("allowlist unreadable after an epoch bump ({e}); failing closed"),
            )
        })?;
        match allowlist::decide(list.as_ref(), self.identity.as_ref()) {
            Decision::Refuse => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{who} was revoked (epoch {} -> {})",
                    self.seen_epoch, rev.epoch
                ),
            )),
            Decision::Admit { name } => {
                log_info!(
                    "broker",
                    "{who} re-admitted as trusted client '{name}' after epoch bump ({} -> {})",
                    self.seen_epoch,
                    rev.epoch
                );
                self.seen_epoch = rev.epoch;
                Ok(())
            }
            Decision::AdmitUnenrolled => {
                // Still the (loudly logged at startup) unenrolled posture.
                self.seen_epoch = rev.epoch;
                Ok(())
            }
        }
    }
}

/// The broker's registry of live RELAY connections, so a revocation can reach
/// an idle connection: the watcher thread sweeps it on every epoch bump and
/// shuts down the socket of any harness the fresh allowlist refuses, which
/// ends that relay's serve loop (its own [`EpochGuard`] would equally refuse
/// its next request; the sweep covers the no-request case). Slots are removed
/// only by their [`RegistrySlot`] guard's Drop (held by the serve worker) --
/// the sweep never removes, so occupancy bookkeeping stays in exactly one
/// place, and by construction rather than by convention.
struct ClientRegistry {
    slots: Mutex<RegistryInner>,
}

struct RegistryInner {
    next_id: u64,
    clients: HashMap<u64, RegisteredClient>,
}

struct RegisteredClient {
    identity: Option<ClientIdentity>,
    /// A clone of the connection's stream, held only to `shutdown()` it.
    stream: BridgeStream,
}

/// Occupancy of one [`ClientRegistry`] slot, released (deregistered) on Drop.
/// The ONLY way to occupy a slot is [`ClientRegistry::register`], and the only
/// way to release it is dropping the returned guard, so no exit path --
/// rejection, serve-loop end, or an early return added later -- can leak one.
/// `deregister` recovers from poison, so the Drop never unwinds.
struct RegistrySlot<'a> {
    registry: &'a ClientRegistry,
    id: u64,
}

impl Drop for RegistrySlot<'_> {
    fn drop(&mut self) {
        self.registry.deregister(self.id);
    }
}

impl ClientRegistry {
    fn new() -> Self {
        ClientRegistry {
            slots: Mutex::new(RegistryInner {
                next_id: 1,
                clients: HashMap::new(),
            }),
        }
    }

    fn register(
        &self,
        identity: Option<ClientIdentity>,
        stream: BridgeStream,
    ) -> Option<RegistrySlot<'_>> {
        // Refuse on poison: this registry is the kill switch's reach, and the
        // thread most likely to have poisoned it is the sweep watcher itself.
        // Admitting a relay the (possibly dead) sweeper can never sever would
        // be fail-open; the caller rejects the connection instead.
        let Ok(mut inner) = self.slots.lock() else {
            return None;
        };
        let id = inner.next_id;
        inner.next_id += 1;
        inner
            .clients
            .insert(id, RegisteredClient { identity, stream });
        Some(RegistrySlot { registry: self, id })
    }

    /// Release path, called only by [`RegistrySlot`]'s Drop.
    fn deregister(&self, id: u64) {
        // Recover from poison so slots cannot leak.
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clients
            .remove(&id);
    }

    /// Shut down every registered relay whose identity `refuse` matches.
    /// Returns how many connections were dropped.
    fn sweep(&self, refuse: impl Fn(Option<&ClientIdentity>) -> bool) -> usize {
        // The kill switch must bite even after a panic poisoned the registry:
        // severing sockets is safe on inconsistent bookkeeping, whereas
        // refusing to sever would leave clients attached.
        let inner = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut dropped = 0;
        for client in inner.clients.values() {
            if refuse(client.identity.as_ref()) {
                let _ = client.stream.shutdown(std::net::Shutdown::Both);
                dropped += 1;
            }
        }
        dropped
    }
}

/// The watcher loop body: re-decide every live relay against the current
/// allowlist, once per tick, and enforce the kill switch on the browser leg
/// (ADR-0030). Factored from the polling thread so the fail-closed matrix is
/// testable. `drop_browsers` severs every live browser connection (the
/// session's kill sweep); it is invoked while the switch is engaged and when
/// the revocation record is unreadable (kill state unknown), and is idempotent
/// so calling it every tick is harmless. Returns the epoch observed (used only
/// to deduplicate the "dropped N" log line across ticks), or `None` when a
/// read failed (so the caller does not advance its logging cursor).
///
/// The re-decide is **unconditional**, not gated on an epoch change. The epoch
/// is a promptness signal for the per-request [`EpochGuard`] fast path, not the
/// thing enforcement depends on: a revocation whose epoch bump failed to
/// persist (a disk-full or rename error) would leave the counter stale, and if
/// the watcher only swept on an epoch change it would then serve the revoked
/// client indefinitely. Sweeping the allowlist every tick makes correctness
/// depend on the authoritative `clients.json`, which the revocation already
/// rewrote, and bounds a stale-epoch exposure to one poll interval. The
/// allowlist is a small local file; reading it once a second is negligible.
/// (The kill flag needs no such backstop: it lives IN the epoch's record and
/// is written atomically with the bump, so it cannot go stale independently --
/// but the sweep still runs it unconditionally, symmetry being cheaper than
/// an argument.)
fn watch_tick(
    registry: &ClientRegistry,
    last_seen: u64,
    rev: io::Result<Revocation>,
    load: impl FnOnce(&Revocation) -> io::Result<Option<allowlist::Allowlist>>,
    drop_browsers: impl FnOnce() -> usize,
) -> Option<u64> {
    let rev = match rev {
        Ok(rev) => rev,
        Err(e) => {
            // Fail closed: with the revocation record unreadable, no relay's
            // admission can be re-validated (the enrollment latch that governs
            // an absent allowlist is unknown) and the kill state is unknowable,
            // so neither the relays nor the browser leg may keep a connection.
            let dropped = registry.sweep(|_| true);
            let browsers = drop_browsers();
            if dropped > 0 || browsers > 0 {
                log_error!(
                    "broker",
                    "revocation record unreadable ({e}); dropped {dropped} relay and \
                     {browsers} browser connection(s) (fail closed)"
                );
            }
            return None;
        }
    };
    if rev.killed {
        let browsers = drop_browsers();
        if browsers > 0 {
            log_error!(
                "broker",
                "kill switch engaged (epoch {}); severed {browsers} browser connection(s)",
                rev.epoch
            );
        }
    }
    match load(&rev) {
        Ok(list) => {
            let dropped = registry.sweep(|identity| {
                matches!(allowlist::decide(list.as_ref(), identity), Decision::Refuse)
            });
            // Log only when something was dropped AND the epoch moved since the
            // last drop, so a steady state (nobody to drop) and a stuck-epoch
            // sweep do not spam the log every second.
            if dropped > 0 && rev.epoch != last_seen {
                log_info!(
                    "broker",
                    "revocation epoch {}; dropped {dropped} revoked relay connection(s)",
                    rev.epoch
                );
            }
            Some(rev.epoch)
        }
        Err(e) => {
            let dropped = registry.sweep(|_| true);
            if dropped > 0 {
                log_error!(
                    "broker",
                    "allowlist unreadable ({e}); dropped {dropped} relay connection(s) \
                     (fail closed)"
                );
            }
            None
        }
    }
}

// ---- Broker ----------------------------------------------------------------

struct Broker {
    session: Session,
    refcount: RefCount,
    /// Connections currently in the handshake/attach phase, bounding accept-time
    /// fan-out ([`MAX_PENDING_ATTACH`]).
    pending: AtomicUsize,
    /// Live relay connections, swept on revocation-epoch bumps (ADR-0025).
    registry: ClientRegistry,
}

/// An admitted relay's two resources, bundled so releasing one without the
/// other is unrepresentable. Field order is load-bearing: struct fields drop
/// in declaration order, so the registry slot is deregistered BEFORE the
/// ref-count decrements -- the order the loom model
/// `registry_is_empty_once_the_shutdown_decision_latches` checks (a slot must
/// never survive the terminal shutdown decision).
struct RelayAdmission<'a> {
    /// Drops first: deregister from the revocation-sweep registry.
    _slot: RegistrySlot<'a>,
    /// Drops second: release the harness ref-count.
    _harness: HarnessSlot<'a>,
}

/// One slot in the broker's pending-attach bound ([`MAX_PENDING_ATTACH`]),
/// released on Drop. Owns an `Arc<Broker>` so it can move into the
/// per-connection worker thread; the acquire and the release are one type, so
/// a worker path that forgets the release is unrepresentable.
struct PendingSlot {
    broker: Arc<Broker>,
}

impl PendingSlot {
    /// Claim a handshake-phase slot, or `None` (count already restored) when
    /// [`MAX_PENDING_ATTACH`] connections are mid-handshake.
    fn try_acquire(broker: &Arc<Broker>) -> Option<PendingSlot> {
        let n = broker.pending.fetch_add(1, Ordering::SeqCst);
        if n >= MAX_PENDING_ATTACH {
            broker.pending.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(PendingSlot {
            broker: Arc::clone(broker),
        })
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        self.broker.pending.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The outcome of the handshake + attach handshake for one connection.
enum Admitted<'a> {
    /// A browser native host, ready to join the session registry. The label
    /// is a [`BrowserLabel`]: validated in the handshake, by construction.
    Browser {
        label: BrowserLabel,
        reader: BufReader<BridgeStream>,
        writer: BufWriter<BridgeStream>,
    },
    /// An admitted relay client. Its ref-count slot and revocation-sweep
    /// registry slot live in `admission`, released (in the load-bearing
    /// order) when it drops after the serve loop ends.
    Client {
        reader: BufReader<BridgeStream>,
        writer: BufWriter<BridgeStream>,
        /// The relay role's serve-loop resources: per-request revocation
        /// epoch guard (ADR-0025) plus its rate limiter, bundled by
        /// [`ServedPeer::relay`] so the role cannot be re-assembled wrong.
        peer: ServedPeer,
        /// This connection's registry + ref-count occupancy (RAII).
        admission: RelayAdmission<'a>,
    },
    /// Rejected (refused, unavailable, or a failed handshake): nothing to do --
    /// any partially acquired resources were released by their guards' Drop.
    Rejected,
}

/// The broker's own stdio harness, as admitted by
/// [`crate::mcp_server::admit_own_harness`]: the identity it was admitted on
/// and the revocation epoch it was admitted under (ADR-0025).
pub(crate) struct OwnHarness {
    pub identity: Option<ClientIdentity>,
    pub epoch: u64,
}

/// Run as the broker: own the accepted socket, serve this instance's own stdio
/// harness, accept browser and relay attaches, and exit when the last harness
/// detaches. Returns the process exit code.
pub(crate) fn run_broker(listener: ipc::BridgeListener, session: Session, own: OwnHarness) -> i32 {
    let broker = Arc::new(Broker {
        session,
        refcount: RefCount::new(MAX_HARNESS_CLIENTS),
        pending: AtomicUsize::new(0),
        registry: ClientRegistry::new(),
    });

    // The broker's own stdio harness is the first client; its slot is held
    // until stdin EOF below, so the count drops to zero only once this harness
    // AND every relay is gone. Acquiring from a fresh, non-terminal counter
    // cannot fail, but the no-panic lint set forbids unwrap/expect: fail
    // closed rather than serve uncounted.
    let Some(own_slot) = broker.refcount.try_acquire() else {
        log_error!(
            "broker",
            "could not reserve the own-harness ref-count slot; refusing to serve"
        );
        ipc::LockFile::remove_if_owned();
        return 1;
    };

    // Watch the revocation epoch so a revoke reaches IDLE relay connections
    // too (requests are guarded inline), and so a kill severs the browser leg
    // within a tick even when nobody is calling (ADR-0030). The thread dies
    // with the process.
    {
        let broker = Arc::clone(&broker);
        let mut last_seen = own.epoch;
        thread::spawn(move || loop {
            thread::sleep(REVOCATION_POLL);
            if let Some(seen) = watch_tick(
                &broker.registry,
                last_seen,
                Revocation::current(),
                allowlist::load_enforced,
                || broker.session.shutdown_all_browsers(),
            ) {
                last_seen = seen;
            }
        });
    }

    // Accept browser and relay connections off the main thread.
    {
        let broker = Arc::clone(&broker);
        thread::spawn(move || accept_loop(&broker, listener));
    }

    // Serve THIS instance's own harness on stdin/stdout, exactly as the server
    // did before: read JSON-RPC, dispatch against the shared session, respond.
    // Its epoch guard covers the broker's own harness: if it is revoked, the
    // serve loop ends (its harness sees EOF and a respawned instance is
    // refused at admission) while attached relays keep being served until
    // they detach. The role - un-backstopped guard, no rate limit - is one
    // constructor call, so it cannot be assembled crossed.
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let mut peer = ServedPeer::own_harness(own);
    let _ = serve_jsonrpc(&broker.session, &mut reader, &mut writer, &mut peer);

    // Own harness gone (stdin EOF). Release our slot, then wait until every
    // relay has also detached before tearing down the socket/lock. If relays
    // are still attached, the broker keeps serving them; it exits only when
    // the last one leaves.
    drop(own_slot);
    broker.refcount.wait_zero();
    ipc::LockFile::remove_if_owned();
    0
}

/// Accept loop: bound the handshake fan-out, then hand each connection to a
/// worker that authenticates it, learns its role, and serves it.
fn accept_loop(broker: &Arc<Broker>, listener: ipc::BridgeListener) {
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // Bound the number of connections simultaneously mid-handshake.
                let Some(pending_slot) = PendingSlot::try_acquire(broker) else {
                    log_warn!("broker", "too many pending attaches; dropping a connection");
                    continue;
                };
                let broker = Arc::clone(broker);
                thread::spawn(move || {
                    let outcome = admit(&broker, stream);
                    // The handshake phase is over; free its slot before any
                    // long-lived serve so pending only bounds handshakes.
                    drop(pending_slot);
                    match outcome {
                        Admitted::Browser {
                            label,
                            reader,
                            writer,
                        } => {
                            // attach_browser enforces the distinct-browser cap
                            // atomically and spawns its own reader thread on
                            // success; this worker then ends. A `false` return
                            // means the cap was reached and the connection was
                            // dropped (the native host reconnects).
                            if !broker.session.attach_browser(label, reader, writer) {
                                log_warn!(
                                    "broker",
                                    "browser cap reached; dropped an attach (it will reconnect)"
                                );
                            }
                        }
                        Admitted::Client {
                            mut reader,
                            mut writer,
                            mut peer,
                            admission,
                        } => {
                            let _ =
                                serve_jsonrpc(&broker.session, &mut reader, &mut writer, &mut peer);
                            // Explicit, not left to scope end: the admission
                            // guard deregisters BEFORE it decrements (its
                            // field order), and dropping it here keeps that
                            // release tied to the serve loop's end rather
                            // than to whatever else this scope grows later.
                            drop(admission);
                        }
                        Admitted::Rejected => {}
                    }
                });
            }
            Err(e) => {
                log_error!("broker", "accept failed: {e}");
                break;
            }
        }
    }
}

/// Authenticate one accepted connection (peer-UID, `attest_peer`, HMAC
/// handshake), read its mandatory [`AttachRequest`], apply admission + DoS
/// caps, send an [`AttachReply`], and return what to do with it. Every failure
/// path is fail-closed: the connection is dropped and [`Admitted::Rejected`]
/// returned.
fn admit(broker: &Broker, stream: BridgeStream) -> Admitted<'_> {
    // Single chokepoint: reject any peer that is not this same user, before
    // authentication (as the accept loop did previously). Unix only.
    #[cfg(unix)]
    {
        let want = crate::sys::effective_uid();
        match ipc::peer_uid(&stream) {
            Ok(uid) if uid == want => {}
            Ok(uid) => {
                log_warn!(
                    "broker",
                    "rejected bridge connection from uid {uid} (broker euid {want})"
                );
                audit::record(
                    audit::AuditRecord::new(audit::AuditKind::AttachRefuse)
                        .surface(audit::Surface::Broker)
                        .outcome("refused")
                        .detail("peer uid mismatch"),
                );
                return Admitted::Rejected;
            }
            Err(e) => {
                log_warn!(
                    "broker",
                    "rejected bridge connection: peer uid unknown: {e}"
                );
                audit::record(
                    audit::AuditRecord::new(audit::AuditKind::AttachRefuse)
                        .surface(audit::Surface::Broker)
                        .outcome("refused")
                        .detail("peer uid unknown"),
                );
                return Admitted::Rejected;
            }
        }
    }
    // Kernel-attest the peer's executable identity: only another instance of
    // THIS binary may attach at all (a native host or a sibling relay). A
    // different same-user program is rejected here, before the HMAC handshake.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if let Err(e) = ipc::attest_peer(&stream) {
            log_warn!("broker", "rejected bridge connection: {e}");
            audit::record(
                audit::AuditRecord::new(audit::AuditKind::AttachRefuse)
                    .surface(audit::Surface::Broker)
                    .outcome("refused")
                    .detail("peer attestation failed"),
            );
            return Admitted::Rejected;
        }
    }

    // Bound the handshake + attach phase with a read timeout so a peer that
    // connects and stalls cannot hold a pending slot indefinitely. Cleared
    // before steady-state serving (idle connections are legitimate there).
    let _ = stream.set_read_timeout(Some(ATTACH_TIMEOUT));

    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log_warn!("broker", "clone stream: {e}");
            return Admitted::Rejected;
        }
    };
    let mut reader = BufReader::new(reader_stream);
    let mut writer = BufWriter::new(stream);

    // HMAC challenge-response over the buffered halves the session then reuses.
    let label = match ipc::server_handshake(&mut reader, &mut writer) {
        Ok(label) => label,
        Err(e) => {
            log_warn!(
                "broker",
                "rejected bridge connection: handshake failed: {e}"
            );
            audit::record(
                audit::AuditRecord::new(audit::AuditKind::AttachRefuse)
                    .surface(audit::Surface::Broker)
                    .outcome("refused")
                    .detail("handshake failed"),
            );
            return Admitted::Rejected;
        }
    };

    // Mandatory role declaration. EOF or a malformed frame fails closed.
    let attach: AttachRequest = match bridge_read(&mut reader) {
        Ok(Some(a)) => a,
        Ok(None) => {
            log_warn!("broker", "connection closed before it declared a role");
            return Admitted::Rejected;
        }
        Err(e) => {
            log_warn!(
                "broker",
                "rejected bridge connection: bad attach frame: {e}"
            );
            return Admitted::Rejected;
        }
    };

    match attach {
        AttachRequest::Browser {} => admit_browser(label, reader, writer),
        AttachRequest::Client { harness } => admit_client(broker, harness, reader, writer),
    }
}

fn admit_browser(
    label: Option<BrowserLabel>,
    reader: BufReader<BridgeStream>,
    mut writer: BufWriter<BridgeStream>,
) -> Admitted<'static> {
    let label = label.unwrap_or_else(BrowserLabel::default_label);
    // The kill switch severs the browser leg entirely (ADR-0030): while it is
    // engaged -- or its state cannot be read -- no browser attach is accepted,
    // so no path to a browser exists even if a dispatch check were bypassed.
    // The refused native host exits; the extension's reconnect finds a
    // control-plane-only host that keeps the unkill surface reachable.
    if let Err(e) = crate::kill::check() {
        let _ = bridge_write(
            &mut writer,
            &AttachReply::Refused {
                reason: "bridge kill switch engaged".into(),
            },
        );
        log_warn!("broker", "refused browser attach ('{label}'): {e}");
        audit::record(
            audit::AuditRecord::new(audit::AuditKind::BrowserRefuse)
                .surface(audit::Surface::Broker)
                .name(label.as_str())
                .outcome("refused")
                .detail(e.code()),
        );
        return Admitted::Rejected;
    }
    // The distinct-browser cap ([`Session::attach_browser`], MAX_BROWSERS) is
    // the sole, atomic authority: it is checked under the same lock that
    // inserts, so no pre-check here can race it. We accept optimistically; if a
    // browser loses the cap race at insert time it is dropped and reconnects
    // (a benign, self-healing degradation only reachable at a pathological
    // browser count). See the note on `attach_browser`.
    if bridge_write(&mut writer, &AttachReply::Accepted {}).is_err() {
        return Admitted::Rejected;
    }
    audit::record(
        audit::AuditRecord::new(audit::AuditKind::BrowserAttach)
            .surface(audit::Surface::Broker)
            .name(label.as_str())
            .outcome("ok"),
    );
    // Steady state: an idle browser connection is normal, so clear the timeout.
    clear_read_timeout(&writer);
    Admitted::Browser {
        label,
        reader,
        writer,
    }
}

fn admit_client<'a>(
    broker: &'a Broker,
    harness: Option<HarnessId>,
    reader: BufReader<BridgeStream>,
    mut writer: BufWriter<BridgeStream>,
) -> Admitted<'a> {
    let identity = harness.as_ref().map(ClientIdentity::from);

    // Register for revocation sweeps BEFORE deciding admission, so an epoch
    // bump can never land in a decide->register window where the sweep would
    // miss this connection and then consider its epoch already handled. The
    // returned slot deregisters on Drop, so every rejection path below
    // releases it by construction.
    let sweep_handle = match writer.get_ref().try_clone() {
        Ok(s) => s,
        Err(e) => {
            log_warn!("broker", "clone stream for the revocation registry: {e}");
            return Admitted::Rejected;
        }
    };
    let Some(slot) = broker.registry.register(identity.clone(), sweep_handle) else {
        log_warn!(
            "broker",
            "revocation registry unavailable (poisoned); refusing relay"
        );
        return Admitted::Rejected;
    };
    // Reply-and-log refusal helper; resource release is the guards' Drop.
    fn reject_relay(
        writer: &mut BufWriter<BridgeStream>,
        reason: &str,
        reply: Option<AttachReply>,
    ) -> Admitted<'static> {
        if let Some(reply) = reply {
            let _ = bridge_write(writer, &reply);
        }
        log_warn!("broker", "refused relay: {reason}");
        Admitted::Rejected
    }

    // Admission decision (ADR-0024/0025). Read order is load-bearing: the
    // revocation record FIRST, then the allowlist -- a revocation writes the
    // allowlist and then bumps the epoch, so this order can never pair a new
    // epoch with a stale list. Failures to read either are fail-closed.
    let rev = match Revocation::current() {
        Ok(rev) => rev,
        Err(e) => {
            return reject_relay(
                &mut writer,
                &format!("cannot read the revocation record: {e}"),
                Some(AttachReply::Refused {
                    reason: "revocation record unreadable".into(),
                }),
            );
        }
    };
    let list = match allowlist::load_enforced(&rev) {
        Ok(l) => l,
        Err(e) => {
            return reject_relay(
                &mut writer,
                &format!("cannot read the allowlist: {e}"),
                Some(AttachReply::Refused {
                    reason: "allowlist unreadable".into(),
                }),
            );
        }
    };
    // The relay-reported harness name is a self-asserted label, never used for
    // authorization. Re-validate it at this trust boundary before it reaches a
    // log line: no log-injection path is reachable today (bridge_read frames
    // are single NDJSON lines and log_* escape), but validate at every boundary
    // rather than trust the peer's string. A malformed name is dropped to "-".
    let reported_name = harness
        .as_ref()
        .and_then(|h| h.name.as_deref())
        .filter(|n| ipc::validate_label(n))
        .map(str::to_string);
    match allowlist::decide(list.as_ref(), identity.as_ref()) {
        Decision::Refuse => {
            audit::record(
                audit::AuditRecord::new(audit::AuditKind::HarnessRefuse)
                    .surface(audit::Surface::Broker)
                    .name(reported_name.as_deref().unwrap_or("-"))
                    .outcome("refused")
                    .detail("not in the trusted-client allowlist"),
            );
            return reject_relay(
                &mut writer,
                &format!(
                    "harness (name {:?}) is not in the trusted-client allowlist",
                    reported_name.as_deref().unwrap_or("-")
                ),
                Some(AttachReply::Refused {
                    reason: "harness not in trusted-client allowlist".into(),
                }),
            );
        }
        Decision::AdmitUnenrolled => {
            log_error!(
                "broker",
                "SECURITY: relay admitted WITHOUT harness attestation -- no trusted-client \
                 allowlist exists yet (unenrolled). Any same-user process that runs our binary \
                 can drive the browser through this relay. Run `chromium-bridge pair-client` to \
                 enroll trusted clients and turn on enforcement. See SECURITY.md."
            );
            audit::record(
                audit::AuditRecord::new(audit::AuditKind::HarnessAdmit)
                    .surface(audit::Surface::Broker)
                    .name(reported_name.as_deref().unwrap_or("-"))
                    .outcome("unenrolled"),
            );
        }
        Decision::Admit { name } => {
            log_info!("broker", "relay admitted for trusted client '{name}'");
            audit::record(
                audit::AuditRecord::new(audit::AuditKind::HarnessAdmit)
                    .surface(audit::Surface::Broker)
                    .name(&name)
                    .outcome("ok"),
            );
        }
    }

    // Capacity + terminal check. Refuse-as-unavailable (retryable) rather than
    // deny, so a relay that lost the race to a shutting-down or full broker
    // retries instead of failing the user's session.
    let Some(harness_slot) = broker.refcount.try_acquire() else {
        return reject_relay(
            &mut writer,
            "broker at capacity or shutting down",
            Some(AttachReply::Unavailable {
                reason: "broker at capacity or shutting down".into(),
            }),
        );
    };
    // Bundle the two slots BEFORE the accept write, so from here on every
    // path -- including the write failure below -- releases them together
    // and in the load-bearing deregister-before-decr order.
    let admission = RelayAdmission {
        _slot: slot,
        _harness: harness_slot,
    };
    if bridge_write(&mut writer, &AttachReply::Accepted {}).is_err() {
        return Admitted::Rejected;
    }
    clear_read_timeout(&writer);
    Admitted::Client {
        reader,
        writer,
        // The relay role in one constructor: backstopped guard (the watcher
        // sweeps this connection's registry slot) plus its rate limiter.
        peer: ServedPeer::relay(identity, rev.epoch),
        admission,
    }
}

/// Clear a bridge stream's read timeout (set during the attach phase) for
/// steady-state serving, where an idle connection is legitimate. Best-effort:
/// a failure here only means the attach timeout lingers, which is harmless.
fn clear_read_timeout(writer: &BufWriter<BridgeStream>) {
    let _ = writer.get_ref().set_read_timeout(None);
}

/// Serve a JSON-RPC stream (this instance's own stdin, or a relay's socket)
/// against the shared session: read a message, dispatch it, write the response.
/// Mirrors the pre-Phase-4 stdin loop (a parse error yields a `-32700` and the
/// loop continues; EOF ends it). `peer` bundles the role's resources
/// ([`ServedPeer`]): a relay is rate-limited - a request over the per-relay
/// limit drops the connection (fail closed) - and the own harness is not.
/// Before EVERY dispatched request, the peer's guard re-checks the revocation
/// epoch (ADR-0025): a revoked harness - or an unreadable revocation record or
/// allowlist - ends the loop, fail closed, so no request is ever served on
/// stale trust.
fn serve_jsonrpc<R: BufRead, W: Write>(
    session: &Session,
    reader: &mut R,
    writer: &mut W,
    peer: &mut ServedPeer,
) -> io::Result<()> {
    let who = peer.who();
    loop {
        let msg = match mcp_read(reader) {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(()), // EOF
            Err(e) => {
                // A read error that is NOT a clean parse failure (an over-cap
                // line, an I/O error) ends the loop, fail closed.
                if e.kind() != io::ErrorKind::InvalidData {
                    return Err(e);
                }
                log_warn!("broker", "stdin/relay parse error: {e}");
                let err =
                    JsonRpc::err(serde_json::Value::Null, -32700, format!("parse error: {e}"));
                mcp_write(writer, &err)?;
                continue;
            }
        };
        // The rate limit is the relay role's resource, carried on its
        // variant; the own harness structurally has none to consult. Checked
        // before the (costlier) revocation re-decide.
        let guard = match peer {
            ServedPeer::OwnHarness { guard } => guard,
            ServedPeer::Relay { guard, limiter } => {
                if !limiter.allow() {
                    log_warn!(
                        "broker",
                        "relay exceeded its request rate limit; dropping it"
                    );
                    return Err(io::Error::other("relay rate limit exceeded"));
                }
                guard
            }
        };
        // Revocation-epoch enforcement, before any dispatch. Fail closed:
        // drop the connection.
        if let Err(e) = guard.recheck(who) {
            log_error!("broker", "dropping {who}: {e}");
            return Err(e);
        }
        if let Some(resp) = crate::mcp_server::handle(session, &msg) {
            mcp_write(writer, &resp)?;
        }
    }
}

// ---- Relay client ----------------------------------------------------------

/// What running as a relay produced, so the caller can decide whether to retry
/// becoming the broker or fail closed. (There is no "served" variant: once the
/// relay is attached and pumping, it ends by exiting the process directly -- see
/// the end of [`run_relay`] -- so it never returns in that case.)
pub(crate) enum RelayOutcome {
    /// The broker was unreachable or transiently unavailable (capacity /
    /// shutting down): the caller should retry (it may become the broker now).
    Retry,
    /// The broker denied admission (allowlist): fail closed, exit non-zero.
    Denied,
}

/// Run as a relay: dial the broker's socket, attest it, authenticate, declare a
/// [`AttachRequest::Client`] with our attested harness identity, and -- if
/// accepted -- pipe this harness's JSON-RPC to the broker and its responses
/// back. A dumb byte pipe over the authenticated socket, mirroring the native
/// host's stdin<->socket pumps.
pub(crate) fn run_relay(harness: Option<HarnessId>) -> RelayOutcome {
    let stream = match ipc::connect() {
        Ok(s) => s,
        Err(e) => {
            log_info!("relay", "broker socket unreachable ({e}); will retry");
            return RelayOutcome::Retry;
        }
    };
    // Attest the broker: it must be another instance of THIS binary before we
    // speak the handshake or forward a frame. Fail closed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if let Err(e) = ipc::attest_peer(&stream) {
            log_error!("relay", "broker attestation failed: {e}");
            return RelayOutcome::Denied;
        }
    }

    let read_half = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log_error!("relay", "clone stream: {e}");
            return RelayOutcome::Retry;
        }
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(stream);

    // A relay fronts no browser, so it carries no browser label.
    if let Err(e) = ipc::client_handshake(&mut reader, &mut writer, None) {
        log_warn!("relay", "bridge handshake failed: {e}");
        return RelayOutcome::Retry;
    }
    if let Err(e) = bridge_write(&mut writer, &AttachRequest::Client { harness }) {
        log_warn!("relay", "attach write failed: {e}");
        return RelayOutcome::Retry;
    }
    match bridge_read::<_, AttachReply>(&mut reader) {
        Ok(Some(AttachReply::Accepted {})) => {}
        Ok(Some(AttachReply::Refused { reason })) => {
            log_error!("relay", "broker refused this client: {reason}");
            return RelayOutcome::Denied;
        }
        Ok(Some(AttachReply::Unavailable { reason })) => {
            log_info!("relay", "broker unavailable ({reason}); will retry");
            return RelayOutcome::Retry;
        }
        Ok(None) | Err(_) => {
            log_info!("relay", "broker closed before accepting; will retry");
            return RelayOutcome::Retry;
        }
    }
    log_info!(
        "relay",
        "attached to broker; relaying this harness's tool calls"
    );

    // Two pumps, mirroring the native host: whichever direction ends first
    // ends the process, so a broken leg cannot leave a half-open relay.
    let out_writer = writer;
    thread::spawn(move || {
        let mut stdin = BufReader::new(io::stdin());
        let mut sock = out_writer;
        let _ = pump_lines(&mut stdin, &mut sock, MCP_MAX_LINE);
        // stdin EOF (harness gone) or a write error: this relay is done.
        std::process::exit(0);
    });

    let mut stdout = BufWriter::new(io::stdout());
    let _ = pump_lines(&mut reader, &mut stdout, MCP_MAX_LINE);
    // The broker closed our connection (it exited, or dropped us). End the
    // process immediately rather than joining the still-blocked stdin pump:
    // that pump is parked in a blocking read of the harness's stdin, which may
    // stay open indefinitely, so joining it would wedge the relay. Exiting
    // closes the harness's view of its server, and the harness respawns a fresh
    // instance that becomes the new broker (the old socket/lock are gone) or a
    // relay. Mirrors the native host's "whichever leg ends first ends the
    // process" shutdown. process::exit runs no destructors, but every writer
    // flushes per line, so nothing buffered is lost.
    std::process::exit(0);
}

/// Copy NDJSON lines from `reader` to `writer`, each line bounded by `cap`
/// bytes (an over-cap line fails closed rather than buffering unbounded). A
/// dumb, fidelity-preserving byte pipe: the relay does not parse the harness's
/// JSON, so no field is dropped in transit (the broker is the single JSON-RPC
/// brain). Returns on EOF.
fn pump_lines<R: BufRead, W: Write>(reader: &mut R, writer: &mut W, cap: usize) -> io::Result<()> {
    loop {
        let mut line = Vec::new();
        let n =
            std::io::Read::take(reader.by_ref(), cap as u64 + 1).read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(());
        }
        if line.len() > cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "line exceeds the length cap",
            ));
        }
        writer.write_all(&line)?;
        writer.flush()?;
    }
}

// Two cfg attributes rather than cfg(all(test, not(loom))): the meaning is
// identical, and the bare #[cfg(test)] is what lets clippy's
// allow-unwrap-in-tests recognize the module's helper fns as test code.
#[cfg(test)]
#[cfg(not(loom))]
mod tests {
    use super::*;

    fn rev(epoch: u64, latched: bool) -> Revocation {
        Revocation {
            version: 1,
            epoch,
            clients_epoch: 0,
            host_key_epoch: 0,
            clients_enrolled: latched,
            killed: false,
            kill_epoch: 0,
        }
    }

    // Only the Unix-gated registry tests exercise the kill sweep (they need
    // UnixStream pairs), so this helper is cfg-gated with them.
    #[cfg(unix)]
    fn killed_rev(epoch: u64) -> Revocation {
        Revocation {
            killed: true,
            kill_epoch: epoch,
            ..rev(epoch, true)
        }
    }

    fn ident(hash: &str) -> ClientIdentity {
        ClientIdentity {
            hash: hash.into(),
            team_id: None,
        }
    }

    // Hash anchors are validated lowercase hex (allowlist::HashDigest), so
    // the fixtures use hex stand-ins; the names say the role each plays.
    const H_SELF: &str = "aa11";
    const H_OTHER: &str = "bb22";
    #[cfg(unix)]
    const H_KEEP: &str = "cafe";
    #[cfg(unix)]
    const H_REVOKED: &str = "dead";

    fn list_with(hash: &str) -> allowlist::Allowlist {
        allowlist::Allowlist {
            version: 1,
            clients: vec![allowlist::ClientEntry {
                name: "c".into(),
                anchor: allowlist::Anchor::Hash(hash.try_into().unwrap()),
                added_unix: 0,
            }],
        }
    }

    #[test]
    fn epoch_guard_is_a_noop_while_the_epoch_is_unchanged() {
        // A backstopped (relay) guard takes the epoch fast path.
        let mut g = EpochGuard {
            identity: Some(ident(H_SELF)),
            seen_epoch: 3,
            backstopped: true,
        };
        // The allowlist loader must not even run when the epoch matches.
        g.recheck_with("t", Ok(rev(3, true)), |_| {
            panic!("allowlist loaded despite an unchanged epoch")
        })
        .unwrap();
        assert_eq!(g.seen_epoch, 3);
    }

    #[test]
    fn un_backstopped_guard_re_decides_even_on_an_unchanged_epoch() {
        // The own harness has no watcher backstop, so its guard must re-decide
        // every request: a revocation whose epoch bump failed to persist
        // (epoch unchanged) must STILL drop it, closing the fail-open the
        // re-review found.
        let mut g = EpochGuard {
            identity: Some(ident(H_SELF)),
            seen_epoch: 3,
            backstopped: false,
        };
        // Same epoch, but the allowlist no longer lists this identity.
        let err = g
            .recheck_with("t", Ok(rev(3, true)), |_| Ok(Some(list_with(H_OTHER))))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // And it keeps serving when still listed, even on an unchanged epoch.
        let mut g = EpochGuard {
            identity: Some(ident(H_SELF)),
            seen_epoch: 3,
            backstopped: false,
        };
        g.recheck_with("t", Ok(rev(3, true)), |_| Ok(Some(list_with(H_SELF))))
            .unwrap();
    }

    #[test]
    fn epoch_guard_readmits_a_still_listed_harness_and_advances() {
        let mut g = EpochGuard {
            identity: Some(ident(H_SELF)),
            seen_epoch: 3,
            backstopped: true,
        };
        g.recheck_with("t", Ok(rev(4, true)), |_| Ok(Some(list_with(H_SELF))))
            .unwrap();
        assert_eq!(
            g.seen_epoch, 4,
            "the guard caches the epoch it re-admitted under"
        );
    }

    #[test]
    fn epoch_guard_drops_a_revoked_harness() {
        let mut g = EpochGuard {
            identity: Some(ident(H_SELF)),
            seen_epoch: 3,
            backstopped: true,
        };
        let err = g
            .recheck_with("t", Ok(rev(4, true)), |_| Ok(Some(list_with(H_OTHER))))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn epoch_guard_fails_closed_on_unreadable_state() {
        // Unreadable revocation record.
        let mut g = EpochGuard {
            identity: Some(ident(H_SELF)),
            seen_epoch: 0,
            backstopped: true,
        };
        assert!(g
            .recheck_with("t", Err(io::Error::other("corrupt")), |_| Ok(None))
            .is_err());
        // Unreadable allowlist after a bump (includes the ADR-0025 tamper
        // case: deleted clients.json with the enrollment latch set).
        let mut g = EpochGuard {
            identity: Some(ident(H_SELF)),
            seen_epoch: 0,
            backstopped: true,
        };
        assert!(g
            .recheck_with("t", Ok(rev(1, true)), |_| Err(io::Error::other("gone")))
            .is_err());
    }

    #[test]
    fn epoch_guard_rechecks_even_a_rolled_back_epoch() {
        // Enforcement compares by inequality, not order: a revocation file
        // rolled back to an OLDER epoch by a tamperer still forces a
        // re-decide against the current allowlist.
        let mut g = EpochGuard {
            identity: Some(ident(H_SELF)),
            seen_epoch: 5,
            backstopped: true,
        };
        let err = g
            .recheck_with("t", Ok(rev(2, true)), |_| Ok(Some(list_with(H_OTHER))))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn epoch_guard_keeps_the_unenrolled_posture_across_bumps() {
        // Unenrolled (no list, latch unset): a bump re-checks and keeps
        // serving -- the pre-enrollment posture is a documented residual, and
        // a bump alone must not lock out a machine that never enrolled.
        let mut g = EpochGuard {
            identity: None,
            seen_epoch: 0,
            backstopped: true,
        };
        g.recheck_with("t", Ok(rev(1, false)), |_| Ok(None))
            .unwrap();
        assert_eq!(g.seen_epoch, 1);
    }

    #[test]
    fn served_peer_roles_bundle_exactly_their_resources() {
        // The role is one admission-time choice (the guard for the old
        // three-independent-parameters shape): a relay carries a BACKSTOPPED
        // guard plus a rate limiter, the own harness an un-backstopped guard
        // and, structurally, no limiter at all.
        match ServedPeer::relay(Some(ident(H_SELF)), 7) {
            ServedPeer::Relay { guard, .. } => {
                assert!(guard.backstopped, "a relay's guard must be backstopped");
                assert_eq!(guard.seen_epoch, 7);
            }
            ServedPeer::OwnHarness { .. } => panic!("relay constructed as the own harness"),
        }
        match ServedPeer::own_harness(OwnHarness {
            identity: Some(ident(H_SELF)),
            epoch: 3,
        }) {
            ServedPeer::OwnHarness { guard } => {
                assert!(
                    !guard.backstopped,
                    "the own harness has no watcher backstop and must re-decide every request"
                );
                assert_eq!(guard.seen_epoch, 3);
            }
            ServedPeer::Relay { .. } => panic!("own harness constructed as a relay"),
        }
        assert_eq!(ServedPeer::relay(None, 0).who(), "relay harness");
        assert_eq!(
            ServedPeer::own_harness(OwnHarness {
                identity: None,
                epoch: 0
            })
            .who(),
            "the broker's own harness"
        );
    }

    #[cfg(unix)]
    mod registry {
        use super::*;
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        #[test]
        fn watch_tick_kill_severs_browsers_but_keeps_listed_relays() {
            // ADR-0030: the kill sweep runs the browser-drop closure while the
            // switch is engaged, on EVERY tick (idempotent), while a
            // still-listed relay keeps its connection -- its tool calls are
            // refused at dispatch with the typed error instead, so the refusal
            // is deliverable.
            let registry = ClientRegistry::new();
            let (srv, mut cli) = UnixStream::pair().unwrap();
            let _slot = registry.register(Some(ident(H_KEEP)), srv).unwrap();

            let browsers = std::cell::Cell::new(0usize);
            let seen = watch_tick(
                &registry,
                9,
                Ok(killed_rev(9)),
                |_| Ok(Some(list_with(H_KEEP))),
                || {
                    browsers.set(browsers.get() + 1);
                    2
                },
            );
            assert_eq!(seen, Some(9));
            assert_eq!(browsers.get(), 1, "the kill must sever the browser leg");

            // The listed relay stays connected (no EOF within the window).
            cli.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut buf = [0u8; 1];
            let err = cli.read(&mut buf).unwrap_err();
            assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "listed relay must survive a kill sweep, got {err:?}"
            );
        }

        #[test]
        fn watch_tick_without_a_kill_never_touches_browsers() {
            let registry = ClientRegistry::new();
            let seen = watch_tick(
                &registry,
                4,
                Ok(rev(4, true)),
                |_| Ok(Some(list_with(H_KEEP))),
                || panic!("browser sweep must not run while the switch is off"),
            );
            assert_eq!(seen, Some(4));
        }

        #[test]
        fn watch_tick_re_decides_every_tick_even_without_an_epoch_change() {
            // The sweep is UNCONDITIONAL: enforcement does not depend on the
            // epoch advancing (a revocation whose bump failed to persist must
            // still be enforced). So the allowlist is loaded and the refused
            // relay dropped even when the observed epoch equals last_seen.
            let registry = ClientRegistry::new();
            let (a_srv, mut a_cli) = UnixStream::pair().unwrap();
            let (b_srv, mut b_cli) = UnixStream::pair().unwrap();
            let _keep = registry.register(Some(ident(H_KEEP)), a_srv).unwrap();
            let _revoked = registry.register(Some(ident(H_REVOKED)), b_srv).unwrap();

            // Same epoch as last_seen, yet "revoked" is no longer listed.
            let seen = watch_tick(
                &registry,
                5,
                Ok(rev(5, true)),
                |_| Ok(Some(list_with(H_KEEP))),
                || 0,
            );
            assert_eq!(seen, Some(5));

            b_cli
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 1];
            assert_eq!(
                b_cli.read(&mut buf).unwrap(),
                0,
                "revoked relay must see EOF"
            );
            a_cli
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let err = a_cli.read(&mut buf).unwrap_err();
            assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "kept relay must remain connected, got {err:?}"
            );
        }

        #[test]
        fn watch_tick_drops_exactly_the_revoked_relays() {
            let registry = ClientRegistry::new();
            let (a_srv, mut a_cli) = UnixStream::pair().unwrap();
            let (b_srv, mut b_cli) = UnixStream::pair().unwrap();
            let _keep = registry.register(Some(ident(H_KEEP)), a_srv).unwrap();
            let _revoked = registry.register(Some(ident(H_REVOKED)), b_srv).unwrap();

            // The fresh allowlist still lists "keep" but not "revoked".
            let seen = watch_tick(
                &registry,
                1,
                Ok(rev(2, true)),
                |_| Ok(Some(list_with(H_KEEP))),
                || 0,
            );
            assert_eq!(seen, Some(2));

            // The revoked relay's socket was shut down: its far end reads EOF.
            b_cli
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 1];
            assert_eq!(
                b_cli.read(&mut buf).unwrap(),
                0,
                "revoked relay must see EOF"
            );

            // The kept relay's socket is untouched: a read would block, so
            // assert via a short timeout that no EOF/shutdown arrived.
            a_cli
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let err = a_cli.read(&mut buf).unwrap_err();
            assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "kept relay must remain connected, got {err:?}"
            );
        }

        #[test]
        fn watch_tick_with_all_still_listed_drops_nobody() {
            // Unconditional sweep, but every registered relay is still trusted:
            // the loader runs (correctness does not skip on an unchanged epoch),
            // and nothing is dropped.
            let registry = ClientRegistry::new();
            let (srv, mut cli) = UnixStream::pair().unwrap();
            let _slot = registry.register(Some(ident(H_KEEP)), srv).unwrap();
            let seen = watch_tick(
                &registry,
                7,
                Ok(rev(7, true)),
                |_| Ok(Some(list_with(H_KEEP))),
                || 0,
            );
            assert_eq!(seen, Some(7));
            cli.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut buf = [0u8; 1];
            assert!(cli.read(&mut buf).is_err(), "still-trusted relay stays up");
        }

        #[test]
        fn watch_tick_fails_closed_dropping_every_relay() {
            // Unreadable revocation record: every relay is dropped and the
            // last-seen epoch is NOT advanced (the error is retried, and
            // keeps failing closed, on the next tick).
            let registry = ClientRegistry::new();
            let (srv, mut cli) = UnixStream::pair().unwrap();
            let _slot = registry.register(Some(ident(H_SELF)), srv).unwrap();
            let browsers = std::cell::Cell::new(0usize);
            let seen = watch_tick(
                &registry,
                1,
                Err(io::Error::other("corrupt")),
                |_| Ok(None),
                || {
                    browsers.set(browsers.get() + 1);
                    3
                },
            );
            assert_eq!(
                browsers.get(),
                1,
                "an unreadable record must also sever the browser leg (kill state unknown)"
            );
            assert_eq!(seen, None);
            cli.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 1];
            assert_eq!(cli.read(&mut buf).unwrap(), 0);

            // Unreadable allowlist after a bump: same posture.
            let registry = ClientRegistry::new();
            let (srv, mut cli) = UnixStream::pair().unwrap();
            let _slot = registry.register(Some(ident(H_SELF)), srv).unwrap();
            let seen = watch_tick(
                &registry,
                1,
                Ok(rev(2, true)),
                |_| Err(io::Error::other("tampered")),
                || 0,
            );
            assert_eq!(seen, None);
            cli.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            assert_eq!(cli.read(&mut buf).unwrap(), 0);
        }

        #[test]
        fn a_dropped_slot_deregisters_so_sweeps_skip_it() {
            let registry = ClientRegistry::new();
            let (srv, _cli) = UnixStream::pair().unwrap();
            let slot = registry.register(Some(ident(H_SELF)), srv).unwrap();
            drop(slot);
            assert_eq!(
                registry.sweep(|_| true),
                0,
                "no slot may survive its guard's drop"
            );
        }

        #[test]
        fn an_early_return_path_cannot_leak_a_slot() {
            // Models a rejection arm in admit_client: the slot goes out of
            // scope without any explicit release call, and the registry must
            // still be empty -- the invariant RAII moved out of comments.
            let registry = ClientRegistry::new();
            {
                let (srv, _cli) = UnixStream::pair().unwrap();
                let _slot = registry.register(Some(ident(H_SELF)), srv).unwrap();
                // early return: nothing released by hand
            }
            assert_eq!(
                registry.sweep(|_| true),
                0,
                "a slot dropped on an early-return path must deregister itself"
            );
        }
    }

    #[test]
    fn refcount_acquire_release_and_capacity() {
        let rc = RefCount::new(3);
        let a = rc.try_acquire().unwrap(); // 1
        let b = rc.try_acquire().unwrap(); // 2
        let c = rc.try_acquire().unwrap(); // 3
        assert!(rc.try_acquire().is_none(), "at capacity");
        drop(c); // 2
        let d = rc.try_acquire();
        assert!(d.is_some(), "room again after a detach"); // 3
        drop((a, b, d));
    }

    #[test]
    fn refcount_wait_zero_returns_when_drained_and_latches_terminal() {
        let rc = RefCount::new(4);
        let own = rc.try_acquire().unwrap();
        drop(own); // own harness gone -> 0
        rc.wait_zero(); // returns immediately, latches terminal
        assert!(
            rc.try_acquire().is_none(),
            "no attach after the terminal shutdown decision"
        );
    }

    #[test]
    fn pending_slot_bounds_the_handshake_phase_and_releases_on_drop() {
        let broker = Arc::new(Broker {
            session: Session::new(),
            refcount: RefCount::new(MAX_HARNESS_CLIENTS),
            pending: AtomicUsize::new(0),
            registry: ClientRegistry::new(),
        });
        let mut held = Vec::new();
        for _ in 0..MAX_PENDING_ATTACH {
            held.push(PendingSlot::try_acquire(&broker).unwrap());
        }
        // Over the bound: refused, and the refusal restores its own probe.
        assert!(PendingSlot::try_acquire(&broker).is_none());
        assert_eq!(broker.pending.load(Ordering::SeqCst), MAX_PENDING_ATTACH);
        // Dropping one slot frees exactly one place.
        held.pop();
        assert!(PendingSlot::try_acquire(&broker).is_some());
        drop(held);
        assert_eq!(broker.pending.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn rate_limiter_allows_a_burst_then_throttles() {
        let mut rl = RateLimiter::new();
        let mut allowed = 0;
        for _ in 0..(RATE_BURST as usize + 10) {
            if rl.allow() {
                allowed += 1;
            }
        }
        // The burst is bounded by the bucket capacity (a hair of refill may let
        // one or two extra through in real time; assert the order of magnitude).
        assert!(allowed >= RATE_BURST as usize);
        assert!(allowed <= RATE_BURST as usize + 5);
    }

    #[test]
    fn pump_lines_copies_and_bounds() {
        use std::io::Cursor;
        let mut input = Cursor::new(b"{\"a\":1}\n{\"b\":2}\n".to_vec());
        let mut out = Vec::new();
        pump_lines(&mut input, &mut out, MCP_MAX_LINE).unwrap();
        assert_eq!(out, b"{\"a\":1}\n{\"b\":2}\n");

        // An over-cap line fails closed.
        let mut big = Cursor::new(vec![b'x'; 64]);
        let mut out = Vec::new();
        let err = pump_lines(&mut big, &mut out, 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Property coverage of the epoch guard's fail-closed matrix (ADR-0025):
    /// an unchanged epoch is a no-op, a changed epoch re-decides, and only a
    /// measured, still-listed identity survives the re-decide.
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn guard_verdict_matrix(
                seen in any::<u64>(),
                current in any::<u64>(),
                listed in any::<bool>(),
                measured in any::<bool>(),
                backstopped in any::<bool>(),
            ) {
                let identity = if measured { Some(ident(H_SELF)) } else { None };
                let mut g = EpochGuard { identity, seen_epoch: seen, backstopped };
                let anchor = if listed { H_SELF } else { H_OTHER };
                let res = g.recheck_with(
                    "t",
                    Ok(rev(current, true)),
                    |_| Ok(Some(list_with(anchor))),
                );
                if backstopped && seen == current {
                    // Backstopped + unchanged epoch: the fast path, a no-op.
                    prop_assert!(res.is_ok());
                    prop_assert_eq!(g.seen_epoch, seen);
                } else if measured && listed {
                    // A re-decide (forced by a changed epoch, or by an
                    // un-backstopped guard) that still admits; the cache
                    // advances to the observed epoch.
                    prop_assert!(res.is_ok());
                    prop_assert_eq!(g.seen_epoch, current);
                } else {
                    // Everything else -- unmeasured identity, delisted
                    // identity -- fails closed on a re-decide.
                    prop_assert!(res.is_err());
                }
            }

            /// An unreadable revocation record fails closed regardless of any
            /// other input.
            #[test]
            fn guard_fails_closed_on_a_revocation_read_error(seen in any::<u64>()) {
                let mut g = EpochGuard {
                    identity: Some(ident(H_SELF)),
                    seen_epoch: seen,
                    backstopped: true,
                };
                let res = g.recheck_with(
                    "t",
                    Err(io::Error::other("unreadable")),
                    |_| Ok(Some(list_with(H_SELF))),
                );
                prop_assert!(res.is_err());
            }
        }
    }
}

/// Loom model-check of the broker's ref-count shutdown protocol. Run with:
/// `RUSTFLAGS="--cfg loom" cargo test -p chromium-bridge-core --lib loom_model`.
/// Under `--cfg loom` the [`RefCount`] `Mutex`/`Condvar` are loom's instrumented
/// versions, and loom exhaustively explores the thread interleavings that could
/// break the two invariants the broker's lifetime depends on: the shutdown
/// decision happens exactly when the client count reaches zero, and no client
/// can attach after that decision has latched (which would strand a relay on a
/// broker that is about to unlink its socket).
#[cfg(all(test, loom))]
mod loom_model {
    use super::RefCount;
    use loom::sync::Arc;
    use loom::thread;

    #[test]
    fn shutdown_happens_exactly_at_zero_and_latches_terminal() {
        loom::model(|| {
            // The broker starts with its own stdio harness as client #1.
            let rc = Arc::new(RefCount::new(4));
            let Some(own) = rc.try_acquire() else {
                panic!("the own-harness slot must be acquirable at count 0");
            };

            // A relay races: it may attach (acquiring a slot) and later detach
            // (dropping it), or lose the race and be refused. Whichever
            // happens, the counts must stay balanced and the shutdown must
            // fire exactly once at zero.
            let relay = {
                let rc = Arc::clone(&rc);
                thread::spawn(move || {
                    if let Some(slot) = rc.try_acquire() {
                        drop(slot);
                    }
                })
            };

            // The broker's own harness detaches (stdin EOF), then the broker
            // waits for every remaining client to leave before tearing down.
            drop(own);
            rc.wait_zero();

            // After the terminal decision no fresh attach may succeed: a relay
            // that dials now must be turned away (it will retry / become the
            // new broker) rather than attaching to a broker mid-teardown.
            assert!(
                rc.try_acquire().is_none(),
                "a client attached after the broker committed to shutting down"
            );

            relay.join().unwrap();
        });
    }

    #[test]
    fn two_relays_racing_attach_and_detach_never_underflow() {
        loom::model(|| {
            // Own harness (1) plus up to two relays contending. The internal
            // debug_assert in `decr` catches an underflow; loom explores every
            // interleaving, so a balance bug surfaces as a failed model.
            let rc = Arc::new(RefCount::new(4));
            let Some(own) = rc.try_acquire() else {
                panic!("the own-harness slot must be acquirable at count 0");
            };
            let a = {
                let rc = Arc::clone(&rc);
                thread::spawn(move || {
                    if let Some(slot) = rc.try_acquire() {
                        drop(slot);
                    }
                })
            };
            let b = {
                let rc = Arc::clone(&rc);
                thread::spawn(move || {
                    if let Some(slot) = rc.try_acquire() {
                        drop(slot);
                    }
                })
            };
            drop(own);
            rc.wait_zero();
            a.join().unwrap();
            b.join().unwrap();
        });
    }

    /// ADR-0025: the revocation-sweep registry must be empty by the time the
    /// broker's teardown decision latches, so no relay stream outlives the
    /// socket it hangs off. The code guarantees it by ordering: a relay's
    /// [`RelayAdmission`](super::RelayAdmission) deregisters BEFORE it
    /// decrements the ref-count (its field declaration order IS the drop
    /// order), and `wait_zero` only returns at count zero. This model mirrors
    /// exactly that shape (a loom-instrumented mutex around the slot map, the
    /// real `RefCount`), with a concurrent sweeper reading the registry the
    /// way the epoch watcher does. Loom exhausts the interleavings; the
    /// invariant is checked after the terminal decision.
    #[test]
    fn registry_is_empty_once_the_shutdown_decision_latches() {
        use loom::sync::Mutex;
        use std::collections::HashMap;

        loom::model(|| {
            let rc = Arc::new(RefCount::new(4));
            let Some(own) = rc.try_acquire() else {
                panic!("the own-harness slot must be acquirable at count 0");
            };
            let slots = Arc::new(Mutex::new(HashMap::new()));

            // A relay: attach (acquire + register), serve, detach --
            // deregister BEFORE the ref-count slot drops, the load-bearing
            // order RelayAdmission's field order encodes.
            let relay = {
                let rc = Arc::clone(&rc);
                let slots = Arc::clone(&slots);
                thread::spawn(move || {
                    if let Some(slot) = rc.try_acquire() {
                        slots.lock().unwrap().insert(1u64, ());
                        slots.lock().unwrap().remove(&1u64);
                        drop(slot);
                    }
                })
            };

            // The epoch watcher: sweeps whatever is registered right now
            // (shutdown is a no-op on the count; the relay's own detach is
            // what balances it).
            let sweeper = {
                let slots = Arc::clone(&slots);
                thread::spawn(move || {
                    let guard = slots.lock().unwrap();
                    // Reading the map models the sweep's iteration.
                    let _ = guard.len();
                })
            };

            // Broker: own harness leaves, then wait for the relays.
            drop(own);
            rc.wait_zero();

            // Terminal: no slot may remain (a surviving slot would be a
            // stream outliving the socket teardown).
            assert_eq!(
                slots.lock().unwrap().len(),
                0,
                "a registry slot survived the shutdown decision"
            );

            relay.join().unwrap();
            sweeper.join().unwrap();
        });
    }
}
