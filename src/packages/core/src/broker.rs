//! The ref-counted, attested broker and its relay clients.
//!
//! Several harnesses (Claude Code, Copilot, Codex, ...) drive one browser at once, so the first MCP-server
//! instance to start becomes the broker: it owns the 0600 bridge socket and the lock, holds the browser
//! connections in its [`Session`], and multiplexes every attached harness's tool calls. Later instances attest
//! it and attach as relays; the broker exits when the last harness (its own plus every relay) detaches.
//!
//! Every connection passes the HMAC handshake, preceded by the same-user check (the peer UID on Unix, the pipe's
//! descriptor on Windows) and by `attest_peer` (our own binary, see [`crate::ipc`]), then sends one
//! [`AttachRequest`]:
//!
//! ```text
//! AttachRequest::Browser  -> a Chrome-spawned native host; its label was MAC-signed in the handshake Response
//! AttachRequest::Client   -> a sibling instance relaying a harness; carries the relay's getppid-attested
//!                            parent identity, checked against the trusted-client allowlist (crate::allowlist)
//! ```
//!
//! The broker trusts a relay's harness hash/signer because the relay passed `attest_peer`: it is our binary,
//! which measures its parent honestly. The harness *name* is a log label only; authorization keys on the hash/signer.
//!
//! Residual: `getppid` names who spawned the relay, not who writes its stdin, and it is measured ONCE at process
//! start (mcp_server's `admit_own_harness`); the identity is then re-decided against the trust record on every
//! request ([`crate::trust::TrustState::decide`]).
//! ```text
//! reparented before the measurement                         -> measured as the reaper: refused once clients are
//!                                                              paired and the reaper is not allowlisted, admitted
//!                                                              while unenrolled (decide ignores the identity)
//! parent exits mid-session, another process holds the stdin -> continues under the admitted identity
//! pid reused around the measurement                         -> the same race
//! ```

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::audit;
use crate::ipc::{self, BridgeStream, BrowserLabel, ClientIdentity};
use crate::protocol::{
    bridge_read, bridge_write, mcp_read, mcp_write, AttachReply, AttachRequest, HarnessId, JsonRpc,
    MCP_MAX_LINE,
};
use crate::session::Session;
use crate::trust::{Admission, AdmittingSurface, Posture, TrustState, POLL_INTERVAL};

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

#[cfg(all(test, feature = "loom"))]
use loom::sync::{Condvar, Mutex, MutexGuard};
#[cfg(not(all(test, feature = "loom")))]
use std::sync::{Condvar, Mutex, MutexGuard};

/// The broker's one lock poisoning policy: recover. SECURITY.md's lock poisoning section owns the reasons.
struct Lock<T>(Mutex<T>);

impl<T> Lock<T> {
    fn new(value: T) -> Self {
        Lock(Mutex::new(value))
    }

    fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

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
    state: Lock<CountState>,
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
            state: Lock::new(CountState {
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
        let mut g = self.state.lock();
        if g.terminal || g.live >= self.max {
            return None;
        }
        // Unreachable overflow (live < max), but refuse rather than wrap:
        // an attach refusal is retryable, a wrapped count is not.
        let live = g.live.checked_add(1)?;
        g.live = live;
        Some(HarnessSlot { refcount: self })
    }

    /// Remove a client (the [`HarnessSlot`] Drop path). Wakes
    /// [`wait_zero`](RefCount::wait_zero) when the count reaches zero.
    fn decr(&self) {
        let mut g = self.state.lock();
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
        let mut g = self.state.lock();
        while g.live != 0 {
            g = self
                .reached_zero
                .wait(g)
                .unwrap_or_else(PoisonError::into_inner);
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

// ---- Admission enforcement -------------------------------------------------

/// One admitted peer of a serve loop: the identity and posture it was admitted with, plus the rate limiter
/// only a relay carries. One value per role, so a serve loop cannot cross one role's limiter with the other's
/// identity. The relay is also swept by the watcher ([`ClientRegistry`]); the own harness has no socket to
/// shut down, so an idle revoked own harness stays connected (it is driving nothing) until its next request.
enum ServedPeer {
    OwnHarness {
        identity: Option<ClientIdentity>,
        posture: Posture,
    },
    Relay {
        identity: Option<ClientIdentity>,
        posture: Posture,
        limiter: RateLimiter,
    },
}

impl ServedPeer {
    fn relay(identity: Option<ClientIdentity>, posture: Posture) -> ServedPeer {
        ServedPeer::Relay {
            identity,
            posture,
            limiter: RateLimiter::new(),
        }
    }

    /// The role's name for logs and the refusal text.
    fn who(&self) -> &'static str {
        match self {
            ServedPeer::OwnHarness { .. } => "the broker's own harness",
            ServedPeer::Relay { .. } => "relay harness",
        }
    }
}

/// Why a served connection is no longer served.
enum Refusal {
    Revoked,
    /// The record enforced admission when the connection was admitted and now reads as the open bootstrap:
    /// it was deleted or hand-edited under a live session.
    BootstrapReverted,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Revoked => f.write_str("was revoked"),
            Refusal::BootstrapReverted => f.write_str(
                "was admitted under an enforced record that now reads as the open bootstrap",
            ),
        }
    }
}

/// The one continued-service rule, shared by the per-request gate and the watcher sweep: a connection is never
/// served under a weaker posture than it was admitted with. Ending the connection on a bootstrap revert is
/// what keeps `rm trust.json` loud: the respawned instance re-admits under the ERROR-logged bootstrap.
fn refusal(
    trust: &TrustState,
    identity: Option<&ClientIdentity>,
    posture: &Posture,
) -> Option<Refusal> {
    match (posture, trust.decide(identity)) {
        (_, Admission::Refused) => Some(Refusal::Revoked),
        (Posture::Trusted { .. }, Admission::Admit(Posture::Unenrolled)) => {
            Some(Refusal::BootstrapReverted)
        }
        (Posture::Unenrolled, Admission::Admit(_))
        | (Posture::Trusted { .. }, Admission::Admit(Posture::Trusted { .. })) => None,
    }
}

/// The per-request gate. The record is read fresh for every request, so a revocation or a corrupted record is
/// enforced on the very next request, never a poll interval later.
fn request_admission(
    who: &str,
    identity: Option<&ClientIdentity>,
    posture: &Posture,
    trust: io::Result<TrustState>,
) -> io::Result<()> {
    let trust = trust.map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("trust record unreadable ({e}); failing closed"),
        )
    })?;
    match refusal(&trust, identity, posture) {
        None => Ok(()),
        Some(why) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{who} {why} (trust epoch {})", trust.epoch()),
        )),
    }
}

/// The broker's registry of live RELAY connections, so a revocation can reach
/// an idle connection: the watcher thread sweeps it every tick and shuts down
/// the socket of any harness the current record refuses, which ends that
/// relay's serve loop (its own per-request gate would equally refuse its next
/// request; the sweep covers the no-request case). Slots are removed only by
/// their [`RegistrySlot`] guard's Drop (held by the serve worker) -- the sweep
/// never removes, so occupancy bookkeeping stays in exactly one place, and by
/// construction rather than by convention.
struct ClientRegistry {
    slots: Lock<RegistryInner>,
}

struct RegistryInner {
    next_id: u64,
    clients: HashMap<u64, RegisteredClient>,
}

struct RegisteredClient {
    identity: Option<ClientIdentity>,
    posture: Posture,
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
            slots: Lock::new(RegistryInner {
                next_id: 1,
                clients: HashMap::new(),
            }),
        }
    }

    fn register(
        &self,
        identity: Option<ClientIdentity>,
        posture: Posture,
        stream: BridgeStream,
    ) -> Option<RegistrySlot<'_>> {
        let mut inner = self.slots.lock();
        let id = inner.next_id;
        // A wrapped id could collide with a live slot and let deregister
        // remove the wrong client; refuse the attach instead (fail closed).
        let next_id = id.checked_add(1)?;
        inner.next_id = next_id;
        inner.clients.insert(
            id,
            RegisteredClient {
                identity,
                posture,
                stream,
            },
        );
        Some(RegistrySlot { registry: self, id })
    }

    /// Release path, called only by [`RegistrySlot`]'s Drop.
    fn deregister(&self, id: u64) {
        self.slots.lock().clients.remove(&id);
    }

    /// Shut down every registered relay `refuse` matches. Returns how many connections were dropped.
    fn sweep(&self, refuse: impl Fn(Option<&ClientIdentity>, &Posture) -> bool) -> usize {
        let inner = self.slots.lock();
        // Explicit loop: the shutdown is enforcement and must not hide as an
        // iterator-adapter side effect. The count only feeds a log line, so
        // clamping on (unreachable) overflow is fine.
        let mut dropped: usize = 0;
        for client in inner.clients.values() {
            if refuse(client.identity.as_ref(), &client.posture) {
                let _ = client.stream.shutdown(std::net::Shutdown::Both);
                dropped = dropped.saturating_add(1);
            }
        }
        dropped
    }
}

/// The watcher loop body, factored from the polling thread so the fail-closed matrix is testable: re-decide every
/// live relay against the current record and enforce the kill switch on the browser leg. The re-decide is
/// UNCONDITIONAL, not gated on an epoch change: the record is the authority, and a sweep gated on the counter
/// would serve a client delisted by a hand edit that left the counter alone.
///
/// ```text
/// sweeping every tick -> bounds an idle revoked relay's exposure to one poll interval
/// drop_browsers       -> idempotent, so calling it every tick is harmless
/// returned epoch      -> only deduplicates the "dropped N" log line; None on a failed read keeps the caller's
///                        logging cursor
/// ```
fn watch_tick(
    registry: &ClientRegistry,
    last_seen: u64,
    trust: io::Result<TrustState>,
    drop_browsers: impl FnOnce() -> usize,
) -> Option<u64> {
    let trust = match trust {
        Ok(trust) => trust,
        Err(e) => {
            // Fail closed: with the record unreadable no relay's admission can be re-validated and the kill
            // state is unknowable, so neither the relays nor the browser leg may keep a connection.
            let dropped = registry.sweep(|_, _| true);
            let browsers = drop_browsers();
            if dropped > 0 || browsers > 0 {
                log_error!(
                    "broker",
                    "trust record unreadable ({e}); dropped {dropped} relay and \
                     {browsers} browser connection(s) (fail closed)"
                );
            }
            return None;
        }
    };
    if trust.killed() {
        let browsers = drop_browsers();
        if browsers > 0 {
            log_error!(
                "broker",
                "kill switch engaged (trust epoch {}); severed {browsers} browser connection(s)",
                trust.epoch()
            );
        }
    }
    let dropped = registry.sweep(|identity, posture| refusal(&trust, identity, posture).is_some());
    // Log only when something was dropped AND the epoch moved since the last drop, so a relay still
    // deregistering mid-dispatch does not repeat the line every second.
    if dropped > 0 && trust.epoch() != last_seen {
        log_info!(
            "broker",
            "trust epoch {}; dropped {dropped} revoked relay connection(s)",
            trust.epoch()
        );
    }
    Some(trust.epoch())
}

// ---- Broker ----------------------------------------------------------------

struct Broker {
    session: Session,
    refcount: RefCount,
    /// Connections currently in the handshake/attach phase, bounding accept-time
    /// fan-out ([`MAX_PENDING_ATTACH`]).
    pending: AtomicUsize,
    /// Live relay connections, swept against the trust record every watcher tick.
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
        /// The relay role's serve-loop resources: its admitted identity plus its rate limiter, bundled by
        /// [`ServedPeer::relay`] so the role cannot be re-assembled wrong.
        peer: ServedPeer,
        /// This connection's registry + ref-count occupancy (RAII).
        admission: RelayAdmission<'a>,
    },
    /// Rejected (refused, unavailable, or a failed handshake): nothing to do --
    /// any partially acquired resources were released by their guards' Drop.
    Rejected,
}

/// Run as the broker: own the accepted socket, serve this instance's own stdio harness, accept browser and
/// relay attaches, and exit when the last harness detaches. `own_identity` and `own_posture` are what
/// `mcp_server::admit_own_harness` admitted this instance's harness with. Returns the process exit code.
pub(crate) fn run_broker(
    listener: ipc::BridgeListener,
    session: Session,
    own_identity: Option<ClientIdentity>,
    own_posture: Posture,
) -> i32 {
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

    // Watch the trust record so a revoke reaches IDLE relay connections too (requests are gated inline), and
    // so a kill severs the browser leg within a tick even when nobody is calling. The thread dies with the
    // process.
    {
        let broker = Arc::clone(&broker);
        let mut last_seen = 0;
        thread::spawn(move || loop {
            thread::sleep(POLL_INTERVAL);
            if let Some(seen) =
                watch_tick(&broker.registry, last_seen, TrustState::current(), || {
                    broker.session.shutdown_all_browsers()
                })
            {
                last_seen = seen;
            }
        });
    }

    // Accept browser and relay connections off the main thread.
    {
        let broker = Arc::clone(&broker);
        thread::spawn(move || accept_loop(&broker, listener));
    }

    // A revoked own harness ends only this loop: attached relays keep being served until they detach.
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let mut peer = ServedPeer::OwnHarness {
        identity: own_identity,
        posture: own_posture,
    };
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
    // The kill switch severs the browser leg entirely: while it is
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

    let trust = match TrustState::current() {
        Ok(trust) => trust,
        Err(e) => {
            return reject_relay(
                &mut writer,
                &format!("cannot read the trust record: {e}"),
                Some(AttachReply::Refused {
                    reason: "trust record unreadable".into(),
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
    let admission = trust.decide(identity.as_ref());
    admission.announce(
        AdmittingSurface::Relay,
        reported_name.as_deref(),
        identity.as_ref(),
    );
    let posture = match admission {
        Admission::Refused => {
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
        Admission::Admit(posture) => posture,
    };

    let sweep_handle = match writer.get_ref().try_clone() {
        Ok(s) => s,
        Err(e) => {
            log_warn!("broker", "clone stream for the revocation registry: {e}");
            return Admitted::Rejected;
        }
    };
    let Some(slot) = broker
        .registry
        .register(identity.clone(), posture.clone(), sweep_handle)
    else {
        log_warn!(
            "broker",
            "revocation registry ids exhausted; refusing relay"
        );
        return Admitted::Rejected;
    };

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
        peer: ServedPeer::relay(identity, posture),
        admission,
    }
}

/// Clear a bridge stream's read timeout (set during the attach phase) for
/// steady-state serving, where an idle connection is legitimate. Best-effort:
/// a failure here only means the attach timeout lingers, which is harmless.
fn clear_read_timeout(writer: &BufWriter<BridgeStream>) {
    let _ = writer.get_ref().set_read_timeout(None);
}

/// Serve a JSON-RPC stream (this instance's own stdin, or a relay's socket) against the shared session through
/// this connection's [`crate::mcp::Connection`]. The gates run HERE, before a message reaches the protocol
/// engine, so adopting rmcp moved none of them; a parse error answers `-32700` and continues, EOF ends the loop.
/// ```text
/// relay over its rate limit                 -> connection dropped (fail closed)
/// revoked, or the trust record unreadable   -> loop ends before dispatch
/// ```
fn serve_jsonrpc<R: BufRead, W: Write>(
    session: &Session,
    reader: &mut R,
    writer: &mut W,
    peer: &mut ServedPeer,
) -> io::Result<()> {
    let who = peer.who();
    let mut mcp = crate::mcp::Connection::open(session.clone())?;
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
        // The rate limit is the relay role's resource, carried on its variant; the own harness structurally
        // has none to consult. Checked before the (costlier) trust re-decide.
        let (identity, posture) = match peer {
            ServedPeer::OwnHarness { identity, posture } => (identity, posture),
            ServedPeer::Relay {
                identity,
                posture,
                limiter,
            } => {
                if !limiter.allow() {
                    log_warn!(
                        "broker",
                        "relay exceeded its request rate limit; dropping it"
                    );
                    return Err(io::Error::other("relay rate limit exceeded"));
                }
                (identity, posture)
            }
        };
        if let Err(e) = request_admission(who, identity.as_ref(), posture, TrustState::current()) {
            log_error!("broker", "dropping {who}: {e}");
            return Err(e);
        }
        if let Some(resp) = mcp.handle(&msg)? {
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
    if let Err(e) = ipc::attest_peer(&stream) {
        log_error!("relay", "broker attestation failed: {e}");
        return RelayOutcome::Denied;
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
    // Read up to cap+1 bytes so an over-cap line is distinguishable from one
    // of exactly cap bytes. An unrepresentable limit fails closed.
    let limit = u64::try_from(cap)
        .ok()
        .and_then(|c| c.checked_add(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "line cap out of range"))?;
    loop {
        let mut line = Vec::new();
        let n = std::io::Read::take(reader.by_ref(), limit).read_until(b'\n', &mut line)?;
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

// Two cfg attributes rather than cfg(all(test, not(feature = "loom"))): the
// meaning is identical, and the bare #[cfg(test)] is what lets clippy's
// allow-unwrap-in-tests recognize the module's helper fns as test code.
#[cfg(test)]
#[cfg(not(feature = "loom"))]
mod tests;

/// Loom model-check of the broker's ref-count shutdown protocol. Run with
/// `moon run core:test-loom` (`cargo test -p chromium-bridge-core --lib
/// --features loom loom_model`). In that test build the [`RefCount`]
/// `Mutex`/`Condvar` are loom's instrumented versions, and loom exhaustively
/// explores the thread interleavings that could break the two invariants the
/// broker's lifetime depends on: the shutdown decision happens exactly when the
/// client count reaches zero, and no client can attach after that decision has
/// latched (which would strand a relay on a broker that is about to unlink its
/// socket).
#[cfg(all(test, feature = "loom"))]
mod loom_model;
