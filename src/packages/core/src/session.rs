//! Session state owned by the MCP server process.
//!
//! The MCP server is the single source of truth. It:
//!   - owns the localhost TCP listener (published via the lock file),
//!   - accepts inbound connections from native hosts (one per browser, each
//!     independently attested and HMAC-authenticated),
//!   - serializes tool invocations as `BridgeReq` over the addressed
//!     connection and correlates the `BridgeResp` by id using a one-shot
//!     channel per id.
//!
//! If a native host disconnects (Chrome closed, SW recycled), the next tool
//! call addressed to it blocks/retries until a fresh host connects back. The
//! extension is responsible for re-calling `connectNative` on its own.
//!
//! ## Label-keyed connection registry
//!
//! Each authenticated connection carries a browser label (from the handshake
//! `Response`, trusted only after the HMAC verifies; missing label maps to
//! [`DEFAULT_LABEL`]). Connections live in a `HashMap<label, Conn>`, so
//! several browsers (chrome, brave, ...) can be attached at once. A new
//! dial-in with the SAME label replaces the old connection for that label
//! (same-browser reconnect); different labels coexist. Requests resolve to a
//! connection via [`resolve_target`]: an explicit `browser` argument picks
//! that label, no argument picks the sole connection, and with several
//! connections and no argument the call fails with a clear error instead of
//! guessing.
//!
//! ## Generation-guarded connections
//!
//! Each accepted connection is stamped with a monotonic `generation` id
//! (global across labels, so ids never collide between browsers). The live
//! writer is stored together with the generation that owns it ([`Conn`]), so
//! a stale reader thread can only tear down *its own* connection: on
//! disconnect it clears its label's slot **only if** that slot still holds
//! its generation. If a newer host already attached under the same label in
//! the race window, the old reader leaves the live connection untouched
//! instead of clobbering it.
//!
//! Pending requests are tagged with the generation they were sent under -
//! bound at insert, under the registry lock, immediately before the write, so
//! an unbound in-flight entry is unrepresentable. When a reader for
//! generation `G` exits, it drains (drops) every pending sender tagged `G`,
//! so those callers fail fast with [`CallError::Disconnected`] instead of
//! waiting the full 120s timeout. Pending entries belonging to other
//! connections survive.

use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use crate::error::CallError;
use crate::ipc::{self, BrowserLabel};
use crate::protocol::{bridge_read, bridge_write, BridgeReq, ParsedResp};

/// The label assigned to a connection whose handshake carried no label.
/// Re-exported from the handshake module, where [`BrowserLabel`] owns the
/// label domain.
pub use crate::ipc::DEFAULT_LABEL;

/// Maximum number of concurrent *distinct* browser labels the session holds, a
/// DoS bound on the browser leg. A reconnect under an existing label replaces
/// its slot (it does not grow the set) and is always allowed; only a NEW label
/// beyond the cap is refused. Enforced atomically at the single insert point
/// (see [`Session::attach_browser`]).
pub(crate) const MAX_BROWSERS: usize = 16;

/// A connection generation. Non-zero by construction: minting refuses a
/// wrapped-to-zero counter value ([`Session::attach_authenticated`]), so no
/// sentinel can ever collide with a real generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Generation(std::num::NonZeroU64);

impl Generation {
    /// The numeric value, for the public [`Session::route_info`] surface and
    /// audit correlation.
    fn get(self) -> u64 {
        self.0.get()
    }
}

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A live, authenticated connection to one browser's native host, paired with
/// the generation id that owns it. Storing the generation alongside the writer
/// makes cleanup atomic under the registry mutex: a reader can compare its own
/// generation against whatever currently occupies its label's slot before
/// touching it.
struct Conn {
    generation: Generation,
    writer: BufWriter<ipc::BridgeStream>,
}

/// Pending request callbacks keyed by `BridgeReq.id`. Each entry carries the
/// generation it was sent under - by construction: [`Session::try_call`]
/// inserts the entry already bound, under the registry lock, immediately
/// before the write, so there is no unsent state a drain or a delivery check
/// could mishandle. A disconnecting reader drops exactly the callers that
/// belonged to its (now-dead) connection.
type Pending = Arc<Mutex<HashMap<u64, (Generation, mpsc::Sender<ParsedResp>)>>>;

/// A reader thread's verdict on one inbound response: deliver it to its
/// waiting caller, refuse it because the pending entry belongs to a different
/// connection ([`RoutedResp::Foreign`] carries the owning generation), or no
/// caller is waiting on that id at all.
enum RoutedResp {
    Deliver(mpsc::Sender<ParsedResp>),
    Foreign(Generation),
    Unknown,
}

/// Decide whether a reader thread owning `my_gen` should clear its label's
/// registry slot on disconnect. Clear **only** when the slot still holds *my*
/// generation; a newer connection under the same label (or an already-empty
/// slot) must be left untouched. This is the core of the anti-clobber fix and
/// is unit-tested directly.
fn should_clear_conn(current: Option<Generation>, my_gen: Generation) -> bool {
    current == Some(my_gen)
}

/// Remove and return every pending entry whose generation is `my_gen`.
/// Dropping the returned senders wakes those callers immediately with a closed
/// channel (surfaced as [`CallError::Disconnected`]). Entries bound to any
/// other generation - other still-live connections - are left in the map.
/// Factored out so the drain policy is unit-testable without sockets.
fn drain_pending_for_generation(
    pending: &mut HashMap<u64, (Generation, mpsc::Sender<ParsedResp>)>,
    my_gen: Generation,
) -> Vec<mpsc::Sender<ParsedResp>> {
    let ids: Vec<u64> = pending
        .iter()
        .filter(|(_, (generation, _))| *generation == my_gen)
        .map(|(id, _)| *id)
        .collect();
    ids.into_iter()
        .filter_map(|id| pending.remove(&id).map(|(_, tx)| tx))
        .collect()
}

/// Remove and return every pending sender. The kill sweep uses this because a
/// kill is global, and every entry is in flight by construction (inserted
/// already bound, immediately before its write): that includes entries whose
/// generation is no longer in the registry (their connection was replaced by
/// a same-label reconnect, or their reader already cleaned up) - the replaced
/// connection's reader may still be alive on a cloned fd and could otherwise
/// deliver a late response after the sweep.
fn drain_pending_all(
    pending: &mut HashMap<u64, (Generation, mpsc::Sender<ParsedResp>)>,
) -> Vec<mpsc::Sender<ParsedResp>> {
    pending.drain().map(|(_, (_, tx))| tx).collect()
}

/// Pick the connection a request should run over. `available` are the live
/// labels (any order); `want` is the request's optional `browser` argument.
///
/// - `want = Some(label)`: that label must be live, otherwise the caller gets
///   [`CallError::BrowserNotFound`] naming what IS connected.
/// - `want = None` with exactly one connection: route to it (single-browser
///   back-compat - no argument needed when there is nothing to choose).
/// - `want = None` with several connections: refuse with
///   [`CallError::AmbiguousBrowser`] rather than guess - acting in the wrong
///   logged-in browser is worse than asking the caller to name one.
/// - No connections at all: [`CallError::NotConnected`].
fn resolve_target(available: &[&str], want: Option<&str>) -> Result<String, CallError> {
    let mut labels: Vec<&str> = available.to_vec();
    labels.sort_unstable();
    match want {
        Some(w) => {
            if labels.contains(&w) {
                Ok(w.to_string())
            } else if labels.is_empty() {
                // The addressed browser cannot exist when nothing is
                // connected; the plain not-connected error (with its retry
                // hint) is the more actionable one.
                Err(CallError::NotConnected)
            } else {
                Err(CallError::BrowserNotFound(w.to_string(), labels.join(", ")))
            }
        }
        None => match labels.as_slice() {
            [] => Err(CallError::NotConnected),
            [sole] => Ok((*sole).to_string()),
            _ => Err(CallError::AmbiguousBrowser(labels.join(", "))),
        },
    }
}

/// Shared session. Cheap to clone - everything is behind Arc.
#[derive(Clone)]
pub struct Session {
    /// The currently-connected native hosts, keyed by (validated) browser
    /// label. Each entry pairs the writer with its generation so the owning
    /// reader can atomically decide whether to clear it (see module docs).
    conns: Arc<Mutex<HashMap<BrowserLabel, Conn>>>,
    /// Pending request callbacks keyed by BridgeReq.id, tagged by binding.
    pending: Pending,
    next_id: Arc<AtomicU64>,
    /// Monotonic per-connection generation counter, global across labels.
    /// Starts at 1; [`Generation`] is non-zero by construction, so a wrapped
    /// counter is refused at the mint point rather than colliding with
    /// anything.
    next_gen: Arc<AtomicU64>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Session {
            conns: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            next_gen: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Take ownership of a freshly-accepted, already-authenticated connection
    /// from a native host and register it under the browser `label` the
    /// handshake carried. A previous connection under the SAME label is
    /// replaced (dropped/closed); connections under other labels are untouched.
    /// Spawns a reader thread that dispatches `BridgeResp` by id.
    ///
    /// Returns `false` when the distinct-browser cap ([`MAX_BROWSERS`]) is
    /// already reached and `label` is new: the cap is checked ATOMICALLY with
    /// the insert (one lock acquisition), so concurrent new-label attaches
    /// cannot each observe room and collectively exceed it. On refusal the
    /// reader/writer are dropped here (the socket closes and the native host
    /// reconnects); the caller has already sent the peer `Accepted`, so a
    /// browser that lost the cap race is dropped rather than breaching the cap
    /// -- a benign, self-healing degradation at a pathological browser count.
    ///
    /// The caller (the broker accept path) performs the HMAC handshake and the
    /// `AttachRequest::Browser` role read on the same buffered halves before
    /// handing them here, so no frame is lost and the label is honored only
    /// after the MAC verified.
    pub(crate) fn attach_browser(
        &self,
        label: BrowserLabel,
        reader: BufReader<ipc::BridgeStream>,
        writer: BufWriter<ipc::BridgeStream>,
    ) -> bool {
        self.attach_authenticated(label, reader, writer, Some(MAX_BROWSERS))
    }

    /// Register an already-authenticated connection under `label` and spawn
    /// its reader. `cap` bounds the number of distinct browser labels
    /// (`None` = unbounded, used by the registry unit tests). The cap check,
    /// the generation allocation, and the insert all happen under ONE lock so
    /// the cap invariant cannot be raced. Returns whether the connection was
    /// attached. Split out so the registry semantics (replace-same-label,
    /// per-entry generation guard, cap) are testable over a socketpair without
    /// a lock file or handshake.
    fn attach_authenticated(
        &self,
        label: BrowserLabel,
        mut reader: BufReader<ipc::BridgeStream>,
        writer: BufWriter<ipc::BridgeStream>,
        cap: Option<usize>,
    ) -> bool {
        // Atomic section: enforce the cap, allocate the generation, and install
        // the writer under a single lock acquisition. An existing same-label
        // entry (older connection to the same browser) is replaced regardless
        // of the cap; a new label beyond the cap is refused. Replacing here
        // drops the old writer; its reader will observe the disconnect and,
        // thanks to the generation guard below, leave THIS entry alone.
        let my_gen = {
            // A poisoned registry lock means a thread panicked mid-mutation;
            // refuse the new connection rather than install it into state we
            // cannot trust (the native host will redial).
            let Ok(mut guard) = self.conns.lock() else {
                log_error!(
                    "session",
                    "browser registry lock poisoned; refusing connection '{label}'"
                );
                return false;
            };
            if let Some(max) = cap {
                if !guard.contains_key(&label) && guard.len() >= max {
                    log_warn!(
                        "session",
                        "browser cap ({max}) reached; refusing new browser label '{label}'"
                    );
                    return false; // reader/writer dropped here -> socket closes
                }
            }
            let raw_gen = self.next_gen.fetch_add(1, Ordering::SeqCst);
            let Some(nz) = std::num::NonZeroU64::new(raw_gen) else {
                // Unreachable short of the u64 wrapping (the counter starts at
                // 1 and only increments), but the no-panic lint set forbids
                // unwrap/expect: refuse the connection (fail closed, the
                // native host redials) rather than mint an invalid generation.
                log_error!(
                    "session",
                    "generation counter wrapped; refusing connection '{label}'"
                );
                return false;
            };
            let my_gen = Generation(nz);
            guard.insert(
                label.clone(),
                Conn {
                    generation: my_gen,
                    writer,
                },
            );
            my_gen
        };
        log_info!(
            "session",
            "native host '{label}' connected and authenticated (generation {my_gen})"
        );

        // Spawn the reader: each response routes to its pending sender. The
        // reader is bound to `my_gen`; on disconnect it only tears down the
        // connection it actually owns. Responses are read as [`ParsedResp`],
        // so a frame the wire shape could spell but the contract cannot mean
        // (ok-with-error, failure-with-data) is a read error here - the
        // connection is dropped, fail closed, before any caller sees it.
        let pending = self.pending.clone();
        let conns = self.conns.clone();
        thread::spawn(move || {
            loop {
                let resp: Option<ParsedResp> = match bridge_read(&mut reader) {
                    Ok(r) => r,
                    Err(e) => {
                        log_warn!(
                            "session",
                            "bridge read error ('{label}' generation {my_gen}): {e}"
                        );
                        break;
                    }
                };
                let resp = match resp {
                    Some(r) => r,
                    None => {
                        log_info!(
                            "session",
                            "native host '{label}' disconnected (generation {my_gen})"
                        );
                        break;
                    }
                };
                // Ids are globally unique (a single monotonic counter), but
                // uniqueness alone is not enforcement: a hostile or broken
                // extension in browser B could echo an id that belongs to a
                // request sent to browser A. Deliver a response only when its
                // pending entry was sent over THIS connection (generation
                // match); anything else is a protocol violation and drops the
                // offending connection (fail closed). This path locks only the
                // pending mutex, which is compatible with the conns→pending
                // ordering used elsewhere.
                let routed = {
                    let Ok(mut pending_guard) = pending.lock() else {
                        // Poisoned pending map: no delivery can be trusted;
                        // drop this connection (fail closed) and let the
                        // cleanup below do what it still can.
                        log_error!(
                            "session",
                            "pending-call lock poisoned ('{label}' generation {my_gen}); \
                             dropping connection"
                        );
                        break;
                    };
                    match pending_guard.entry(resp.id) {
                        std::collections::hash_map::Entry::Occupied(entry)
                            if entry.get().0 == my_gen =>
                        {
                            RoutedResp::Deliver(entry.remove().1)
                        }
                        std::collections::hash_map::Entry::Occupied(entry) => {
                            RoutedResp::Foreign(entry.get().0)
                        }
                        std::collections::hash_map::Entry::Vacant(_) => RoutedResp::Unknown,
                    }
                };
                match routed {
                    RoutedResp::Deliver(tx) => {
                        let _ = tx.send(resp);
                    }
                    RoutedResp::Foreign(owner) => {
                        log_warn!(
                            "session",
                            "connection '{label}' (generation {my_gen}) answered id {} \
                             belonging to generation {owner}; dropping this connection",
                            resp.id
                        );
                        break;
                    }
                    RoutedResp::Unknown => {
                        log_warn!("session", "no pending caller for id {}", resp.id);
                    }
                }
            }

            // Reader ended (disconnect / error). Under a consistent lock order
            // (conns mutex THEN pending mutex):
            //   1. Clear this label's slot, but ONLY if it still holds our
            //      generation - a newer host may have already replaced us in
            //      the race window, and clobbering it would leave `call`
            //      wrongly failing against a healthy connection.
            //   2. Drop every pending sender tagged with our generation so
            //      those in-flight callers fail fast with `Disconnected`
            //      instead of blocking for the full 120s timeout. Pending
            //      entries of other connections are left untouched.
            let drained = {
                // A poisoned lock here means another thread panicked while
                // holding it; skip the half we cannot trust (and say so) --
                // any caller whose entry survives fails via its timeout.
                let mut conns_guard = match conns.lock() {
                    Ok(guard) => Some(guard),
                    Err(_) => {
                        log_error!(
                            "session",
                            "browser registry lock poisoned during '{label}' cleanup \
                             (generation {my_gen})"
                        );
                        None
                    }
                };
                if let Some(guard) = conns_guard.as_mut() {
                    let current = guard.get(&label).map(|c| c.generation);
                    if should_clear_conn(current, my_gen) {
                        guard.remove(&label);
                    }
                }
                match pending.lock() {
                    Ok(mut pending_guard) => {
                        drain_pending_for_generation(&mut pending_guard, my_gen)
                    }
                    Err(_) => {
                        log_error!(
                            "session",
                            "pending-call lock poisoned during '{label}' cleanup \
                             (generation {my_gen})"
                        );
                        Vec::new()
                    }
                }
            };
            // Senders drop here (locks already released), unblocking callers.
            drop(drained);
        });
        true
    }

    /// The labels of all currently-connected browsers, sorted. Used by the
    /// `list_browsers` tool and by routing errors.
    pub fn labels(&self) -> Vec<String> {
        // A poisoned registry reads as empty: report nothing rather than
        // labels from state we cannot trust (callers then fail NotConnected).
        let mut labels: Vec<String> = match self.conns.lock() {
            Ok(guard) => guard.keys().map(|l| l.as_str().to_string()).collect(),
            Err(_) => {
                log_error!(
                    "session",
                    "browser registry lock poisoned; reporting no browsers"
                );
                Vec::new()
            }
        };
        labels.sort_unstable();
        labels
    }

    /// Sever every live browser connection (the kill switch's teeth on the
    /// browser leg, ADR-0030) and do the registry bookkeeping synchronously:
    /// clear every slot and drain every sent pending caller into
    /// [`CallError::Disconnected`]. The sweep must NOT delegate this to the
    /// reader threads: a reader already blocked in `recv(2)` is not reliably
    /// woken by `shutdown(2)` on macOS (observed live under load: a reader
    /// still parked in `__recvfrom` 90 seconds after the sweep), so
    /// reader-side cleanup may only happen once the peer's end closes. The
    /// generation guard keeps such a late-waking reader honest: its slot is
    /// already gone (or re-occupied by a newer generation), so its own
    /// cleanup degrades to a no-op, and its pending drain finds nothing left.
    ///
    /// The drain covers every pending entry, not just the connections severed
    /// by this call: a kill is global, every entry is in flight by
    /// construction, and an entry left behind by an already-replaced
    /// connection could otherwise still be answered by that connection's
    /// lingering reader after the sweep (see [`drain_pending_all`]). A
    /// response a reader claimed before the sweep (its entry already removed
    /// for delivery) is a call that completed before the kill, not one that
    /// survived it.
    ///
    /// Idempotent: sweeping an already-empty registry signals nobody, and
    /// shutting down a socket twice is harmless, so the broker's watcher may
    /// call this every tick while killed. Returns how many connections were
    /// severed by THIS call.
    pub(crate) fn shutdown_all_browsers(&self) -> usize {
        // The kill switch must bite even after a panic poisoned a lock:
        // severing sockets, dropping slots, and waking callers with a typed
        // disconnect are all safe on inconsistent bookkeeping (they can only
        // make callers fail faster), whereas refusing to sever would leave
        // the bridge alive. Recover both guards.
        let mut conns_guard = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Sever first: the kernel-level cut in both directions (the peer sees
        // EOF, inbound data is discarded) must not depend on the bookkeeping
        // below. A failure here is unexpected on a registered socket; the
        // removal and drain below still neutralize the connection (no caller
        // is left for a late response to reach), so log rather than abort.
        for (label, conn) in conns_guard.iter() {
            if let Err(e) = conn.writer.get_ref().shutdown(std::net::Shutdown::Both) {
                log_warn!("session", "kill sweep: shutdown of '{label}' failed: {e}");
            }
        }
        // Bookkeeping under the same conns -> pending lock order the readers
        // and `try_call` use, so the three paths serialize instead of racing.
        let severed: Vec<Conn> = conns_guard.drain().map(|(_, conn)| conn).collect();
        let drained: Vec<mpsc::Sender<ParsedResp>> = {
            let mut pending_guard = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            drain_pending_all(&mut pending_guard)
        };
        drop(conns_guard);
        let count = severed.len();
        // Locks released: dropping the writers closes our socket handles;
        // dropping the senders wakes the in-flight callers immediately with
        // `Disconnected` (ADR-0030: drained, not left to ride out timeouts).
        drop(severed);
        drop(drained);
        count
    }

    /// Resolve where a call with the given `browser` argument would be routed
    /// right now: the label and that connection's generation. `None` when the
    /// request is unroutable at this moment (nothing connected, unknown label,
    /// or ambiguous). Used by the MCP server to tag audit lines so operators
    /// can correlate a tool call with the specific browser and connection it
    /// ran over, across reconnects. Just a lock and a map - non-blocking.
    pub fn route_info(&self, browser: Option<&str>) -> Option<(String, u64)> {
        // A poisoned registry is unroutable (None), same as nothing connected.
        let conns = self.conns.lock().ok()?;
        let labels: Vec<&str> = conns.keys().map(BrowserLabel::as_str).collect();
        let label = resolve_target(&labels, browser).ok()?;
        // Borrow<str> lets the validated key be probed with the plain string
        // resolve_target picked from this very key set.
        let generation = conns.get(label.as_str())?.generation;
        Some((label, generation.get()))
    }

    /// Send a request to the addressed browser's extension and wait for the
    /// correlated response. `browser` is the tool call's optional `browser`
    /// argument; see [`resolve_target`] for how it picks a connection.
    /// Returns the response data on success, or a typed [`CallError`].
    pub fn call(
        &self,
        op: &str,
        tab_id: Option<i64>,
        args: Value,
        browser: Option<&str>,
    ) -> Result<Value, CallError> {
        // If no native host has connected yet, wait briefly for one. The
        // extension's service worker reconnects on a ~2s timer; right after
        // the MCP client spawns a fresh MCP server, the first tool call can arrive
        // before any host has re-established its bridge connection. Waiting
        // here (rather than failing instantly) makes startup robust. The wait
        // only covers the empty-registry case: once at least one browser is
        // attached, an unknown or ambiguous target is a real error the caller
        // should see immediately, not something to wait out.
        // A poisoned lock skips the wait (reads as non-empty); try_call below
        // then surfaces the failure as a typed error.
        let registry_empty = || self.conns.lock().is_ok_and(|g| g.is_empty());
        if registry_empty() {
            // checked_add: an unrepresentable deadline (Instant near its
            // upper bound) skips the wait rather than panicking.
            if let Some(deadline) =
                std::time::Instant::now().checked_add(std::time::Duration::from_secs(12))
            {
                while std::time::Instant::now() < deadline {
                    if !registry_empty() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(150));
                }
            }
        }

        // Generous response timeout: the extension may need to prompt the
        // user (Toast) for high-risk actions, which can take a while.
        self.try_call(op, tab_id, args, browser, Duration::from_secs(120))
    }

    /// Like [`call`], but with no startup wait (an empty registry fails
    /// immediately with [`CallError::NotConnected`]) and a caller-chosen
    /// response timeout. Used by enumeration (`list_browsers`), which must
    /// stay responsive when a browser is wedged: one dead connection may cost
    /// at most `timeout`, never the interactive 120s, and never a connect
    /// wait.
    pub fn try_call(
        &self,
        op: &str,
        tab_id: Option<i64>,
        args: Value,
        browser: Option<&str>,
        timeout: Duration,
    ) -> Result<Value, CallError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel::<ParsedResp>();

        // Resolve the target, register the pending entry, and send, all under
        // the registry lock so the chosen connection cannot be swapped between
        // the decision and the write. The entry is inserted ALREADY BOUND to
        // the resolved connection's generation, immediately before the write:
        // an unbound in-flight request is unrepresentable (there is no unsent
        // state to rebind later), and the response cannot beat the
        // registration because the request is not on the wire until after the
        // insert. Lock ordering is always conns mutex THEN pending mutex when
        // nesting, matching the reader-cleanup path, so the two can never
        // deadlock. A poisoned lock anywhere on this path refuses the call
        // with a typed internal error instead of acting on suspect state.
        {
            let Ok(mut guard) = self.conns.lock() else {
                return Err(CallError::Internal("browser registry lock poisoned".into()));
            };
            let labels: Vec<&str> = guard.keys().map(BrowserLabel::as_str).collect();
            let label = resolve_target(&labels, browser)?;
            // Borrow<str>: probe the validated key set with the plain string
            // resolve_target picked from it.
            let Some(conn) = guard.get_mut(label.as_str()) else {
                // Unreachable in practice: resolve_target picked the label
                // from this very map under the same lock. Refuse rather than
                // panic if that invariant is ever broken.
                return Err(CallError::Internal(
                    "resolved browser label vanished from the registry".into(),
                ));
            };
            let generation = conn.generation;
            match self.pending.lock() {
                Ok(mut pending_guard) => {
                    pending_guard.insert(id, (generation, tx));
                }
                Err(_) => {
                    // Do not send a request whose response could never be
                    // routed back (no entry would be waiting for it).
                    return Err(CallError::Internal("pending-call lock poisoned".into()));
                }
            }
            let req = BridgeReq {
                id,
                op: op.to_string(),
                tab_id,
                args,
                browser: Some(label),
            };
            if let Err(e) = bridge_write(&mut conn.writer, &req) {
                self.remove_pending(id);
                return Err(CallError::Write(e));
            }
        }

        // Wait for the response. The boundary parse already reduced it to
        // exactly success-with-data or failure-with-error, so there is no
        // flag-and-optionals mixture left to re-interpret here.
        match rx.recv_timeout(timeout) {
            Ok(resp) => resp.outcome.map_err(CallError::Extension),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.remove_pending(id);
                Err(CallError::Timeout(timeout))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.remove_pending(id);
                Err(CallError::Disconnected)
            }
        }
    }

    /// Best-effort removal of a pending entry (error/timeout cleanup). If the
    /// pending lock is poisoned the entry is left behind: the map is already
    /// condemned state and every path that could act on it refuses first.
    fn remove_pending(&self, id: u64) {
        if let Ok(mut pending_guard) = self.pending.lock() {
            pending_guard.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests;
