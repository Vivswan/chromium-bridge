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
//! Pending requests are likewise tagged with the generation they were sent
//! under. When a reader for generation `G` exits, it drains (drops) every
//! pending sender tagged `G`, so those callers fail fast with
//! [`CallError::Disconnected`] instead of waiting the full 120s timeout.
//! Pending entries belonging to other connections survive.

use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use crate::error::CallError;
use crate::ipc;
use crate::protocol::{bridge_read, bridge_write, BridgeReq, BridgeResp};

/// The label assigned to a connection whose handshake carried no label
/// (single-browser installs, pre-label wrappers). Keeps one-browser setups
/// working with zero configuration.
pub const DEFAULT_LABEL: &str = "default";

/// A live, authenticated connection to one browser's native host, paired with
/// the generation id that owns it. Storing the generation alongside the writer
/// makes cleanup atomic under the registry mutex: a reader can compare its own
/// generation against whatever currently occupies its label's slot before
/// touching it.
struct Conn {
    generation: u64,
    writer: BufWriter<ipc::BridgeStream>,
}

/// Pending request callbacks keyed by `BridgeReq.id`. Each entry carries the
/// generation it was sent under, so a disconnecting reader can drop exactly the
/// callers that belonged to its (now-dead) connection.
type Pending = Arc<Mutex<HashMap<u64, (u64, mpsc::Sender<BridgeResp>)>>>;

/// Sentinel generation for a pending entry that has been registered but not yet
/// bound to a live connection (see [`Session::call`]). Real generations start
/// at 1, so a reader draining generation `G >= 1` can never accidentally drop a
/// not-yet-sent pending entry.
const UNSENT_GENERATION: u64 = 0;

/// A reader thread's verdict on one inbound response: deliver it to its
/// waiting caller, refuse it because the pending entry belongs to a different
/// connection ([`RoutedResp::Foreign`] carries the owning generation), or no
/// caller is waiting on that id at all.
enum RoutedResp {
    Deliver(mpsc::Sender<BridgeResp>),
    Foreign(u64),
    Unknown,
}

/// Decide whether a reader thread owning `my_gen` should clear its label's
/// registry slot on disconnect. Clear **only** when the slot still holds *my*
/// generation; a newer connection under the same label (or an already-empty
/// slot) must be left untouched. This is the core of the anti-clobber fix and
/// is unit-tested directly.
fn should_clear_conn(current: Option<u64>, my_gen: u64) -> bool {
    current == Some(my_gen)
}

/// Remove and return every pending entry whose generation matches `my_gen`.
/// Dropping the returned senders wakes those callers immediately with a closed
/// channel (surfaced as [`CallError::Disconnected`]). Entries tagged with any
/// other generation — including other still-live connections — are left in the
/// map. Factored out so the drain policy is unit-testable without sockets.
fn drain_pending_for_generation(
    pending: &mut HashMap<u64, (u64, mpsc::Sender<BridgeResp>)>,
    my_gen: u64,
) -> Vec<mpsc::Sender<BridgeResp>> {
    let ids: Vec<u64> = pending
        .iter()
        .filter(|(_, (gen, _))| *gen == my_gen)
        .map(|(id, _)| *id)
        .collect();
    ids.into_iter()
        .map(|id| pending.remove(&id).expect("id just enumerated").1)
        .collect()
}

/// Pick the connection a request should run over. `available` are the live
/// labels (any order); `want` is the request's optional `browser` argument.
///
/// - `want = Some(label)`: that label must be live, otherwise the caller gets
///   [`CallError::BrowserNotFound`] naming what IS connected.
/// - `want = None` with exactly one connection: route to it (single-browser
///   back-compat — no argument needed when there is nothing to choose).
/// - `want = None` with several connections: refuse with
///   [`CallError::AmbiguousBrowser`] rather than guess — acting in the wrong
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
        None => match labels.len() {
            0 => Err(CallError::NotConnected),
            1 => Ok(labels[0].to_string()),
            _ => Err(CallError::AmbiguousBrowser(labels.join(", "))),
        },
    }
}

/// Shared session. Cheap to clone — everything is behind Arc.
#[derive(Clone)]
pub struct Session {
    /// The currently-connected native hosts, keyed by browser label. Each
    /// entry pairs the writer with its generation so the owning reader can
    /// atomically decide whether to clear it (see module docs).
    conns: Arc<Mutex<HashMap<String, Conn>>>,
    /// Pending request callbacks keyed by BridgeReq.id, tagged by generation.
    pending: Pending,
    next_id: Arc<AtomicU64>,
    /// Monotonic per-connection generation counter, global across labels.
    /// Starts at 1 so that generation 0 is reserved as the
    /// [`UNSENT_GENERATION`] sentinel.
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

    /// Take ownership of a freshly-accepted connection from a native host.
    /// Authenticates it (HMAC challenge-response), then registers it under the
    /// label the handshake carried. A previous connection under the SAME label
    /// is replaced (dropped/closed); connections under other labels are
    /// untouched. Spawns a reader thread that dispatches BridgeResp by id.
    pub fn attach_connection(&self, stream: ipc::BridgeStream) -> io::Result<()> {
        // Authenticate with the HMAC challenge-response before trusting the
        // connection or installing the writer. The same buffered reader/writer
        // carry the handshake and then the session, so no frame is lost. The
        // label is part of the signed response, so it is only honored here,
        // after the MAC verified.
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = BufWriter::new(stream);
        let label = match ipc::server_handshake(&mut reader, &mut writer) {
            Ok(label) => label.unwrap_or_else(|| DEFAULT_LABEL.to_string()),
            Err(e) => {
                log_warn!("session", "rejected inbound connection: {e}");
                return Err(e);
            }
        };
        self.attach_authenticated(label, reader, writer);
        Ok(())
    }

    /// Register an already-authenticated connection under `label` and spawn
    /// its reader. Split from [`attach_connection`] so the registry semantics
    /// (replace-same-label, per-entry generation guard) are testable over a
    /// socketpair without a lock file or handshake.
    fn attach_authenticated(
        &self,
        label: String,
        mut reader: BufReader<ipc::BridgeStream>,
        writer: BufWriter<ipc::BridgeStream>,
    ) {
        // Allocate this connection's generation before publishing the writer, so
        // the writer and its owning generation are installed together.
        let my_gen = self.next_gen.fetch_add(1, Ordering::SeqCst);
        log_info!(
            "session",
            "native host '{label}' connected and authenticated (generation {my_gen})"
        );

        // Store the writer half together with its generation, keyed by label.
        // An existing same-label entry (older connection to the same browser)
        // is dropped here; its reader will observe the disconnect and, thanks
        // to the generation guard below, leave THIS entry alone.
        self.conns.lock().unwrap().insert(
            label.clone(),
            Conn {
                generation: my_gen,
                writer,
            },
        );

        // Spawn the reader: each BridgeResp routes to its pending sender. The
        // reader is bound to `my_gen`; on disconnect it only tears down the
        // connection it actually owns.
        let pending = self.pending.clone();
        let conns = self.conns.clone();
        thread::spawn(move || {
            loop {
                let resp: Option<BridgeResp> = match bridge_read(&mut reader) {
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
                // offending connection (fail closed). An UNSENT entry cannot
                // legally be answered either — its request has not been
                // written to any connection yet. This path locks only the
                // pending mutex, which is compatible with the conns→pending
                // ordering used elsewhere.
                let routed = {
                    let mut pending_guard = pending.lock().unwrap();
                    match pending_guard.get(&resp.id) {
                        Some((gen, _)) if *gen == my_gen => RoutedResp::Deliver(
                            pending_guard.remove(&resp.id).expect("entry just found").1,
                        ),
                        Some((gen, _)) => RoutedResp::Foreign(*gen),
                        None => RoutedResp::Unknown,
                    }
                };
                match routed {
                    RoutedResp::Deliver(tx) => {
                        let _ = tx.send(resp);
                    }
                    RoutedResp::Foreign(owner_gen) => {
                        log_warn!(
                            "session",
                            "connection '{label}' (generation {my_gen}) answered id {} \
                             belonging to generation {owner_gen}; dropping this connection",
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
            //      generation — a newer host may have already replaced us in
            //      the race window, and clobbering it would leave `call`
            //      wrongly failing against a healthy connection.
            //   2. Drop every pending sender tagged with our generation so
            //      those in-flight callers fail fast with `Disconnected`
            //      instead of blocking for the full 120s timeout. Pending
            //      entries of other connections are left untouched.
            let drained = {
                let mut conns_guard = conns.lock().unwrap();
                let current = conns_guard.get(&label).map(|c| c.generation);
                if should_clear_conn(current, my_gen) {
                    conns_guard.remove(&label);
                }
                let mut pending_guard = pending.lock().unwrap();
                drain_pending_for_generation(&mut pending_guard, my_gen)
            };
            // Senders drop here (locks already released), unblocking callers.
            drop(drained);
        });
    }

    /// The labels of all currently-connected browsers, sorted. Used by the
    /// `list_browsers` tool and by routing errors.
    pub fn labels(&self) -> Vec<String> {
        let mut labels: Vec<String> = self.conns.lock().unwrap().keys().cloned().collect();
        labels.sort_unstable();
        labels
    }

    /// Resolve where a call with the given `browser` argument would be routed
    /// right now: the label and that connection's generation. `None` when the
    /// request is unroutable at this moment (nothing connected, unknown label,
    /// or ambiguous). Used by the MCP server to tag audit lines so operators
    /// can correlate a tool call with the specific browser and connection it
    /// ran over, across reconnects. Just a lock and a map — non-blocking.
    pub fn route_info(&self, browser: Option<&str>) -> Option<(String, u64)> {
        let conns = self.conns.lock().unwrap();
        let labels: Vec<&str> = conns.keys().map(String::as_str).collect();
        let label = resolve_target(&labels, browser).ok()?;
        let generation = conns.get(&label)?.generation;
        Some((label, generation))
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
        if self.conns.lock().unwrap().is_empty() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
            while std::time::Instant::now() < deadline {
                if !self.conns.lock().unwrap().is_empty() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
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

        // Register the one-shot receiver BEFORE sending, to avoid a race where
        // the response arrives before we're listening. The generation is not
        // known yet, so tag the entry with the UNSENT sentinel; it is rewritten
        // to the real generation under the conns lock just before the write. A
        // reader draining a real generation (>= 1) will never touch this
        // sentinel entry.
        let (tx, rx) = mpsc::channel::<BridgeResp>();
        self.pending
            .lock()
            .unwrap()
            .insert(id, (UNSENT_GENERATION, tx));

        // Resolve the target and send, all under the registry lock so the
        // chosen connection cannot be swapped between the decision and the
        // write. Lock ordering is always conns mutex THEN pending mutex when
        // nesting, matching the reader-cleanup path, so the two can never
        // deadlock.
        {
            let mut guard = self.conns.lock().unwrap();
            let labels: Vec<&str> = guard.keys().map(String::as_str).collect();
            let label = match resolve_target(&labels, browser) {
                Ok(l) => l,
                Err(e) => {
                    // Clean up the pending entry on failure.
                    self.pending.lock().unwrap().remove(&id);
                    return Err(e);
                }
            };
            let conn = guard
                .get_mut(&label)
                .expect("resolve_target only returns live labels");
            // Bind this pending entry to the live connection's generation so a
            // subsequent disconnect of *this* connection drains it fast.
            let generation = conn.generation;
            if let Some(entry) = self.pending.lock().unwrap().get_mut(&id) {
                entry.0 = generation;
            }
            let req = BridgeReq {
                id,
                op: op.to_string(),
                tab_id,
                args,
                browser: Some(label),
            };
            if let Err(e) = bridge_write(&mut conn.writer, &req) {
                self.pending.lock().unwrap().remove(&id);
                return Err(CallError::Write(e));
            }
        }

        // Wait for the response.
        match rx.recv_timeout(timeout) {
            Ok(resp) => {
                if resp.ok {
                    Ok(resp.data.unwrap_or(Value::Null))
                } else {
                    Err(CallError::Extension(
                        resp.error.unwrap_or_else(|| "unknown error".into()),
                    ))
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.pending.lock().unwrap().remove(&id);
                Err(CallError::Timeout(timeout))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.pending.lock().unwrap().remove(&id);
                Err(CallError::Disconnected)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_session_has_no_connections() {
        // A brand-new session has no attached connection: nothing to list and
        // nothing to route to.
        let session = Session::new();
        assert!(session.labels().is_empty());
        assert_eq!(session.route_info(None), None);
        assert_eq!(session.route_info(Some("chrome")), None);
        // Same via Default, which just forwards to `new`.
        assert!(Session::default().labels().is_empty());
    }

    #[test]
    fn generations_are_monotonic() {
        // Mirrors the `next_gen` counter: strictly increasing, starting at 1 so
        // that 0 stays free as the UNSENT sentinel.
        let next = AtomicU64::new(1);
        let a = next.fetch_add(1, Ordering::SeqCst);
        let b = next.fetch_add(1, Ordering::SeqCst);
        let c = next.fetch_add(1, Ordering::SeqCst);
        assert_eq!((a, b, c), (1, 2, 3));
        assert!(a < b && b < c);
        assert_ne!(a, UNSENT_GENERATION);
    }

    #[test]
    fn clear_decision_only_true_when_current_matches_mine() {
        // Slot still holds my generation -> I own it, so I must clear it.
        assert!(should_clear_conn(Some(7), 7));
        // A newer connection replaced the slot -> leave it untouched (this is
        // the clobber the generation guard fixes).
        assert!(!should_clear_conn(Some(8), 7));
        // An older generation must never clear a newer live slot.
        assert!(!should_clear_conn(Some(2), 5));
        // Slot already empty -> nothing to clear.
        assert!(!should_clear_conn(None, 7));
    }

    #[test]
    fn resolve_routes_the_sole_connection_without_an_argument() {
        // Single browser, no `browser` argument: route to it (back-compat).
        assert_eq!(resolve_target(&["default"], None).unwrap(), "default");
        assert_eq!(resolve_target(&["brave"], None).unwrap(), "brave");
    }

    #[test]
    fn resolve_requires_an_argument_when_several_browsers_are_live() {
        // Two browsers, no argument: refuse rather than guess. The error names
        // the live labels (sorted) so the caller can pick one.
        let err = resolve_target(&["chrome", "brave"], None).unwrap_err();
        match err {
            CallError::AmbiguousBrowser(labels) => assert_eq!(labels, "brave, chrome"),
            other => panic!("expected AmbiguousBrowser, got {other:?}"),
        }
        // An explicit argument disambiguates.
        assert_eq!(
            resolve_target(&["chrome", "brave"], Some("brave")).unwrap(),
            "brave"
        );
    }

    #[test]
    fn resolve_rejects_an_unknown_label_naming_what_is_live() {
        let err = resolve_target(&["chrome", "brave"], Some("edge")).unwrap_err();
        match err {
            CallError::BrowserNotFound(want, live) => {
                assert_eq!(want, "edge");
                assert_eq!(live, "brave, chrome");
            }
            other => panic!("expected BrowserNotFound, got {other:?}"),
        }
    }

    #[test]
    fn resolve_with_nothing_connected_is_not_connected() {
        // Whether or not a label was named, an empty registry is the plain
        // (retryable) not-connected condition.
        assert!(matches!(
            resolve_target(&[], None),
            Err(CallError::NotConnected)
        ));
        assert!(matches!(
            resolve_target(&[], Some("chrome")),
            Err(CallError::NotConnected)
        ));
    }

    #[test]
    fn drain_drops_only_my_generation_and_wakes_those_callers() {
        let mut pending: HashMap<u64, (u64, mpsc::Sender<BridgeResp>)> = HashMap::new();
        // gen 1: two in-flight callers; gen 2: one in-flight caller on another
        // (still-live) connection.
        let (tx1a, rx1a) = mpsc::channel::<BridgeResp>();
        let (tx1b, rx1b) = mpsc::channel::<BridgeResp>();
        let (tx2, rx2) = mpsc::channel::<BridgeResp>();
        pending.insert(10, (1, tx1a));
        pending.insert(11, (1, tx1b));
        pending.insert(20, (2, tx2));

        let drained = drain_pending_for_generation(&mut pending, 1);
        assert_eq!(drained.len(), 2);
        // gen 1 entries removed; the other connection's entry survives.
        assert!(!pending.contains_key(&10));
        assert!(!pending.contains_key(&11));
        assert!(pending.contains_key(&20));

        // Dropping the drained senders closes their channels: those callers
        // observe `Disconnected` immediately rather than waiting 120s.
        drop(drained);
        assert!(matches!(rx1a.recv(), Err(mpsc::RecvError)));
        assert!(matches!(rx1b.recv(), Err(mpsc::RecvError)));

        // The other connection's caller is untouched: its sender is still held
        // in the map, so its receiver is merely empty (not disconnected).
        assert!(matches!(rx2.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn drain_for_absent_generation_is_a_noop() {
        let mut pending: HashMap<u64, (u64, mpsc::Sender<BridgeResp>)> = HashMap::new();
        let (tx, _rx) = mpsc::channel::<BridgeResp>();
        pending.insert(1, (5, tx));

        let drained = drain_pending_for_generation(&mut pending, 99);
        assert!(drained.is_empty());
        // The unrelated entry is left in place.
        assert!(pending.contains_key(&1));
    }

    #[test]
    fn drain_never_touches_unsent_sentinel_entries() {
        // A pending entry that was registered but not yet sent carries the
        // UNSENT sentinel generation and must survive any real-generation drain.
        let mut pending: HashMap<u64, (u64, mpsc::Sender<BridgeResp>)> = HashMap::new();
        let (unsent_tx, unsent_rx) = mpsc::channel::<BridgeResp>();
        let (live_tx, _live_rx) = mpsc::channel::<BridgeResp>();
        pending.insert(1, (UNSENT_GENERATION, unsent_tx));
        pending.insert(2, (1, live_tx));

        let drained = drain_pending_for_generation(&mut pending, 1);
        assert_eq!(drained.len(), 1);
        assert!(pending.contains_key(&1));
        // The sentinel caller is still connected (sender retained in the map).
        assert!(matches!(
            unsent_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    // ---- registry semantics over real socketpairs (unix only) --------------
    //
    // attach_authenticated skips the handshake, so these tests exercise the
    // registry itself: insert, replace-same-label, coexist-across-labels, and
    // the per-entry generation guard on disconnect.
    #[cfg(unix)]
    mod registry {
        use super::*;
        use std::os::unix::net::UnixStream;
        use std::time::Instant;

        /// Attach the server end of a fresh socketpair under `label`,
        /// returning the far (client) end. Dropping the far end disconnects
        /// the reader.
        fn attach(session: &Session, label: &str) -> UnixStream {
            let (srv, cli) = UnixStream::pair().unwrap();
            let reader = BufReader::new(srv.try_clone().unwrap());
            let writer = BufWriter::new(srv);
            session.attach_authenticated(label.to_string(), reader, writer);
            cli
        }

        /// Poll until `cond` holds or a deadline passes. Reader-thread cleanup
        /// is asynchronous, so tests wait on the observable state instead of
        /// sleeping a fixed amount.
        fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if cond() {
                    return true;
                }
                thread::sleep(Duration::from_millis(10));
            }
            false
        }

        #[test]
        fn labels_coexist_and_disconnect_removes_only_that_label() {
            let session = Session::new();
            let chrome = attach(&session, "chrome");
            let _brave = attach(&session, "brave");
            assert_eq!(session.labels(), vec!["brave", "chrome"]);

            // Both routable by name; no-argument routing is ambiguous.
            assert!(session.route_info(Some("chrome")).is_some());
            assert!(session.route_info(Some("brave")).is_some());
            assert_eq!(session.route_info(None), None);

            // Dropping chrome's far end disconnects its reader; only that
            // entry is removed and routing collapses back to the sole brave.
            drop(chrome);
            assert!(wait_until(|| session.labels() == vec!["brave"]));
            assert_eq!(session.route_info(None).unwrap().0, "brave");
        }

        #[test]
        fn same_label_reconnect_replaces_and_old_reader_cannot_clobber() {
            let session = Session::new();
            let old = attach(&session, "chrome");
            let (_, old_gen) = session.route_info(Some("chrome")).unwrap();

            // A second dial-in under the same label replaces the entry with a
            // newer generation immediately.
            let _new = attach(&session, "chrome");
            let (_, new_gen) = session.route_info(Some("chrome")).unwrap();
            assert!(new_gen > old_gen);

            // The OLD connection's reader now observes its disconnect (its
            // writer was dropped by the replacement; drop our far end too).
            // Its generation no longer matches the slot, so it must leave the
            // new entry alone: chrome stays connected at the new generation.
            drop(old);
            // No removal event to wait for — poll briefly and require the
            // entry to still be the new one afterwards.
            thread::sleep(Duration::from_millis(200));
            assert_eq!(
                session.route_info(Some("chrome")).map(|(_, g)| g),
                Some(new_gen)
            );
        }

        #[test]
        fn a_response_from_the_wrong_browser_is_refused_and_drops_it() {
            use std::io::{BufRead, Write};

            let session = Session::new();
            let chrome = attach(&session, "chrome");
            let brave = attach(&session, "brave");

            // A call routed to chrome: capture the request id off chrome's
            // far end, exactly as its extension would see it.
            let s2 = session.clone();
            let caller = thread::spawn(move || {
                s2.try_call(
                    "tab_list",
                    None,
                    serde_json::json!({}),
                    Some("chrome"),
                    Duration::from_secs(10),
                )
            });
            let mut chrome_reader = std::io::BufReader::new(chrome.try_clone().unwrap());
            let mut line = String::new();
            chrome_reader.read_line(&mut line).unwrap();
            let req: BridgeReq = serde_json::from_str(&line).unwrap();
            assert_eq!(req.browser.as_deref(), Some("chrome"));

            // Brave's connection answers chrome's id. The reader must refuse
            // to deliver it (the pending entry belongs to chrome's
            // generation) and drop brave's connection as a protocol violator.
            let mut brave_w = brave.try_clone().unwrap();
            brave_w
                .write_all(
                    format!(
                        "{}\n",
                        serde_json::json!({ "id": req.id, "ok": true, "data": "spoof" })
                    )
                    .as_bytes(),
                )
                .unwrap();
            brave_w.flush().unwrap();
            assert!(
                wait_until(|| session.labels() == vec!["chrome"]),
                "the spoofing connection must be dropped"
            );

            // The genuine browser can still answer, and the caller gets ITS
            // data — not the spoofed payload.
            let mut chrome_w = chrome.try_clone().unwrap();
            chrome_w
                .write_all(
                    format!(
                        "{}\n",
                        serde_json::json!({ "id": req.id, "ok": true, "data": "real" })
                    )
                    .as_bytes(),
                )
                .unwrap();
            chrome_w.flush().unwrap();
            let got = caller.join().unwrap().unwrap();
            assert_eq!(got, serde_json::json!("real"));
        }
    }
}
