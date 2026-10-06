//! Session state owned by the MCP server process: the registry of authenticated native-host connections (one per
//! browser) and the pending-request table that correlates each `BridgeResp` to its `BridgeReq` by id.
//!
//! If no host is connected (Chrome closed, SW recycled), [`Session::call`] waits up to [`CONNECT_WAIT`] (bounded
//! by the caller's deadline) for one to attach; the extension re-calls `connectNative` on its own.
//!
//! Connections are keyed by browser label (from the handshake `Response`, trusted only after the HMAC verifies;
//! a missing label maps to [`crate::ipc::DEFAULT_LABEL`]). A new dial-in under the SAME label supersedes that connection:
//! the registry severs the older socket, its host exits on the EOF, and that extension life redials on its own.
//! Different labels coexist. [`resolve_target`] picks the connection for a request.
//!
//! Every connection carries a monotonic `generation` (global across labels), and a pending request is bound to
//! the generation it was sent under at insert, under the registry lock, immediately before the write, so an
//! unbound in-flight entry is unrepresentable. The pending entry is the one record of "no reply yet": the reader
//! removes it when it delivers the reply, and the [`InFlight`] guard removes it on Drop, sending `cancel` through
//! whatever connection holds the label by then. Nothing else removes an entry: a disconnect, a supersession, or
//! the kill sweep only WAKES the caller ([`Delivery::Severed`]), so a request stranded by a host restart is still
//! cancelled on the reconnected host, which reaches the same service worker.
//!
//! ```text
//! reader for generation G exits         -> clears its label's slot ONLY if it still holds G; a newer host that
//!                                          attached in the race window is left alone
//! same reader                           -> wakes every caller whose request went out on G, so they fail fast with
//!                                          `CallError::Disconnected` instead of waiting out their deadline
//! ```

use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::error::CallError;
use crate::ipc::{self, BrowserLabel};
use crate::protocol::{bridge_read, bridge_write, BridgeReq, BridgeSignal, ParsedResp};
use crate::tools::BridgeCommand;

/// Maximum number of concurrent *distinct* browser labels the session holds, a
/// DoS bound on the browser leg. A reconnect under an existing label replaces
/// its slot (it does not grow the set) and is always allowed; only a NEW label
/// beyond the cap is refused. Enforced atomically at the single insert point
/// (see [`Session::attach_browser`]).
pub(crate) const MAX_BROWSERS: usize = 16;

/// How long [`Session::call`] waits for the first host when none is attached: the extension's service worker
/// reconnects on a ~2 s timer, so right after an MCP client spawns a fresh server the first tool call can arrive
/// before any host has re-attached. Only the empty registry waits.
const CONNECT_WAIT: Duration = Duration::from_secs(12);

/// A connection generation. Non-zero by construction: the mint ([`Session::attach_authenticated`]) refuses
/// a wrapped counter, so no sentinel can collide with a real generation.
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

/// A live, authenticated connection to one browser's native host and the generation that owns it.
///
/// Dropping a `Conn` severs its socket, and every path that takes one out of the registry (supersession, the
/// owning reader's cleanup, the kill sweep) drops it once the lock is released, so no removed connection stays
/// open. Dropping the writer alone would not sever it: the reader thread holds a cloned fd.
struct Conn {
    generation: Generation,
    writer: BufWriter<ipc::BridgeStream>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        // `NotConnected` is the peer already gone (the reader saw its EOF first): the same end state.
        if let Err(e) = self.writer.get_ref().shutdown(std::net::Shutdown::Both) {
            if e.kind() != std::io::ErrorKind::NotConnected {
                log_warn!(
                    "session",
                    "shutdown of the socket for generation {} failed: {e}",
                    self.generation
                );
            }
        }
    }
}

/// Pending request callbacks keyed by `BridgeReq.id`, each bound to the generation it was sent under
/// (module docs).
type Pending = Arc<Mutex<HashMap<u64, (Generation, mpsc::Sender<Delivery>)>>>;

/// What a waiting caller receives: the reply, or the news that its connection is gone. Severance travels
/// through the channel instead of dropping the sender so the pending entry survives for the guard's Drop
/// (module docs).
#[derive(Debug)]
enum Delivery {
    Reply(ParsedResp),
    Severed,
}

/// A reader thread's verdict on one inbound response: deliver it to its
/// waiting caller, refuse it because the pending entry belongs to a different
/// connection ([`RoutedResp::Foreign`] carries the owning generation), or no
/// caller is waiting on that id at all.
enum RoutedResp {
    Deliver(mpsc::Sender<Delivery>),
    Foreign(Generation),
    Unknown,
}

/// Whether a reader owning `my_gen` may clear its label's slot on disconnect: only while the slot is still
/// its own, never a newer connection's.
fn should_clear_conn(current: Option<Generation>, my_gen: Generation) -> bool {
    current == Some(my_gen)
}

/// Wake every caller whose request went out on `my_gen` with [`Delivery::Severed`], surfaced as
/// [`CallError::Disconnected`] at once instead of a wait to the deadline. The entries stay: each caller's guard
/// removes its own on Drop and cancels through whatever connection holds the label by then. Entries bound to
/// any other generation - other still-live connections - are untouched. Returns how many were woken.
fn sever_pending_for_generation(
    pending: &HashMap<u64, (Generation, mpsc::Sender<Delivery>)>,
    my_gen: Generation,
) -> usize {
    pending
        .values()
        .filter(|(generation, _)| *generation == my_gen)
        .map(|(_, tx)| {
            // A caller that already stopped listening needs no waking.
            let _ = tx.send(Delivery::Severed);
        })
        .count()
}

/// Wake every caller: a kill is global, and every entry is in flight (module docs), including those whose
/// generation already left the registry.
fn sever_pending_all(pending: &HashMap<u64, (Generation, mpsc::Sender<Delivery>)>) -> usize {
    pending
        .values()
        .map(|(_, tx)| {
            let _ = tx.send(Delivery::Severed);
        })
        .count()
}

/// Pick the connection a request runs over; `available` are the live labels, `want` the request's optional
/// `browser` argument. Refusing to guess among several browsers is deliberate: acting in the wrong logged-in
/// browser is worse than asking the caller to name one.
///
/// ```text
/// `Some(label)`, live             -> that label
/// `Some(label)`, not live         -> `CallError::BrowserNotFound` naming what IS connected
/// `None`, exactly one connection  -> that one (no argument needed when there is nothing to choose)
/// `None`, several                 -> `CallError::AmbiguousBrowser`
/// nothing connected               -> `CallError::NotConnected`
/// ```
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
    conns: Arc<Mutex<HashMap<BrowserLabel, Conn>>>,
    pending: Pending,
    next_id: Arc<AtomicU64>,
    /// Starts at 1, global across labels; [`Generation`] refuses a wrap.
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

    /// Register a freshly-accepted, already-authenticated native-host connection under the `label` the handshake
    /// carried, replacing a previous connection under the SAME label. The caller (the broker accept path) ran the
    /// HMAC handshake and the `AttachRequest::Browser` role read on these same buffered halves, so no frame is lost
    /// and the label is honored only after the MAC verified.
    ///
    /// Returns `false` when [`MAX_BROWSERS`] distinct labels exist and `label` is new.
    /// ```text
    /// cap checked in the insert's lock acquisition -> concurrent new-label attaches cannot each see room
    /// refused peer was already sent `Accepted`     -> simply dropped; the socket closes and the host reconnects
    /// ```
    pub(crate) fn attach_browser(
        &self,
        label: BrowserLabel,
        reader: BufReader<ipc::BridgeStream>,
        writer: BufWriter<ipc::BridgeStream>,
    ) -> bool {
        self.attach_authenticated(label, reader, writer, Some(MAX_BROWSERS))
    }

    /// Register an already-authenticated connection under `label` and spawn its reader; `cap` bounds the
    /// distinct labels (`None` in the registry tests, which run over a socketpair with no lock file or
    /// handshake). The cap check, the generation mint, and the insert share ONE lock acquisition, so the cap
    /// cannot be raced.
    fn attach_authenticated(
        &self,
        label: BrowserLabel,
        mut reader: BufReader<ipc::BridgeStream>,
        writer: BufWriter<ipc::BridgeStream>,
        cap: Option<usize>,
    ) -> bool {
        let (my_gen, superseded) = {
            // A poisoned lock is state nothing may build on; the refused host redials.
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
                // Only a wrapped u64 lands here; the no-panic lint set forbids unwrap, so refuse instead.
                log_error!(
                    "session",
                    "generation counter wrapped; refusing connection '{label}'"
                );
                return false;
            };
            let my_gen = Generation(nz);
            let superseded = guard.insert(
                label.clone(),
                Conn {
                    generation: my_gen,
                    writer,
                },
            );
            (my_gen, superseded)
        };
        log_info!(
            "session",
            "native host '{label}' connected and authenticated (generation {my_gen})"
        );
        if let Some(old) = superseded {
            log_info!(
                "session",
                "native host '{label}' generation {} superseded by generation {my_gen}; closing it so its \
                 extension life reconnects",
                old.generation
            );
            drop(old);
        }

        // Responses are read as [`ParsedResp`], so a frame the wire can spell but the contract cannot mean is
        // a read error here: the connection drops before any caller sees it.
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
                // Ids are globally unique, but uniqueness is not enforcement: a hostile or broken extension in
                // browser B could echo an id belonging to a request sent to browser A. Locks only the pending mutex,
                // compatible with the conns -> pending order.
                //   pending entry sent over THIS connection (generation match)  -> delivered
                //   pending entry owned by another generation                   -> protocol violation; this connection is dropped
                //   no pending entry (its caller gave up and sent `cancel`, or
                //   the id was never issued)                                    -> dropped and logged; the connection stays
                let routed = {
                    let Ok(mut pending_guard) = pending.lock() else {
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
                        // A caller that already gave up (its guard removed nothing: the entry was ours to
                        // remove) needs no delivery.
                        let _ = tx.send(Delivery::Reply(resp));
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
                        log_warn!(
                            "session",
                            "dropping late reply for id {} from '{label}': no caller is waiting (cancelled or never issued)",
                            resp.id
                        );
                    }
                }
            }

            // Reader ended (disconnect / error). Lock order conns THEN pending, as in `send`.
            //   clear this label's slot ONLY if it still holds our generation  -> a newer host may have replaced us
            //                                                                    in the race window; clobbering it
            //                                                                    would fail `call` on a healthy connection
            //   wake every caller whose request went out on our generation      -> they fail fast with `Disconnected`
            //                                                                    instead of waiting out their deadline,
            //                                                                    and their guards cancel through a
            //                                                                    replacement connection if one attached
            let removed = {
                // A poisoned half is skipped; a caller whose entry survives fails via its timeout.
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
                let mut removed = None;
                if let Some(guard) = conns_guard.as_mut() {
                    let current = guard.get(&label).map(|c| c.generation);
                    if should_clear_conn(current, my_gen) {
                        removed = guard.remove(&label);
                    }
                }
                match pending.lock() {
                    Ok(pending_guard) => {
                        sever_pending_for_generation(&pending_guard, my_gen);
                    }
                    Err(_) => {
                        log_error!(
                            "session",
                            "pending-call lock poisoned during '{label}' cleanup \
                             (generation {my_gen})"
                        );
                    }
                }
                removed
            };
            drop(removed);
        });
        true
    }

    /// The labels of all currently-connected browsers, sorted. A poisoned registry reads as empty rather than
    /// reporting labels from suspect state.
    pub fn labels(&self) -> Vec<String> {
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

    /// Sever every live browser connection (the kill switch's teeth on the browser leg) and do the
    /// registry bookkeeping synchronously here, not in the reader threads, so the kill does not wait on a
    /// reader waking. Idempotent, so the broker's watcher may call it every tick while killed; returns how many
    /// connections THIS call severed.
    ///
    /// ```text
    /// late-waking reader           -> its slot is gone or re-occupied (generation guard), so its cleanup is a no-op
    /// EVERY caller woken           -> `sever_pending_all`, including callers of a replaced connection whose
    ///                                 lingering reader could otherwise answer after the sweep; each gets
    ///                                 `CallError::Disconnected` and its guard finds no connection left to cancel on
    /// response claimed pre-sweep   -> a call that completed before the kill, not one that survived it
    /// ```
    pub(crate) fn shutdown_all_browsers(&self) -> usize {
        // Both guards recover from poison: severing and waking are safe on inconsistent bookkeeping (callers
        // only fail faster), while refusing to sever would leave the bridge alive.
        let mut conns_guard = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // conns THEN pending, the order every path keeps.
        let severed: Vec<Conn> = conns_guard.drain().map(|(_, conn)| conn).collect();
        {
            let pending_guard = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sever_pending_all(&pending_guard);
        }
        drop(conns_guard);
        let count = severed.len();
        drop(severed);
        count
    }

    /// Where a call with this `browser` argument would route right now: the label and that connection's
    /// generation, which the audit line carries so a tool call correlates with one browser connection across
    /// reconnects. `None` when unroutable at this moment, a poisoned registry included.
    pub fn route_info(&self, browser: Option<&str>) -> Option<(String, u64)> {
        let conns = self.conns.lock().ok()?;
        let labels: Vec<&str> = conns.keys().map(BrowserLabel::as_str).collect();
        let label = resolve_target(&labels, browser).ok()?;
        let generation = conns.get(label.as_str())?.generation;
        Some((label, generation.get()))
    }

    /// Send a command to the addressed browser's extension and wait for the correlated response until `deadline`.
    /// `browser` is the tool call's optional `browser` argument; see [`resolve_target`] for how it picks a
    /// connection. The deadline is the caller's: it bounds the connect wait and the reply wait together, and when
    /// it passes the request is abandoned with a `cancel` to the extension ([`InFlight`]).
    pub fn call(
        &self,
        command: BridgeCommand,
        browser: Option<&str>,
        deadline: Instant,
    ) -> Result<Value, CallError> {
        // Only the empty registry waits (see CONNECT_WAIT): once a browser is attached, an unknown or ambiguous
        // target is a real error the caller should see immediately, and a poisoned lock reads as non-empty so
        // `send` surfaces the failure as a typed error.
        let registry_empty = || self.conns.lock().is_ok_and(|g| g.is_empty());
        if registry_empty() {
            // checked_add: an unrepresentable connect deadline (Instant near its upper bound) skips the wait
            // rather than panicking.
            let connect_deadline = Instant::now()
                .checked_add(CONNECT_WAIT)
                .map_or(deadline, |until| until.min(deadline));
            // Each sleep is bounded by what is left, so the wait ends at the budget, never a tick past it.
            loop {
                let remaining = connect_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() || !registry_empty() {
                    break;
                }
                thread::sleep(remaining.min(Duration::from_millis(150)));
            }
        }
        self.send(command, browser, deadline)?.wait()
    }

    /// Put a command on the wire to the addressed browser and hand back the guard that owns the wait until
    /// `deadline`. Fails immediately on an empty registry ([`CallError::NotConnected`]), so an enumeration
    /// over several browsers never waits for a connect, and on a deadline already passed
    /// ([`CallError::Timeout`] with a zero budget): a request the caller will not wait for must not start a
    /// browser action the cancel could only interrupt, never undo.
    pub fn send(
        &self,
        command: BridgeCommand,
        browser: Option<&str>,
        deadline: Instant,
    ) -> Result<InFlight<'_>, CallError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel::<Delivery>();

        // Resolve, register the pending entry, and send under the registry lock, so the chosen connection cannot be
        // swapped between the decision and the write, and the response cannot beat the registration.
        //   lock order     -> conns mutex THEN pending mutex, matching the reader-cleanup path, so no deadlock
        //   poisoned lock  -> refuse the call with a typed internal error instead of acting on suspect state
        let Ok(mut guard) = self.conns.lock() else {
            return Err(CallError::Internal("browser registry lock poisoned".into()));
        };
        let labels: Vec<&str> = guard.keys().map(BrowserLabel::as_str).collect();
        let label = resolve_target(&labels, browser)?;
        let Some(conn) = guard.get_mut(label.as_str()) else {
            // resolve_target picked the label from this map under this lock; refuse rather than panic.
            return Err(CallError::Internal(
                "resolved browser label vanished from the registry".into(),
            ));
        };
        let generation = conn.generation;
        let Ok(mut pending_guard) = self.pending.lock() else {
            return Err(CallError::Internal("pending-call lock poisoned".into()));
        };
        // Routing errors first: a budget that ran out while no browser was attached is reported as the
        // missing browser (actionable), not as a zero timeout. The clock is read with both locks held,
        // right before the insert and the write: a write stalled on another connection can hold either
        // lock past this request's deadline, and a request the caller will not wait for must not start.
        let sent = Instant::now();
        if deadline <= sent {
            return Err(CallError::Timeout(Duration::ZERO));
        }
        pending_guard.insert(id, (generation, tx));
        drop(pending_guard);
        let req = BridgeReq {
            id,
            command,
            browser: Some(label.clone()),
        };
        if let Err(e) = bridge_write(&mut conn.writer, &req) {
            // Nothing reached the extension, so there is nothing to cancel: the entry just goes. A poisoned
            // pending lock is condemned state; every path that could act on the entry refuses first.
            if let Ok(mut pending_guard) = self.pending.lock() {
                pending_guard.remove(&id);
            }
            return Err(CallError::Write(e));
        }
        Ok(InFlight {
            session: self,
            id,
            label,
            sent,
            deadline,
            rx,
        })
    }
}

/// A request on the wire, owned by its caller until the reply or the deadline. Dropping it before the reply
/// arrived sends `cancel` for its id to the browser the request was routed to, so the extension stops working
/// on it and the two sides agree the id is dead; dropping it after the reply sends nothing.
///
/// The pending entry is the one record of which case this is (module docs): the reader removes it when it
/// delivers the reply, so Drop cancels exactly when it still finds the entry. The cancel goes to the
/// connection that holds the label NOW: Chrome spawns a host process per port, but the extension's service
/// worker (which runs the op and keys its in-flight table by id) outlives a reconnect, so after a same-label
/// reconnect the new connection is the only way to reach it. A different browser that took the label ignores
/// the unknown id.
///
/// ```text
/// reply delivered         -> wait() returns it; Drop finds no entry, sends nothing
/// deadline passed         -> Timeout; Drop removes the entry and sends cancel to the label's connection
/// connection severed      -> Disconnected (reader exit or kill sweep); Drop removes the entry and cancels
///                            through the connection now holding the label, if any: after a host restart that
///                            is the new host, and it reaches the same service worker
/// label gone              -> nothing to write to; the op ends on its own in the extension
/// ```
#[must_use = "dropping the guard abandons the request and sends cancel"]
pub struct InFlight<'s> {
    session: &'s Session,
    id: u64,
    label: String,
    sent: Instant,
    deadline: Instant,
    rx: mpsc::Receiver<Delivery>,
}

impl InFlight<'_> {
    /// Wait for the reply until the deadline the request was sent with. The boundary parse already reduced
    /// the response to exactly success-with-data or failure-with-error, so there is no flag-and-optionals
    /// mixture left to interpret.
    pub fn wait(self) -> Result<Value, CallError> {
        match self
            .rx
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
        {
            Ok(Delivery::Reply(resp)) => resp.outcome.map_err(CallError::Extension),
            Ok(Delivery::Severed) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(CallError::Disconnected)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(CallError::Timeout(
                self.deadline.saturating_duration_since(self.sent),
            )),
        }
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        // conns THEN pending, the order every path keeps. A poisoned lock means another thread panicked mid-mutation:
        // condemned state nothing acts on, so the cancel is skipped.
        let Ok(mut conns) = self.session.conns.lock() else {
            return;
        };
        let still_pending = match self.session.pending.lock() {
            Ok(mut pending) => pending.remove(&self.id).is_some(),
            Err(_) => return,
        };
        if !still_pending {
            return;
        }
        let Some(conn) = conns.get_mut(self.label.as_str()) else {
            return;
        };
        if let Err(e) = bridge_write(&mut conn.writer, &BridgeSignal::Cancel { id: self.id }) {
            log_warn!(
                "session",
                "could not send cancel for id {} to '{}': {e}",
                self.id,
                self.label
            );
        }
    }
}

#[cfg(test)]
mod tests;
