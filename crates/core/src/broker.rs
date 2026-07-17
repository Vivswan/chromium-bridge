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

use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::allowlist::{self, Decision};
use crate::ipc::{self, BridgeStream};
use crate::protocol::{
    bridge_read, bridge_write, mcp_read, mcp_write, AttachReply, AttachRequest, HarnessId, JsonRpc,
    MCP_MAX_LINE,
};
use crate::session::{Session, DEFAULT_LABEL};

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
    /// `(live_clients, terminal)`. `terminal` latches once [`wait_zero`] has
    /// observed zero under the lock, after which [`try_incr`] refuses so a
    /// racing relay cannot revive a broker that has committed to exit.
    ///
    /// [`try_incr`]: RefCount::try_incr
    /// [`wait_zero`]: RefCount::wait_zero
    state: Mutex<(usize, bool)>,
    reached_zero: Condvar,
    max: usize,
}

impl RefCount {
    fn new(initial: usize, max: usize) -> Self {
        RefCount {
            state: Mutex::new((initial, false)),
            reached_zero: Condvar::new(),
            max,
        }
    }

    /// Try to add a client. Fails (returns false) if the broker is at capacity
    /// or has already committed to shutting down (`terminal`).
    fn try_incr(&self) -> bool {
        let mut g = self.state.lock().unwrap();
        let (count, terminal) = *g;
        if terminal || count >= self.max {
            return false;
        }
        g.0 = count + 1;
        true
    }

    /// Remove a client. Wakes [`wait_zero`](RefCount::wait_zero) when the count
    /// reaches zero.
    fn decr(&self) {
        let mut g = self.state.lock().unwrap();
        debug_assert!(g.0 > 0, "decr underflow");
        g.0 -= 1;
        if g.0 == 0 {
            self.reached_zero.notify_all();
        }
    }

    /// Block until the client count is zero, then latch `terminal` and return.
    /// After this returns, no new client can attach (see
    /// [`try_incr`](RefCount::try_incr)), so the caller can tear the broker down
    /// without racing a fresh attach.
    fn wait_zero(&self) {
        let mut g = self.state.lock().unwrap();
        while g.0 != 0 {
            g = self.reached_zero.wait(g).unwrap();
        }
        g.1 = true;
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

// ---- Broker ----------------------------------------------------------------

struct Broker {
    session: Session,
    refcount: RefCount,
    /// Connections currently in the handshake/attach phase, bounding accept-time
    /// fan-out ([`MAX_PENDING_ATTACH`]).
    pending: AtomicUsize,
}

/// The outcome of the handshake + attach handshake for one connection.
enum Admitted {
    /// A browser native host, ready to join the session registry.
    Browser {
        label: String,
        reader: BufReader<BridgeStream>,
        writer: BufWriter<BridgeStream>,
    },
    /// An admitted relay client; the broker's ref-count has been incremented
    /// and must be decremented when its serve loop ends.
    Client {
        reader: BufReader<BridgeStream>,
        writer: BufWriter<BridgeStream>,
    },
    /// Rejected (refused, unavailable, or a failed handshake): nothing to do.
    Rejected,
}

/// Run as the broker: own the accepted socket, serve this instance's own stdio
/// harness, accept browser and relay attaches, and exit when the last harness
/// detaches. Returns the process exit code.
pub(crate) fn run_broker(listener: ipc::BridgeListener, session: Session) -> i32 {
    // The broker's own stdio harness is the first client, so the count starts
    // at one; it drops to zero only once this harness AND every relay is gone.
    let broker = Arc::new(Broker {
        session,
        refcount: RefCount::new(1, MAX_HARNESS_CLIENTS),
        pending: AtomicUsize::new(0),
    });

    // Accept browser and relay connections off the main thread.
    {
        let broker = Arc::clone(&broker);
        thread::spawn(move || accept_loop(&broker, listener));
    }

    // Serve THIS instance's own harness on stdin/stdout, exactly as the server
    // did before: read JSON-RPC, dispatch against the shared session, respond.
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let _ = serve_jsonrpc(&broker.session, &mut reader, &mut writer, None);

    // Own harness gone (stdin EOF). Drop our ref, then wait until every relay
    // has also detached before tearing down the socket/lock. If relays are
    // still attached, the broker keeps serving them; it exits only when the
    // last one leaves.
    broker.refcount.decr();
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
                let n = broker.pending.fetch_add(1, Ordering::SeqCst);
                if n >= MAX_PENDING_ATTACH {
                    broker.pending.fetch_sub(1, Ordering::SeqCst);
                    log_warn!("broker", "too many pending attaches; dropping a connection");
                    continue;
                }
                let broker = Arc::clone(broker);
                thread::spawn(move || {
                    let outcome = admit(&broker, stream);
                    // The handshake phase is over; free its slot before any
                    // long-lived serve so pending only bounds handshakes.
                    broker.pending.fetch_sub(1, Ordering::SeqCst);
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
                        } => {
                            let mut limiter = RateLimiter::new();
                            let _ = serve_jsonrpc(
                                &broker.session,
                                &mut reader,
                                &mut writer,
                                Some(&mut limiter),
                            );
                            broker.refcount.decr();
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
fn admit(broker: &Broker, stream: BridgeStream) -> Admitted {
    // Single chokepoint: reject any peer that is not this same user, before
    // authentication (as the accept loop did previously). Unix only.
    #[cfg(unix)]
    {
        let want = unsafe { libc::geteuid() };
        match ipc::peer_uid(&stream) {
            Ok(uid) if uid == want => {}
            Ok(uid) => {
                log_warn!(
                    "broker",
                    "rejected bridge connection from uid {uid} (broker euid {want})"
                );
                return Admitted::Rejected;
            }
            Err(e) => {
                log_warn!(
                    "broker",
                    "rejected bridge connection: peer uid unknown: {e}"
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
        AttachRequest::Browser => admit_browser(label, reader, writer),
        AttachRequest::Client { harness } => admit_client(broker, harness, reader, writer),
    }
}

fn admit_browser(
    label: Option<String>,
    reader: BufReader<BridgeStream>,
    mut writer: BufWriter<BridgeStream>,
) -> Admitted {
    let label = label.unwrap_or_else(|| DEFAULT_LABEL.to_string());
    // The distinct-browser cap ([`Session::attach_browser`], MAX_BROWSERS) is
    // the sole, atomic authority: it is checked under the same lock that
    // inserts, so no pre-check here can race it. We accept optimistically; if a
    // browser loses the cap race at insert time it is dropped and reconnects
    // (a benign, self-healing degradation only reachable at a pathological
    // browser count). See the note on `attach_browser`.
    if bridge_write(&mut writer, &AttachReply::Accepted).is_err() {
        return Admitted::Rejected;
    }
    // Steady state: an idle browser connection is normal, so clear the timeout.
    clear_read_timeout(&writer);
    Admitted::Browser {
        label,
        reader,
        writer,
    }
}

fn admit_client(
    broker: &Broker,
    harness: Option<HarnessId>,
    reader: BufReader<BridgeStream>,
    mut writer: BufWriter<BridgeStream>,
) -> Admitted {
    // Admission decision: check the relay's reported (attested) harness
    // identity against the allowlist. A failure to LOAD the allowlist is
    // fail-closed (do not treat a damaged allowlist as unenrolled).
    let list = match allowlist::Allowlist::load() {
        Ok(l) => l,
        Err(e) => {
            log_error!("broker", "refusing relay: cannot read allowlist: {e}");
            let _ = bridge_write(
                &mut writer,
                &AttachReply::Refused {
                    reason: "allowlist unreadable".into(),
                },
            );
            return Admitted::Rejected;
        }
    };
    let identity = harness.as_ref().map(|h| ipc::ClientIdentity {
        hash: h.hash.clone(),
        team_id: h.team_id.clone(),
    });
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
            log_warn!(
                "broker",
                "refused relay: harness (name {:?}) is not in the trusted-client allowlist",
                reported_name.as_deref().unwrap_or("-")
            );
            let _ = bridge_write(
                &mut writer,
                &AttachReply::Refused {
                    reason: "harness not in trusted-client allowlist".into(),
                },
            );
            return Admitted::Rejected;
        }
        Decision::AdmitUnenrolled => {
            log_error!(
                "broker",
                "SECURITY: relay admitted WITHOUT harness attestation -- no trusted-client \
                 allowlist exists yet (unenrolled). Any same-user process that runs our binary \
                 can drive the browser through this relay. Run `chromium-bridge pair-client` to \
                 enroll trusted clients and turn on enforcement. See SECURITY.md."
            );
        }
        Decision::Admit { name } => {
            log_info!("broker", "relay admitted for trusted client '{name}'");
        }
    }

    // Capacity + terminal check. Refuse-as-unavailable (retryable) rather than
    // deny, so a relay that lost the race to a shutting-down or full broker
    // retries instead of failing the user's session.
    if !broker.refcount.try_incr() {
        let _ = bridge_write(
            &mut writer,
            &AttachReply::Unavailable {
                reason: "broker at capacity or shutting down".into(),
            },
        );
        return Admitted::Rejected;
    }
    if bridge_write(&mut writer, &AttachReply::Accepted).is_err() {
        broker.refcount.decr();
        return Admitted::Rejected;
    }
    clear_read_timeout(&writer);
    Admitted::Client { reader, writer }
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
/// loop continues; EOF ends it). When a `limiter` is present (relay), a request
/// over the per-relay rate limit drops the connection (fail closed).
fn serve_jsonrpc<R: BufRead, W: Write>(
    session: &Session,
    reader: &mut R,
    writer: &mut W,
    mut limiter: Option<&mut RateLimiter>,
) -> io::Result<()> {
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
        if let Some(l) = limiter.as_deref_mut() {
            if !l.allow() {
                log_warn!(
                    "broker",
                    "relay exceeded its request rate limit; dropping it"
                );
                return Err(io::Error::other("relay rate limit exceeded"));
            }
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
        Ok(Some(AttachReply::Accepted)) => {}
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

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn refcount_incr_decr_and_capacity() {
        let rc = RefCount::new(1, 3);
        assert!(rc.try_incr()); // 2
        assert!(rc.try_incr()); // 3
        assert!(!rc.try_incr(), "at capacity");
        rc.decr(); // 2
        assert!(rc.try_incr(), "room again after a detach"); // 3
    }

    #[test]
    fn refcount_wait_zero_returns_when_drained_and_latches_terminal() {
        let rc = RefCount::new(1, 4);
        rc.decr(); // own harness gone -> 0
        rc.wait_zero(); // returns immediately, latches terminal
        assert!(
            !rc.try_incr(),
            "no attach after the terminal shutdown decision"
        );
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
            let rc = Arc::new(RefCount::new(1, 4));

            // A relay races: it may attach (incrementing) and later detach, or
            // lose the race and be refused. Whichever happens, the counts must
            // stay balanced and the shutdown must fire exactly once at zero.
            let relay = {
                let rc = Arc::clone(&rc);
                thread::spawn(move || {
                    if rc.try_incr() {
                        rc.decr();
                    }
                })
            };

            // The broker's own harness detaches (stdin EOF), then the broker
            // waits for every remaining client to leave before tearing down.
            rc.decr();
            rc.wait_zero();

            // After the terminal decision no fresh attach may succeed: a relay
            // that dials now must be turned away (it will retry / become the
            // new broker) rather than attaching to a broker mid-teardown.
            assert!(
                !rc.try_incr(),
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
            let rc = Arc::new(RefCount::new(1, 4));
            let a = {
                let rc = Arc::clone(&rc);
                thread::spawn(move || {
                    if rc.try_incr() {
                        rc.decr();
                    }
                })
            };
            let b = {
                let rc = Arc::clone(&rc);
                thread::spawn(move || {
                    if rc.try_incr() {
                        rc.decr();
                    }
                })
            };
            rc.decr();
            rc.wait_zero();
            a.join().unwrap();
            b.join().unwrap();
        });
    }
}
