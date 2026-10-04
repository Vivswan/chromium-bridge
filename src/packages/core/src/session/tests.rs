use super::*;

/// A test generation; panics on 0, which is exactly the point -- a real
/// [`Generation`] cannot be zero.
fn gen(n: u64) -> Generation {
    Generation(std::num::NonZeroU64::new(n).unwrap())
}

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
fn generations_are_monotonic_and_never_zero() {
    // Mirrors the `next_gen` counter: strictly increasing from 1, and the
    // mint refuses a zero value, so `Generation` is non-zero by
    // construction.
    let next = AtomicU64::new(1);
    let mint = || std::num::NonZeroU64::new(next.fetch_add(1, Ordering::SeqCst)).map(Generation);
    let (a, b, c) = (mint().unwrap(), mint().unwrap(), mint().unwrap());
    assert_eq!((a.get(), b.get(), c.get()), (1, 2, 3));
    assert!(a.get() < b.get() && b.get() < c.get());
    assert_eq!(std::num::NonZeroU64::new(0).map(Generation), None);
}

#[test]
fn clear_decision_only_true_when_current_matches_mine() {
    // Slot still holds my generation -> I own it, so I must clear it.
    assert!(should_clear_conn(Some(gen(7)), gen(7)));
    // A newer connection replaced the slot -> leave it untouched (this is
    // the clobber the generation guard fixes).
    assert!(!should_clear_conn(Some(gen(8)), gen(7)));
    // An older generation must never clear a newer live slot.
    assert!(!should_clear_conn(Some(gen(2)), gen(5)));
    // Slot already empty -> nothing to clear.
    assert!(!should_clear_conn(None, gen(7)));
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
    let CallError::AmbiguousBrowser(labels) = err else {
        panic!("expected AmbiguousBrowser, got {err:?}");
    };
    assert_eq!(labels, "brave, chrome");
    // An explicit argument disambiguates.
    assert_eq!(
        resolve_target(&["chrome", "brave"], Some("brave")).unwrap(),
        "brave"
    );
}

#[test]
fn resolve_rejects_an_unknown_label_naming_what_is_live() {
    let err = resolve_target(&["chrome", "brave"], Some("edge")).unwrap_err();
    let CallError::BrowserNotFound(want, live) = err else {
        panic!("expected BrowserNotFound, got {err:?}");
    };
    assert_eq!(want, "edge");
    assert_eq!(live, "brave, chrome");
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
fn the_connect_wait_ends_at_the_callers_deadline() {
    // The deadline is the caller's whole budget, connect wait included: a call with 200 ms left on an empty
    // registry fails NotConnected at the budget (the actionable error, not a zero timeout), not after the
    // full CONNECT_WAIT a fixed timeout used to impose. The bound is loose on purpose: the suite runs in
    // parallel, and a tight timing assertion would flake where a 12 s regression cannot hide.
    let started = Instant::now();
    let err = Session::new()
        .call(
            BridgeCommand::TabList(crate::tools::args::NoArgs {}),
            None,
            started + Duration::from_millis(200),
        )
        .unwrap_err();
    assert!(matches!(err, CallError::NotConnected), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn severing_a_generation_wakes_only_its_callers_and_keeps_every_entry() {
    // A reader's exit wakes the callers of ITS connection (they fail fast with Disconnected instead of waiting
    // out their deadline) and nobody else's; the entries stay, because the waking caller's guard is what
    // removes them and cancels through the label's replacement connection. An absent generation wakes nobody.
    let mut pending: HashMap<u64, (Generation, mpsc::Sender<Delivery>)> = HashMap::new();
    let (tx1a, rx1a) = mpsc::channel::<Delivery>();
    let (tx1b, rx1b) = mpsc::channel::<Delivery>();
    let (tx2, rx2) = mpsc::channel::<Delivery>();
    pending.insert(10, (gen(1), tx1a));
    pending.insert(11, (gen(1), tx1b));
    pending.insert(20, (gen(2), tx2));

    assert_eq!(sever_pending_for_generation(&pending, gen(99)), 0);
    assert_eq!(sever_pending_for_generation(&pending, gen(1)), 2);
    assert_eq!(pending.len(), 3, "severing removes no entry");
    assert!(matches!(rx1a.try_recv(), Ok(Delivery::Severed)));
    assert!(matches!(rx1b.try_recv(), Ok(Delivery::Severed)));
    // The other connection's caller is untouched: merely empty, not woken.
    assert!(matches!(rx2.try_recv(), Err(mpsc::TryRecvError::Empty)));
}

#[test]
fn the_kill_sweep_wakes_every_caller_including_replaced_generations() {
    // The kill sweep's severance: every caller, including one whose connection already left the registry
    // (replaced by a same-label reconnect) and whose lingering reader could otherwise still answer it after
    // the sweep. There is no unsent state left to special-case: every entry was bound at insert.
    let mut pending: HashMap<u64, (Generation, mpsc::Sender<Delivery>)> = HashMap::new();
    let (tx1, rx1) = mpsc::channel::<Delivery>();
    let (tx2, rx2) = mpsc::channel::<Delivery>();
    pending.insert(10, (gen(1), tx1)); // a replaced (no longer registered) gen
    pending.insert(20, (gen(2), tx2)); // a live gen

    assert_eq!(sever_pending_all(&pending), 2);
    assert_eq!(pending.len(), 2, "severing removes no entry");
    assert!(matches!(rx1.try_recv(), Ok(Delivery::Severed)));
    assert!(matches!(rx2.try_recv(), Ok(Delivery::Severed)));
}

// ---- registry semantics over real socketpairs (unix only) --------------
//
// attach_authenticated skips the handshake, so these tests exercise the
// registry itself: insert, replace-same-label, coexist-across-labels, and
// the per-entry generation guard on disconnect.
#[cfg(unix)]
mod registry {
    use super::*;
    use crate::tools::args::NoArgs;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    /// Attach the server end of a fresh socketpair under `label`,
    /// returning the far (client) end. Dropping the far end disconnects
    /// the reader.
    fn attach(session: &Session, label: &str) -> UnixStream {
        let (srv, cli) = UnixStream::pair().unwrap();
        let reader = BufReader::new(srv.try_clone().unwrap());
        let writer = BufWriter::new(srv);
        // No cap in the registry tests (they exercise replace/coexist/guard
        // semantics, not the browser DoS cap).
        assert!(session.attach_authenticated(
            BrowserLabel::parse(label).unwrap(),
            reader,
            writer,
            None
        ));
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

    /// A `tab_list` round-trip to chrome with its own reply budget and no connect wait.
    fn tab_list(session: &Session, budget: Duration) -> Result<Value, CallError> {
        session
            .send(
                BridgeCommand::TabList(NoArgs {}),
                Some("chrome"),
                Instant::now() + budget,
            )
            .and_then(InFlight::wait)
    }

    /// Put a `tab_list` to chrome on the wire with `budget` left, without waiting.
    fn send_tab_list(session: &Session, budget: Duration) -> InFlight<'_> {
        session
            .send(
                BridgeCommand::TabList(NoArgs {}),
                Some("chrome"),
                Instant::now() + budget,
            )
            .unwrap()
    }

    /// The next NDJSON frame the far end (the native host) receives, parsed; panics on EOF or a read
    /// timeout, so the far end's read timeout is the test's own deadline.
    fn next_frame(reader: &mut std::io::BufReader<UnixStream>) -> Value {
        use std::io::BufRead;
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "the far end saw EOF");
        serde_json::from_str(&line).unwrap()
    }

    /// Assert that nothing reaches the far end within `window` (the far end's read timeout is set to it).
    fn expect_silence(reader: &mut std::io::BufReader<UnixStream>, window: Duration) {
        use std::io::BufRead;
        reader.get_ref().set_read_timeout(Some(window)).unwrap();
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => panic!("the far end saw EOF instead of silence"),
            Ok(_) => panic!("an unexpected frame reached the far end: {line}"),
            Err(e) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "unexpected read error: {e}"
            ),
        }
    }

    fn answer(far: &UnixStream, reply: Value) {
        use std::io::Write;
        let mut w = far.try_clone().unwrap();
        w.write_all(format!("{reply}\n").as_bytes()).unwrap();
        w.flush().unwrap();
    }

    #[test]
    fn a_dropped_guard_cancels_once_and_a_late_reply_is_dropped_without_severing() {
        // The cancel leg of the bridge contract, as the extension sees it: a request whose caller gave up is
        // followed by exactly one `cancel` for its id and nothing else; a reply the extension still sends for
        // that id is dropped (no caller) without severing the connection, so the next request on it still
        // round-trips. Before the guard existed, a timed-out request was simply forgotten and the extension
        // kept working on it.
        let session = Session::new();
        let far = attach(&session, "chrome");
        far.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut host = std::io::BufReader::new(far.try_clone().unwrap());

        let in_flight = send_tab_list(&session, Duration::from_millis(50));
        let request = next_frame(&mut host);
        let id = request["id"].as_u64().unwrap();
        // The 50 ms budget runs out unanswered: the caller gives up and the guard drops.
        assert!(matches!(in_flight.wait(), Err(CallError::Timeout(_))));
        assert_eq!(
            next_frame(&mut host),
            serde_json::json!({ "type": "cancel", "id": id })
        );
        expect_silence(&mut host, Duration::from_millis(300));

        // The extension answers anyway (it did not honor the cancel in time): dropped, connection kept.
        answer(
            &far,
            serde_json::json!({ "id": id, "ok": true, "data": "late" }),
        );
        host.get_ref()
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let second = send_tab_list(&session, Duration::from_secs(5));
        let next = next_frame(&mut host);
        assert_ne!(next["id"].as_u64().unwrap(), id, "ids are never reused");
        answer(
            &far,
            serde_json::json!({ "id": next["id"], "ok": true, "data": "fresh" }),
        );
        // The reader consumed the late reply before this one, so a delivered "fresh" proves it is still alive.
        assert_eq!(second.wait().unwrap(), serde_json::json!("fresh"));
        assert_eq!(session.labels(), vec!["chrome"]);
    }

    #[test]
    fn a_deadline_already_passed_sends_nothing() {
        // A request the caller will not wait for must not start a browser action: the connect wait can
        // consume the whole budget, and a cancel after the fact interrupts an action, never undoes it. The
        // browser is attached and routable, so only the budget refuses, as a zero Timeout, and nothing
        // reaches the far end.
        let session = Session::new();
        let far = attach(&session, "chrome");
        let mut host = std::io::BufReader::new(far.try_clone().unwrap());
        let err = session
            .send(
                BridgeCommand::TabList(NoArgs {}),
                Some("chrome"),
                Instant::now(),
            )
            .map(|_| ())
            .unwrap_err();
        assert!(
            matches!(err, CallError::Timeout(d) if d.is_zero()),
            "{err:?}"
        );
        expect_silence(&mut host, Duration::from_millis(300));
    }

    #[test]
    fn a_request_severed_by_its_connection_is_cancelled_through_the_replacement() {
        // The host restarts mid-request (its port dropped, the service worker reconnected, the new host
        // attached) and only then does the old connection's reader see EOF. The caller is woken with
        // Disconnected, and its guard must still cancel the op: the new connection reaches the same service
        // worker, which holds the id in its in-flight table. A drain that removed the entry would lose the
        // cancel here.
        let session = Session::new();
        let old = attach(&session, "chrome");
        old.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut old_host = std::io::BufReader::new(old.try_clone().unwrap());
        let in_flight = send_tab_list(&session, Duration::from_secs(5));
        let id = next_frame(&mut old_host)["id"].as_u64().unwrap();

        let new = attach(&session, "chrome");
        new.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut new_host = std::io::BufReader::new(new.try_clone().unwrap());
        // The old host is gone: its reader sees EOF and wakes the caller.
        drop(old_host);
        drop(old);
        assert!(matches!(in_flight.wait(), Err(CallError::Disconnected)));
        assert_eq!(
            next_frame(&mut new_host),
            serde_json::json!({ "type": "cancel", "id": id })
        );
    }

    #[test]
    fn an_answered_request_sends_no_cancel() {
        // The pending entry is the one record of in-flight: the reader removed it when it delivered the reply,
        // so the guard's Drop has nothing to cancel. A cancel after a reply would make the extension abort
        // whatever op reused nothing (ids are unique) but would still be a frame the contract forbids.
        let session = Session::new();
        let far = attach(&session, "chrome");
        far.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut host = std::io::BufReader::new(far.try_clone().unwrap());

        let in_flight = send_tab_list(&session, Duration::from_secs(5));
        let id = next_frame(&mut host)["id"].as_u64().unwrap();
        answer(
            &far,
            serde_json::json!({ "id": id, "ok": true, "data": [] }),
        );
        assert_eq!(in_flight.wait().unwrap(), serde_json::json!([]));
        expect_silence(&mut host, Duration::from_millis(300));
    }

    #[test]
    fn a_cancel_after_a_same_label_reconnect_reaches_the_new_connection() {
        // Same-label reconnect while a request is in flight: Chrome spawned a new host process, but the
        // service worker running the op (and holding the id in its in-flight table) is the same one, so the
        // cancel must travel over the connection that holds the label now. The replaced connection gets
        // nothing: its host is on the way out.
        let session = Session::new();
        let old = attach(&session, "chrome");
        old.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut old_host = std::io::BufReader::new(old.try_clone().unwrap());
        let in_flight = send_tab_list(&session, Duration::from_secs(5));
        let id = next_frame(&mut old_host)["id"].as_u64().unwrap();

        let new = attach(&session, "chrome");
        new.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut new_host = std::io::BufReader::new(new.try_clone().unwrap());
        drop(in_flight);
        assert_eq!(
            next_frame(&mut new_host),
            serde_json::json!({ "type": "cancel", "id": id })
        );
        expect_silence(&mut old_host, Duration::from_millis(300));
    }

    #[test]
    fn shutdown_all_browsers_severs_every_connection_and_clears_the_registry() {
        use std::io::Read;
        let session = Session::new();
        let mut chrome = attach(&session, "chrome");
        let mut brave = attach(&session, "brave");
        assert_eq!(session.labels(), vec!["brave", "chrome"]);

        // Bound the EOF reads below while the pairs are still connected:
        // macOS fails setsockopt(SO_RCVTIMEO) with EINVAL on a unix
        // socket whose peer end is fully closed, which it may be the
        // instant the sweep returns. Reads still return EOF; only the
        // option set is order-sensitive.
        for far in [&chrome, &brave] {
            far.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        }

        // The kill sweep severs both connections and clears the registry
        // synchronously; there is nothing asynchronous to wait for.
        assert_eq!(session.shutdown_all_browsers(), 2);
        assert!(session.labels().is_empty());

        // Each far end sees EOF (the native host exits on it). The read
        // timeout is a fail-fast bound, not a synchronization point: the
        // EOF is kernel-guaranteed by the shutdown above.
        for far in [&mut chrome, &mut brave] {
            let mut buf = [0u8; 1];
            assert_eq!(far.read(&mut buf).unwrap(), 0, "far end must see EOF");
        }

        // Idempotent: sweeping an empty registry signals nobody.
        assert_eq!(session.shutdown_all_browsers(), 0);
    }

    #[test]
    fn kill_sweep_fails_in_flight_callers_fast_with_disconnected() {
        use std::io::BufRead;
        let session = Session::new();
        let far = attach(&session, "chrome");
        far.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        // Put a call in flight: once its request is readable on the far
        // end, the caller is parked waiting and its pending entry is
        // bound to the live generation (both happen before the write,
        // under the registry lock). The caller timeout only bounds how
        // long a REGRESSION takes to fail; the drain must beat it.
        let s2 = session.clone();
        let caller = thread::spawn(move || tab_list(&s2, Duration::from_secs(15)));
        let mut far_reader = std::io::BufReader::new(far.try_clone().unwrap());
        let mut line = String::new();
        far_reader.read_line(&mut line).unwrap();
        let req: BridgeReq = serde_json::from_str(&line).unwrap();
        assert_eq!(req.browser.as_deref(), Some("chrome"));

        // The sweep itself drains the caller (its reader thread may
        // never observe the shutdown on macOS): the caller must see
        // Disconnected now, not its timeout.
        assert_eq!(session.shutdown_all_browsers(), 1);
        assert!(matches!(
            caller.join().unwrap(),
            Err(CallError::Disconnected)
        ));
    }

    #[test]
    fn kill_sweep_drains_callers_of_an_already_replaced_connection() {
        use std::io::BufRead;

        // A call is in flight on generation G when a same-label reconnect
        // replaces G's slot. G's socket and reader may both still be
        // alive (the reader holds a cloned fd), so a later kill sweep
        // must drain G's caller too: an entry left waiting could
        // otherwise still be answered by the replaced connection AFTER
        // the kill. The sweep drains every sent generation, not just the
        // ones still in the registry.
        let session = Session::new();
        let old = attach(&session, "chrome");
        old.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let s2 = session.clone();
        let caller = thread::spawn(move || tab_list(&s2, Duration::from_secs(15)));
        // The request is on the wire of the OLD connection.
        let mut old_reader = std::io::BufReader::new(old.try_clone().unwrap());
        let mut line = String::new();
        old_reader.read_line(&mut line).unwrap();

        // Same-label reconnect: the registry slot now belongs to a newer
        // generation; the old connection is no longer in the map.
        let _new = attach(&session, "chrome");

        // The sweep severs the new connection (count 1) AND drains the
        // old generation's caller into Disconnected.
        assert_eq!(session.shutdown_all_browsers(), 1);
        assert!(matches!(
            caller.join().unwrap(),
            Err(CallError::Disconnected)
        ));
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
        // No removal event to wait for - poll briefly and require the
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
        let caller = thread::spawn(move || tab_list(&s2, Duration::from_secs(10)));
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
        // data - not the spoofed payload.
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

    #[test]
    fn a_contradictory_response_is_refused_and_drops_the_connection() {
        use std::io::{BufRead, Write};

        // The flat wire shape can spell `ok: true` alongside an `error`;
        // the contract cannot mean it. The boundary parse (ParsedResp)
        // refuses the frame inside bridge_read, so the reader treats it
        // exactly like any malformed frame: the connection is dropped,
        // fail closed, and the in-flight caller sees Disconnected -- the
        // ambiguous payload never reaches anyone.
        let session = Session::new();
        let chrome = attach(&session, "chrome");
        chrome
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let s2 = session.clone();
        let caller = thread::spawn(move || tab_list(&s2, Duration::from_secs(10)));
        let mut chrome_reader = std::io::BufReader::new(chrome.try_clone().unwrap());
        let mut line = String::new();
        chrome_reader.read_line(&mut line).unwrap();
        let req: BridgeReq = serde_json::from_str(&line).unwrap();

        let mut w = chrome.try_clone().unwrap();
        w.write_all(
            format!(
                "{}\n",
                serde_json::json!({
                    "id": req.id, "ok": true, "data": "payload", "error": "also failed?"
                })
            )
            .as_bytes(),
        )
        .unwrap();
        w.flush().unwrap();

        assert!(
            wait_until(|| session.labels().is_empty()),
            "a connection sending a contradictory response must be dropped"
        );
        assert!(matches!(
            caller.join().unwrap(),
            Err(CallError::Disconnected)
        ));
    }

    #[test]
    fn a_new_label_beyond_the_cap_is_refused_but_a_reconnect_is_allowed() {
        // The distinct-browser cap is enforced at attach: with `max` labels
        // present, a NEW label is refused, but a same-label reconnect
        // (which replaces, not adds) still goes through even at the cap.
        let session = Session::new();
        let max = 2;
        let mk = || {
            let (srv, cli) = UnixStream::pair().unwrap();
            (
                BufReader::new(srv.try_clone().unwrap()),
                BufWriter::new(srv),
                cli,
            )
        };
        let lbl = |s: &str| BrowserLabel::parse(s).unwrap();
        let (r1, w1, _c1) = mk();
        assert!(session.attach_authenticated(lbl("a"), r1, w1, Some(max)));
        let (r2, w2, _c2) = mk();
        assert!(session.attach_authenticated(lbl("b"), r2, w2, Some(max)));
        // A third DISTINCT label is refused at the cap.
        let (r3, w3, _c3) = mk();
        assert!(!session.attach_authenticated(lbl("c"), r3, w3, Some(max)));
        assert_eq!(session.labels(), vec!["a", "b"]);
        // A reconnect under an existing label replaces its slot even at cap.
        let (r2b, w2b, _c2b) = mk();
        assert!(session.attach_authenticated(lbl("b"), r2b, w2b, Some(max)));
        assert_eq!(session.labels(), vec!["a", "b"]);
    }
}
