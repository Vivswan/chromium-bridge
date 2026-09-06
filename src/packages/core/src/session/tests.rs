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
    let mut pending: HashMap<u64, (Generation, mpsc::Sender<ParsedResp>)> = HashMap::new();
    // gen 1: two in-flight callers; gen 2: one in-flight caller on another
    // (still-live) connection.
    let (tx1a, rx1a) = mpsc::channel::<ParsedResp>();
    let (tx1b, rx1b) = mpsc::channel::<ParsedResp>();
    let (tx2, rx2) = mpsc::channel::<ParsedResp>();
    pending.insert(10, (gen(1), tx1a));
    pending.insert(11, (gen(1), tx1b));
    pending.insert(20, (gen(2), tx2));

    let drained = drain_pending_for_generation(&mut pending, gen(1));
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
    let mut pending: HashMap<u64, (Generation, mpsc::Sender<ParsedResp>)> = HashMap::new();
    let (tx, _rx) = mpsc::channel::<ParsedResp>();
    pending.insert(1, (gen(5), tx));

    let drained = drain_pending_for_generation(&mut pending, gen(99));
    assert!(drained.is_empty());
    // The unrelated entry is left in place.
    assert!(pending.contains_key(&1));
}

#[test]
fn kill_drain_drops_every_entry_including_replaced_generations() {
    // The kill sweep's drain: every entry goes, including one whose
    // connection already left the registry (replaced by a same-label
    // reconnect) -- its lingering reader could otherwise still answer it
    // after the sweep. There is no unsent state left to special-case:
    // every entry was bound to a generation at insert, by construction.
    let mut pending: HashMap<u64, (Generation, mpsc::Sender<ParsedResp>)> = HashMap::new();
    let (tx1, rx1) = mpsc::channel::<ParsedResp>();
    let (tx2, rx2) = mpsc::channel::<ParsedResp>();
    pending.insert(10, (gen(1), tx1)); // a replaced (no longer registered) gen
    pending.insert(20, (gen(2), tx2)); // a live gen

    let drained = drain_pending_all(&mut pending);
    assert_eq!(drained.len(), 2);
    assert!(pending.is_empty());

    drop(drained);
    assert!(matches!(rx1.recv(), Err(mpsc::RecvError)));
    assert!(matches!(rx2.recv(), Err(mpsc::RecvError)));
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
        let caller = thread::spawn(move || {
            s2.try_call(
                "tab_list",
                None,
                serde_json::json!({}),
                Some("chrome"),
                Duration::from_secs(15),
            )
        });
        let mut far_reader = std::io::BufReader::new(far.try_clone().unwrap());
        let mut line = String::new();
        far_reader.read_line(&mut line).unwrap();
        let req: BridgeReq = serde_json::from_str(&line).unwrap();
        assert_eq!(req.browser.as_deref(), Some("chrome"));

        // The sweep itself drains the caller (its reader thread may
        // never observe the shutdown on macOS): the caller must see
        // Disconnected now, not its timeout (ADR-0030).
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
        let caller = thread::spawn(move || {
            s2.try_call(
                "tab_list",
                None,
                serde_json::json!({}),
                Some("chrome"),
                Duration::from_secs(15),
            )
        });
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
