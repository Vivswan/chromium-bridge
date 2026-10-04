use super::*;

use crate::allowlist::{Anchor, ClientEntry, ClientName};
use crate::trust::{Clients, Posture, Trust};

fn ident(hash: &str) -> ClientIdentity {
    ClientIdentity {
        hash: ipc::HashDigest::try_from(hash).unwrap(),
        signer: None,
    }
}

// Hash anchors are measured-width lowercase hex (ipc::HashDigest); the
// fixtures are cdhash-width stand-ins, and the names say the role each plays.
const H_SELF: &str = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11";
const H_OTHER: &str = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22";
#[cfg(unix)]
const H_KEEP: &str = "cafecafecafecafecafecafecafecafecafecafe";
#[cfg(unix)]
const H_REVOKED: &str = "deaddeaddeaddeaddeaddeaddeaddeaddeaddead";

/// A record at `epoch` whose paired clients are exactly `hashes` (an empty slice is every client revoked).
fn trust_listing(epoch: u64, hashes: &[&str]) -> TrustState {
    TrustState::from(Trust::fixture(epoch, false, paired(hashes)))
}

fn paired(hashes: &[&str]) -> Clients {
    Clients::Paired(
        hashes
            .iter()
            .map(|h| ClientEntry {
                name: ClientName::try_from("c").unwrap(),
                anchor: Anchor::Hash((*h).try_into().unwrap()),
                added_unix: 0,
            })
            .collect(),
    )
}

fn trusted() -> Posture {
    Posture::Trusted { name: "c".into() }
}

/// The per-request gate's whole matrix. The decision is a function of the record's CURRENT content, so a
/// delisted identity is refused on its next request even when the epoch never moved (a hand edit that leaves
/// the counter alone, which an epoch-gated guard served), an unmeasured identity is refused once anything is
/// paired, an unreadable record fails closed, and a connection admitted under enforcement is refused when the
/// record reverts to the bootstrap (the review incident: `rm trust.json` under a live enrolled broker turned
/// it open silently). Only a connection admitted unenrolled is served by the bootstrap.
#[test]
fn request_admission_never_serves_under_a_weaker_posture_than_admitted() {
    let unenrolled = || TrustState::from(Trust::default());
    let cases = [
        (
            "still listed",
            Ok(trust_listing(3, &[H_SELF])),
            Some(ident(H_SELF)),
            trusted(),
            None,
        ),
        (
            "delisted, same epoch",
            Ok(trust_listing(3, &[H_OTHER])),
            Some(ident(H_SELF)),
            trusted(),
            Some(io::ErrorKind::PermissionDenied),
        ),
        (
            "paired, unmeasured",
            Ok(trust_listing(3, &[H_SELF])),
            None,
            Posture::Unenrolled,
            Some(io::ErrorKind::PermissionDenied),
        ),
        (
            "never paired, admitted unenrolled",
            Ok(unenrolled()),
            None,
            Posture::Unenrolled,
            None,
        ),
        (
            "admitted unenrolled, then paired",
            Ok(trust_listing(3, &[H_SELF])),
            Some(ident(H_SELF)),
            Posture::Unenrolled,
            None,
        ),
        (
            "admitted trusted, record reverted to the bootstrap",
            Ok(unenrolled()),
            Some(ident(H_SELF)),
            trusted(),
            Some(io::ErrorKind::PermissionDenied),
        ),
        (
            "unreadable record",
            Err(io::Error::other("corrupt")),
            Some(ident(H_SELF)),
            trusted(),
            Some(io::ErrorKind::InvalidData),
        ),
    ];
    for (case, trust, identity, posture, want) in cases {
        let got = request_admission("t", identity.as_ref(), &posture, trust).map_err(|e| e.kind());
        assert_eq!(got, want.map_or(Ok(()), Err), "{case}");
    }
}

#[cfg(unix)]
mod registry {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    fn killed(epoch: u64, hashes: &[&str]) -> TrustState {
        TrustState::from(Trust::fixture(epoch, true, paired(hashes)))
    }

    /// The far end of a swept relay reads EOF; an untouched relay's read times out.
    fn assert_eof(cli: &mut UnixStream, what: &str) {
        cli.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 1];
        match cli.read(&mut buf) {
            Ok(0) => {}
            other => panic!("{what} must see EOF, got {other:?}"),
        }
    }

    fn assert_connected(cli: &mut UnixStream, what: &str) {
        cli.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut buf = [0u8; 1];
        let err = cli.read(&mut buf).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{what} must remain connected, got {err:?}"
        );
    }

    #[test]
    fn watch_tick_kill_severs_browsers_but_keeps_listed_relays() {
        // The kill sweep runs the browser-drop closure while the switch is engaged, on EVERY tick
        // (idempotent), while a still-listed relay keeps its connection: its tool calls are refused at
        // dispatch with the typed error instead, so the refusal is deliverable.
        let registry = ClientRegistry::new();
        let (srv, mut cli) = UnixStream::pair().unwrap();
        let _slot = registry
            .register(Some(ident(H_KEEP)), trusted(), srv)
            .unwrap();

        let browsers = std::cell::Cell::new(0usize);
        let seen = watch_tick(&registry, 9, Ok(killed(9, &[H_KEEP])), || {
            browsers.set(browsers.get() + 1);
            2
        });
        assert_eq!(seen, Some(9));
        assert_eq!(browsers.get(), 1, "the kill must sever the browser leg");
        assert_connected(&mut cli, "a listed relay under a kill");
    }

    #[test]
    fn watch_tick_without_a_kill_never_touches_browsers() {
        let registry = ClientRegistry::new();
        let seen = watch_tick(&registry, 4, Ok(trust_listing(4, &[H_KEEP])), || {
            panic!("browser sweep must not run while the switch is off")
        });
        assert_eq!(seen, Some(4));
    }

    #[test]
    fn watch_tick_drops_exactly_the_delisted_relays_even_on_an_unchanged_epoch() {
        // The sweep is UNCONDITIONAL: a hand edit that delists a client and leaves the counter alone must
        // still be enforced, so the delisted relay is dropped and the listed one kept when the observed
        // epoch equals last_seen.
        let registry = ClientRegistry::new();
        let (a_srv, mut a_cli) = UnixStream::pair().unwrap();
        let (b_srv, mut b_cli) = UnixStream::pair().unwrap();
        let _keep = registry
            .register(Some(ident(H_KEEP)), trusted(), a_srv)
            .unwrap();
        let _revoked = registry
            .register(Some(ident(H_REVOKED)), trusted(), b_srv)
            .unwrap();

        let seen = watch_tick(&registry, 5, Ok(trust_listing(5, &[H_KEEP])), || 0);
        assert_eq!(seen, Some(5));
        assert_eof(&mut b_cli, "the delisted relay");
        assert_connected(&mut a_cli, "the kept relay");
    }

    #[test]
    fn watch_tick_drops_a_trusted_relay_when_the_record_reverts_to_the_bootstrap() {
        // `rm trust.json` under a live enrolled broker: the relay admitted under enforcement is severed (its
        // respawn re-admits under the ERROR-logged bootstrap), while a relay admitted unenrolled stays.
        let registry = ClientRegistry::new();
        let (a_srv, mut a_cli) = UnixStream::pair().unwrap();
        let (b_srv, mut b_cli) = UnixStream::pair().unwrap();
        let _open = registry.register(None, Posture::Unenrolled, a_srv).unwrap();
        let _enforced = registry
            .register(Some(ident(H_KEEP)), trusted(), b_srv)
            .unwrap();

        let seen = watch_tick(&registry, 5, Ok(TrustState::from(Trust::default())), || 0);
        assert_eq!(seen, Some(0));
        assert_eof(&mut b_cli, "the relay admitted under enforcement");
        assert_connected(&mut a_cli, "the relay admitted unenrolled");
    }

    #[test]
    fn watch_tick_fails_closed_dropping_every_relay_and_browser() {
        // Unreadable record: every relay and the browser leg are dropped (the kill state is unknown) and the
        // last-seen epoch is NOT advanced, so the next tick retries and keeps failing closed.
        let registry = ClientRegistry::new();
        let (srv, mut cli) = UnixStream::pair().unwrap();
        let _slot = registry
            .register(Some(ident(H_SELF)), trusted(), srv)
            .unwrap();
        let browsers = std::cell::Cell::new(0usize);
        let seen = watch_tick(&registry, 1, Err(io::Error::other("corrupt")), || {
            browsers.set(browsers.get() + 1);
            3
        });
        assert_eq!(
            browsers.get(),
            1,
            "an unreadable record must sever the browser leg"
        );
        assert_eq!(seen, None);
        assert_eof(&mut cli, "every relay under an unreadable record");
    }

    #[test]
    fn a_dropped_slot_deregisters_so_sweeps_skip_it() {
        let registry = ClientRegistry::new();
        let (srv, _cli) = UnixStream::pair().unwrap();
        let slot = registry
            .register(Some(ident(H_SELF)), trusted(), srv)
            .unwrap();
        drop(slot);
        assert_eq!(
            registry.sweep(|_, _| true),
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
            let _slot = registry
                .register(Some(ident(H_SELF)), trusted(), srv)
                .unwrap();
            // early return: nothing released by hand
        }
        assert_eq!(
            registry.sweep(|_, _| true),
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
