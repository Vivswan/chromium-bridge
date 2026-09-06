use super::*;

fn rev(epoch: u64, latched: bool) -> Revocation {
    Revocation {
        version: 1,
        epoch,
        clients_epoch: 0,
        host_key_epoch: 0,
        policy_epoch: 0,
        lang_epoch: 0,
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
