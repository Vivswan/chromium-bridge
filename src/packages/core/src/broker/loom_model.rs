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
