#![no_main]
//! Fuzz the challenge-message builders over the extension-relayed nonce and
//! context fields. Two oracles beyond no-panic: the enrollment and presence
//! builders share one validation matrix (they must agree on Ok/Err), and on
//! success their messages must differ - the domain separation that keeps an
//! enrollment proof from ever replaying as a presence approval.
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use chromium_bridge_core::enclave::{challenge_message, presence_message};

#[derive(Arbitrary, Debug)]
struct Input {
    nonce: String,
    context: Option<String>,
}

fuzz_target!(|input: Input| {
    let enroll = challenge_message(&input.nonce, input.context.as_deref());
    let presence = presence_message(&input.nonce, input.context.as_deref());
    assert_eq!(
        enroll.is_ok(),
        presence.is_ok(),
        "builders disagree on field validity"
    );
    if let (Ok(enroll), Ok(presence)) = (enroll, presence) {
        assert_ne!(enroll, presence, "domain separation must hold");
    }
});
