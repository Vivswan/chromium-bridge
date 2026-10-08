#![no_main]
//! Fuzz the host-key challenge-message builder over the extension-relayed nonce and context fields. Two
//! oracles beyond no-panic: the builder accepts exactly the documented field matrix, and an accepted message
//! is injective in its fields: it opens with the domain and splits back into the same nonce and context.
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use chromium_bridge_core::enclave::{challenge_message, CHALLENGE_DOMAIN, MAX_CONTEXT_LEN};
use chromium_bridge_core::webauthn::MAX_NONCE_LEN;

#[derive(Arbitrary, Debug)]
struct Input {
    nonce: String,
    context: Option<String>,
}

fuzz_target!(|input: Input| {
    let context = input.context.as_deref();
    let nonce_ok = !input.nonce.is_empty()
        && input.nonce.len() <= MAX_NONCE_LEN
        && !input.nonce.contains('\0');
    let context_ok = context.is_none_or(|c| c.len() <= MAX_CONTEXT_LEN && !c.contains('\0'));
    match challenge_message(&input.nonce, context) {
        Ok(message) => {
            assert!(
                nonce_ok && context_ok,
                "builder accepted a field outside the matrix"
            );
            let mut parts = message.split(|b| *b == 0);
            assert_eq!(
                parts.next(),
                Some(CHALLENGE_DOMAIN.as_bytes()),
                "an accepted message opens with the challenge domain"
            );
            assert_eq!(
                parts.next(),
                Some(input.nonce.as_bytes()),
                "the second NUL-separated field is the nonce as given"
            );
            assert_eq!(
                parts.next(),
                Some(context.unwrap_or("").as_bytes()),
                "the third NUL-separated field is the context, empty when absent"
            );
            assert!(
                parts.next().is_none(),
                "a NUL-free field pair splits into exactly three parts"
            );
        }
        Err(_) => assert!(
            !(nonce_ok && context_ok),
            "builder refused a field inside the matrix"
        ),
    }
});
