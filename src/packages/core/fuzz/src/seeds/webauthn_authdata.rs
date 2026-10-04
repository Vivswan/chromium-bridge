//! `seeds/webauthn_authdata/`: authenticatorData byte strings for the WebAuthn layout parser, from the
//! core's own encoder (the one its verifier tests sign over). The credential key is the P-256 generator:
//! a point on the curve with no private scalar anywhere.

use chromium_bridge_core::webauthn::encode::{
    authenticator_data, cose_ec2_key, flags, Algorithm, P256_GENERATOR_SEC1,
};
use chromium_bridge_core::webauthn::{AuthenticatorData, RpId};

use super::{Directory, Seed};
use crate::targets;

fn reads(bytes: &[u8]) -> bool {
    AuthenticatorData::parse(bytes).is_ok()
}

pub(super) fn directory() -> Directory {
    let rp = RpId::pinned().hash();
    let id = [0xc1; 32];
    let es256 = cose_ec2_key(&P256_GENERATOR_SEC1, Algorithm::ES256);
    let header = |flag_bits: u8| authenticator_data(&rp, flag_bits, 7, None);
    let attested = |flag_bits: u8, id: &[u8], cose: &[u8]| {
        authenticator_data(&rp, flag_bits, 0, Some((id, cose)))
    };
    let registration = attested(flags::UP | flags::UV | flags::AT, &id, &es256);
    Directory {
        target: targets::WEBAUTHN_AUTHDATA,
        seeds: vec![
            Seed::accepted("assertion_up", header(flags::UP), reads),
            Seed::accepted("assertion_up_uv", header(flags::UP | flags::UV), reads),
            Seed::accepted(
                "assertion_synced_passkey",
                header(flags::UP | flags::UV | flags::BE | flags::BS),
                reads,
            ),
            Seed::accepted("registration_es256", registration.clone(), reads),
            Seed::accepted(
                "registration_backup_eligible",
                attested(flags::UP | flags::AT | flags::BE, &id, &es256),
                reads,
            ),
            Seed::refused("header_short_by_one", header(flags::UP)[..36].to_vec(), reads),
            Seed::refused("reserved_flag_bit", header(flags::UP | 0x02), reads),
            Seed::refused("extensions_flag", header(flags::UP | flags::ED), reads),
            Seed::refused(
                "backup_state_without_eligibility",
                header(flags::UP | flags::BS),
                reads,
            ),
            Seed::refused(
                "trailing_byte",
                [header(flags::UP), vec![0x00]].concat(),
                reads,
            ),
            Seed::refused(
                "attested_flag_without_data",
                header(flags::UP | flags::AT),
                reads,
            ),
            Seed::refused(
                "attested_truncated_in_credential_id",
                registration[..37 + 16 + 2 + 8].to_vec(),
                reads,
            ),
            Seed::refused(
                "credential_id_15_bytes",
                attested(flags::UP | flags::AT, &[0xc1; 15], &es256),
                reads,
            ),
            Seed::refused(
                "rs256_key",
                attested(
                    flags::UP | flags::AT,
                    &id,
                    &cose_ec2_key(&P256_GENERATOR_SEC1, Algorithm::RS256),
                ),
                reads,
            ),
            Seed::refused(
                "coordinates_31_bytes",
                attested(
                    flags::UP | flags::AT,
                    &id,
                    &cose_ec2_key(&P256_GENERATOR_SEC1[..63], Algorithm::ES256),
                ),
                reads,
            ),
            Seed::refused(
                "bytes_after_cose_key",
                [registration, vec![0xa0]].concat(),
                reads,
            ),
            Seed::refused("empty", Vec::new(), reads),
        ],
    }
}
