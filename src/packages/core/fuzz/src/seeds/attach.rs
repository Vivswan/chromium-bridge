//! `seeds/attach/`: the post-handshake role-declaration frame, read by `bridge_read::<AttachRequest>`.

use std::io::Cursor;

use chromium_bridge_core::ipc::{HashDigest, TeamId};
use chromium_bridge_core::protocol::{bridge_read, AttachRequest, HarnessId};
use serde_json::json;

use super::{edited, ndjson, repeated_key, Directory, Seed};
use crate::targets;

fn reads(bytes: &[u8]) -> bool {
    matches!(
        bridge_read::<_, AttachRequest>(&mut Cursor::new(bytes)),
        Ok(Some(_))
    )
}

pub(super) fn directory() -> Directory {
    let harness = HarnessId {
        hash: HashDigest::try_from(&[0x11u8; 32][..]).expect("32 bytes is a digest width"),
        team_id: Some(TeamId::try_from("EXAMPLE123").expect("non-empty")),
        name: Some("example-harness".into()),
    };
    let browser = json_of!(AttachRequest::Browser {});
    let client = json_of!(AttachRequest::Client {
        harness: Some(harness)
    });
    let unmeasured = json_of!(AttachRequest::Client { harness: None });
    Directory {
        target: targets::ATTACH,
        seeds: vec![
            Seed::accepted("browser", ndjson(&browser), reads),
            Seed::accepted("client", ndjson(&client), reads),
            Seed::accepted("client_unmeasured", ndjson(&unmeasured), reads),
            Seed::refused(
                "browser_unknown_field",
                ndjson(&edited(&browser, |v| v["surprise"] = json!(true))),
                reads,
            ),
            Seed::refused(
                "unknown_role",
                ndjson(&edited(&browser, |v| v["attach"] = json!("relay"))),
                reads,
            ),
            Seed::refused(
                "client_hash_width_over_bound",
                ndjson(&edited(&client, |v| {
                    v["harness"]["hash"] = json!("11".repeat(33));
                })),
                reads,
            ),
            Seed::refused(
                "client_empty_team_id",
                ndjson(&edited(&client, |v| v["harness"]["team_id"] = json!(""))),
                reads,
            ),
            Seed::refused(
                "client_repeated_key",
                [repeated_key(&client, "attach"), b"\n".to_vec()].concat(),
                reads,
            ),
        ],
    }
}
