use super::*;
use proptest::prelude::*;
use serde_json::Map;
use std::io::Cursor;

/// A bounded, arbitrary JSON string built from arbitrary Unicode scalar
/// values (control chars included - serde escapes them). Avoids the
/// `regex-syntax` proptest feature so the dependency tree stays lean.
fn arb_string() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..12).prop_map(|cs| cs.into_iter().collect())
}

/// A bounded, arbitrary JSON value. Numbers are integers only: JSON cannot
/// represent NaN/Infinity, and `serde_json::Number` rejects them, so a
/// float strategy would generate unserializable values. Depth and breadth
/// are capped to keep each case small and fast.
fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(n.into())),
        arb_string().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 48, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec((arb_string(), inner), 0..6)
                .prop_map(|kvs| Value::Object(kvs.into_iter().collect::<Map<String, Value>>())),
        ]
    })
}

/// Like [`arb_json`] but never `null` at the top level. For `Option<Value>`
/// fields, `Some(Value::Null)` serializes as `null` and deserializes back
/// as `None` - an intentional serde asymmetry that would make an exact
/// roundtrip comparison spuriously fail. Nested nulls are still allowed.
fn arb_json_non_null() -> impl Strategy<Value = Value> {
    arb_json().prop_filter("non-null at top level", |v| !v.is_null())
}

proptest! {
    // --- 1. Roundtrip ---------------------------------------------------

    /// Native-messaging framing carries arbitrary byte payloads faithfully
    /// (bytes modelled as a JSON array of integers, the shape the frame
    /// body actually transports).
    #[test]
    fn nm_frame_carries_bytes(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let payload = Value::Array(
            bytes.iter().map(|b| Value::Number((*b as u64).into())).collect(),
        );
        let mut buf = Vec::new();
        nm_write_frame(&mut buf, &payload).unwrap();
        // 4-byte LE length prefix precedes the body.
        let body_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        prop_assert_eq!(body_len, buf.len() - 4);
        let got = nm_read_frame(&mut Cursor::new(buf)).unwrap().unwrap();
        prop_assert_eq!(got, payload);
    }

    /// Any bounded JSON value survives a native-messaging frame roundtrip.
    #[test]
    fn nm_frame_value_roundtrip(v in arb_json()) {
        let mut buf = Vec::new();
        nm_write_frame(&mut buf, &v).unwrap();
        let got = nm_read_frame(&mut Cursor::new(buf)).unwrap().unwrap();
        prop_assert_eq!(got, v);
    }

    /// A JSON-RPC message survives an MCP NDJSON roundtrip, and always
    /// serializes to exactly one line.
    #[test]
    fn mcp_roundtrip(
        jsonrpc in prop::option::of(arb_string()),
        id in prop::option::of(arb_json_non_null()),
        method in prop::option::of(arb_string()),
        params in prop::option::of(arb_json_non_null()),
    ) {
        let msg = JsonRpc {
            jsonrpc,
            id,
            method,
            params,
            result: None,
            error: None,
        };
        let mut buf = Vec::new();
        mcp_write(&mut buf, &msg).unwrap();
        // NDJSON invariant: exactly one newline, the frame terminator.
        prop_assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);
        let got = mcp_read(&mut Cursor::new(buf)).unwrap().unwrap();
        prop_assert_eq!(
            serde_json::to_value(&got).unwrap(),
            serde_json::to_value(&msg).unwrap(),
        );
    }

    /// A bridge request survives an NDJSON roundtrip over the envelope.
    #[test]
    fn bridge_req_roundtrip(
        id in any::<u64>(),
        op in arb_string(),
        tab_id in prop::option::of(any::<i64>()),
        args in arb_json(),
        browser in prop::option::of(arb_string()),
    ) {
        let req = BridgeReq { id, op, tab_id, args, browser };
        let mut buf = Vec::new();
        bridge_write(&mut buf, &req).unwrap();
        let got: BridgeReq = bridge_read(&mut Cursor::new(buf)).unwrap().unwrap();
        prop_assert_eq!(
            serde_json::to_value(&got).unwrap(),
            serde_json::to_value(&req).unwrap(),
        );
    }

    /// A bridge response survives an NDJSON roundtrip over the envelope.
    #[test]
    fn bridge_resp_roundtrip(
        id in any::<u64>(),
        ok in any::<bool>(),
        data in prop::option::of(arb_json_non_null()),
        error in prop::option::of(arb_string()),
    ) {
        let resp = BridgeResp { id, ok, data, error };
        let mut buf = Vec::new();
        bridge_write(&mut buf, &resp).unwrap();
        let got: BridgeResp = bridge_read(&mut Cursor::new(buf)).unwrap().unwrap();
        prop_assert_eq!(
            serde_json::to_value(&got).unwrap(),
            serde_json::to_value(&resp).unwrap(),
        );
    }

    /// The boundary parse admits exactly the two legal response states:
    /// over the whole `{ ok, data?, error? }` space, `ParsedResp` accepts
    /// success-without-error and failure-with-error-without-data, maps
    /// them to the matching `outcome`, and refuses every other mixture.
    #[test]
    fn parsed_resp_matrix(
        id in any::<u64>(),
        ok in any::<bool>(),
        data in prop::option::of(arb_json_non_null()),
        error in prop::option::of(arb_string()),
    ) {
        let wire = BridgeResp { id, ok, data: data.clone(), error: error.clone() };
        let parsed = ParsedResp::try_from(wire);
        match (ok, data, error) {
            (true, data, None) => {
                let parsed = parsed.unwrap();
                prop_assert_eq!(parsed.id, id);
                prop_assert_eq!(parsed.outcome, Ok(data.unwrap_or(Value::Null)));
            }
            (false, None, Some(e)) => {
                let parsed = parsed.unwrap();
                prop_assert_eq!(parsed.id, id);
                prop_assert_eq!(parsed.outcome, Err(e));
            }
            _ => prop_assert!(parsed.is_err(), "a contradictory shape must be refused"),
        }
    }

    // --- 2. Never panics on arbitrary input (the fuzz property) ---------

    /// `nm_read_frame` on arbitrary bytes yields `Ok`/`Err`, never a panic.
    #[test]
    fn nm_read_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = nm_read_frame(&mut Cursor::new(data));
    }

    /// `mcp_read` on arbitrary bytes yields `Ok`/`Err`, never a panic.
    #[test]
    fn mcp_read_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = mcp_read(&mut Cursor::new(data));
    }

    /// `bridge_read` on arbitrary bytes yields `Ok`/`Err`, never a panic.
    #[test]
    fn bridge_read_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _: io::Result<Option<Value>> = bridge_read(&mut Cursor::new(data));
    }

    // --- 3. Size guard --------------------------------------------------

    /// Any length prefix above the 64 MB inbound clamp is rejected with
    /// `InvalidData`, before allocating or reading the claimed body.
    #[test]
    fn nm_oversize_prefix_always_rejected(len in (64u32 * 1024 * 1024 + 1)..=u32::MAX) {
        let mut framed = len.to_le_bytes().to_vec();
        // Trailing bytes the guard must refuse to read past.
        framed.extend_from_slice(&[0u8; 8]);
        let err = nm_read_frame(&mut Cursor::new(framed)).unwrap_err();
        prop_assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
