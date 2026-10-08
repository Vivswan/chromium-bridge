//! `seeds/mcp_jsonrpc/`: the JSON-RPC lines `mcp_read` takes from a client, including one `tools/call`
//! per catalogue tool and the `tools/list` result built from the catalogue. The method names are the
//! MCP specification's vocabulary (rmcp serves them); the `_meta` keys are this crate's pinned literals.

use std::io::Cursor;

use genkan_core::protocol::{
    mcp_read, JsonRpc, MCP_META_CLIENT_CAPABILITIES, MCP_META_PROTOCOL_VERSION,
    MCP_META_SERVER_INFO, MCP_PROTOCOL_VERSION,
};
use genkan_core::tools;
use serde_json::{json, Value};

use super::{edited, ndjson, repeated_key, tool_requests, Directory, Seed};
use crate::targets;

fn reads(bytes: &[u8]) -> bool {
    matches!(mcp_read(&mut Cursor::new(bytes)), Ok(Some(_)))
}

/// The `params._meta` block a client speaking MCP_PROTOCOL_VERSION stamps on every request.
fn meta() -> Value {
    json!({
        MCP_META_PROTOCOL_VERSION: MCP_PROTOCOL_VERSION,
        MCP_META_CLIENT_CAPABILITIES: {},
    })
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json_of!(JsonRpc {
        jsonrpc: Some("2.0".into()),
        id: Some(json!(id)),
        method: Some(method.into()),
        params: Some(params),
        result: None,
        error: None,
    })
}

pub(super) fn directory() -> Directory {
    let initialize = request(
        1,
        "initialize",
        json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "example-client", "version": "0.0.0" },
        }),
    );
    let initialized = json_of!(JsonRpc {
        jsonrpc: Some("2.0".into()),
        id: None,
        method: Some("notifications/initialized".into()),
        params: None,
        result: None,
        error: None,
    });
    let discover = request(2, "server/discover", json!({ "_meta": meta() }));
    let tools_list = request(3, "tools/list", json!({ "_meta": meta() }));
    let catalogue: Vec<Value> = tools::all()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema(),
            })
        })
        .collect();
    // A result at MCP_PROTOCOL_VERSION stamps the server identity under `_meta`.
    let tools_list_result = json_of!(JsonRpc::ok(
        json!(3),
        json!({
            "tools": catalogue,
            "_meta": { MCP_META_SERVER_INFO: { "name": "example-server", "version": "0.0.0" } },
        })
    ));
    let result = json_of!(JsonRpc::ok(json!(2), json!({ "ok": true })));
    let error = json_of!(JsonRpc::err(json!(3), -32600, "invalid request"));

    let mut seeds = vec![
        Seed::accepted("request_initialize", ndjson(&initialize), reads),
        Seed::accepted("notification_initialized", ndjson(&initialized), reads),
        Seed::accepted("request_discover", ndjson(&discover), reads),
        Seed::accepted("request_tools_list", ndjson(&tools_list), reads),
        Seed::accepted("response_tools_list", ndjson(&tools_list_result), reads),
        Seed::accepted("response_result", ndjson(&result), reads),
        Seed::accepted("response_error", ndjson(&error), reads),
        // JsonRpc is deliberately not deny_unknown_fields: third-party clients add top-level members.
        Seed::accepted(
            "request_extra_member",
            ndjson(&edited(&initialize, |v| v["extra"] = json!(1))),
            reads,
        ),
        Seed::refused(
            "error_code_not_integer",
            ndjson(&edited(&error, |v| v["error"]["code"] = json!("x"))),
            reads,
        ),
        Seed::refused(
            "jsonrpc_not_string",
            ndjson(&edited(&initialize, |v| v["jsonrpc"] = json!(2))),
            reads,
        ),
        Seed::refused(
            "request_repeated_id",
            [repeated_key(&tools_list, "id"), b"\n".to_vec()].concat(),
            reads,
        ),
        Seed::refused("not_an_object", ndjson(&json!([1])), reads),
        Seed::refused("blank_line", b"\n".to_vec(), reads),
    ];
    for (i, (name, args, _)) in tool_requests().into_iter().enumerate() {
        let id = u64::try_from(i).expect("a small index") + 10;
        let call = request(
            id,
            "tools/call",
            json!({ "name": name, "arguments": args, "_meta": meta() }),
        );
        seeds.push(Seed::accepted(
            format!("request_tools_call_{name}"),
            ndjson(&call),
            reads,
        ));
    }
    Directory {
        target: targets::MCP_JSONRPC,
        seeds,
    }
}
