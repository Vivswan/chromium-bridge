#![no_main]
//! The MCP JSON-RPC NDJSON reader; the body and its oracle are `targets::mcp_jsonrpc`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| genkan_fuzz::targets::mcp_jsonrpc(data));
