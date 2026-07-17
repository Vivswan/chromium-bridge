# ADR-0007: Pin the MCP protocol version to 2025-06-18

- **Status**: Accepted
- **Date**: 2026-07-07

## Context

MCP (Model Context Protocol) is evolving quickly. Protocol versions are identified by date strings (such as `2024-11-05`, `2025-06-18`), and versions differ in handshake fields, capability declarations, and message formats.

As an MCP server, browser-bridge has to declare the protocol version it speaks in the `initialize` response and implement to that version. Picking the wrong version makes MCP client handshakes fail or misbehave.

## Decision

**Pin the protocol version to `2025-06-18`** (the current stable version at research time).

Concretely:
- The `initialize` response carries `protocolVersion: "2025-06-18"`
- Implement that version's minimal message set: `initialize` / `notifications/initialized` / `ping` / `tools/list` / `tools/call`
- Do not implement `resources/` / `prompts/` (optional; capabilities declares only `{"tools": {}}`)
- Tool errors use `isError: true` inside the result, not a JSON-RPC error
- Unknown methods return `-32601`

## Alternatives considered

### Option A: use the latest draft version
- **Research finding**: one draft proposes removing the `initialize` / `notifications/initialized` handshake in favor of a stateless model
- **Problem**: at research time **no released client** used this draft
- **Rejected**: using the draft would be incompatible with every real client

### Option B: use the older `2024-11-05`
- **Problem**: the old version's field conventions and capability model diverge from current client implementations
- **Rejected**: MCP clients broadly implement 2025-06-18; using the old version could miss newer conventions

### Option C: negotiate (echo whatever version the client sends)
- **Problem**: the server should declare the version it supports and let the client negotiate. Blindly echoing the client's version means the server claims support for things it never implemented
- **Handling**: the server declares `2025-06-18`; if the client sends a different version, the client decides whether to continue (our implementation does not negotiate actively)

## Consequences

### Positive
- **Compatible with MCP clients**: this is the version MCP clients broadly implement, so the handshake succeeds
- **Stable**: the protocol version is pinned and does not drift with drafts
- **Minimal implementation**: only the required messages, so the code stays small and auditable

### Negative
- **Future follow-up required**: if MCP releases a new stable version and clients upgrade, browser-bridge may need a protocol version bump plus adaptation to the new conventions
- **No active negotiation**: if a client insists on another version we do not downgrade/upgrade (we declare 2025-06-18 outright; if the client refuses it, the connection fails)

## Key implementation details

From the byte-level protocol research (see the architecture research report):

### Transport
- NDJSON, LF-separated, **no embedded newlines** (serde serialization escapes them automatically)
- Receive on stdin, send on stdout, stderr for logs only
- One `\n` per message

### Handshake
```
client -> server: {"jsonrpc":"2.0","id":1,"method":"initialize",
                  "params":{"protocolVersion":"2025-06-18","capabilities":{},...}}
server -> client: {"jsonrpc":"2.0","id":1,"result":{
                  "protocolVersion":"2025-06-18",
                  "capabilities":{"tools":{}},
                  "serverInfo":{"name":"browser-bridge","version":"0.1.0"}}}
client -> server: {"jsonrpc":"2.0","method":"notifications/initialized"}  <- no id, no reply
```

### Tool errors (critical)
Tool-execution failures use **`isError: true` inside the result**, **not** a JSON-RPC error:
```json
{"jsonrpc":"2.0","id":3,"result":{
  "content":[{"type":"text","text":"Error: extension not connected"}],
  "isError":true
}}
```
Rationale: let the model see the error text and self-correct; a JSON-RPC error signals a protocol-level failure and confuses middleware.

### ping must be handled
Clients send `ping` as keepalive; the server must return an empty result:
```json
// in:  {"jsonrpc":"2.0","id":7,"method":"ping"}
// out: {"jsonrpc":"2.0","id":7,"result":{}}
```
Many clients declare the server dead when ping goes unanswered.

## Implementation

The `handle()` function in `src/mcp_server.rs`: 5 method branches plus the default `-32601`.

## Verified

End-to-end tests PASS:
- The initialize response correctly returns protocolVersion/capabilities/serverInfo
- notifications/initialized is correctly swallowed (no response)
- tools/list returns 11 tools
- ping returns an empty result
- Exit code 0, lock file cleanup is correct

## References

- [MCP Lifecycle 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle)
- [MCP Tools 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [MCP Transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
- Draft spec changelog (the stateless-handshake proposal, not adopted)
