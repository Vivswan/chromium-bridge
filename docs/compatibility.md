# Compatibility: protocol and capability versions

> This doc explains the three kinds of "version" in chromium-bridge, the
> compatibility policy for the internal bridge protocol, and the **contract
> status** of the version/capability handshake. The protocol-boundary overview
> is in [architecture.md section 11](./architecture.md#11-protocol-boundary-contracts-error-taxonomy-and-handshake);
> the single source of truth for contracts is the Rust core (ADR-0028).

## Three distinct kinds of "version"

Before talking about compatibility, separate the three levels (see [architecture.md section 11.2](./architecture.md#112-capability--version-handshake-capabilitiesrs--bridge_protocol_version)):

| Version | Value | Single source | What a change means |
|------|------|------|----------|
| MCP JSON-RPC version | date string `2025-06-18` | [ADR-0007](./adr/0007-mcp-protocol-version-2025-06-18.md) | The external protocol between the MCP client and the MCP server; pinned, not changed casually |
| Internal bridge protocol version | monotonic integer (currently `1`) | `BRIDGE_PROTOCOL_VERSION` in [`src/packages/core/src/protocol.rs`](../src/packages/core/src/protocol.rs) | The wire contract between the MCP server, native host, and extension |
| Extension/binary release version | SemVer (such as `0.1.0`) | `Cargo.toml` (see [ADR-0013](./adr/0013-ci-and-toolchain.md)) | The version of release artifacts; release discipline is in [release.md](./release.md) |

This doc focuses on the **internal bridge protocol version**: a small integer that is
incremented only when the bridge wire contract (the `BridgeReq`/`BridgeResp` shapes, the
`hello` handshake, op/capability semantics) changes **incompatibly**. Backward-compatible
changes such as new optional fields, new tools, or new capabilities do not bump it (under
SemVer they land in the minor of the release version, see
[release.md](./release.md#semver-rules)).

## Capability negotiation: capabilities.rs

Besides the protocol version, a connection also negotiates a **capability set**.
[`src/packages/core/src/tools/capabilities.rs`](../src/packages/core/src/tools/capabilities.rs)
groups tools by shared Chrome permission/scope (such as `page_eval`, `cookie_read`,
`page_snapshot_precise`), derived conceptually from the catalogue's
`permission`/`scope` fields. The design intent: on
connect, the extension/native host advertise the capability ids that are **actually
available** (permission granted, tool not disabled), and a tool is callable only if its
capability is advertised.

## Handshake and fail-fast (contract defined, wiring pending)

The doc comment on `BRIDGE_PROTOCOL_VERSION`
([`src/packages/core/src/protocol.rs`](../src/packages/core/src/protocol.rs)) describes the
**intended** negotiation flow, layered on top of the existing `hello` secret authentication (see
[ADR-0002](./adr/0002-three-process-architecture-localhost-tcp.md)):

1. After the secret check passes, the extension reports its `protocolVersion` and its list
   of capability ids.
2. The server compares protocol versions: on incompatibility it **fails fast**, returning
   `PROTOCOL_MISMATCH` from the error taxonomy (`ERROR_SPECS` in
   [`src/packages/core/src/error.rs`](../src/packages/core/src/error.rs); `category: protocol`,
   `retryable: false`) with a clear message, instead of accepting
   the connection and blowing up late with "unknown op" on some later `tools/call`.
3. If a capability required by a tool is not advertised, the tool call is rejected up
   front rather than dispatching an op the extension cannot handle.

**Honest statement of the current state**: this "version + capability handshake" is
currently **defined only in the contract modules** (`BRIDGE_PROTOCOL_VERSION` +
`capabilities.rs`); the handshake **wiring on the code side is not connected yet**. That
is deliberate deferral: the trigger for wiring it up is when the binary and the extension
can be upgraded independently (for example, a Web Store listing or separate release
cadences). What has landed today is the **first stage**: pending requests are bound to a
connection generation, and generation-guarded reconnect keeps an old connection from
affecting a new one (see
[architecture.md section 5.2](./architecture.md#52-native-host-reconnect-flow)). The
`PROTOCOL_MISMATCH` error code is already in place in the contract, ready to enable once
the wiring lands.

## Related

- Error taxonomy and `PROTOCOL_MISMATCH`: [architecture.md section 11.1](./architecture.md#111-error-taxonomy-error_specs),
  [`src/packages/core/src/error.rs`](../src/packages/core/src/error.rs).
- Connection and reconnect semantics: [architecture.md section 5.2](./architecture.md#52-native-host-reconnect-flow),
  [operations.md](./operations.md).
- Release and SemVer discipline: [release.md](./release.md).
