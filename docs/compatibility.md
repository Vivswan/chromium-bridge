# Compatibility: protocol and capability versions

> This doc explains the three kinds of "version" in chromium-bridge, the
> compatibility policy for the internal bridge protocol, and the **contract
> status** of the version/capability handshake. The protocol-boundary overview
> is in [architecture.md section 11](./architecture.md#11-protocol-boundary-contracts-error-taxonomy-and-handshake);
> the single source of truth for contracts is the Rust core (ADR-0028).

## Three distinct kinds of "version"

Before talking about compatibility, separate the three levels (see [architecture.md section 11.2](./architecture.md#112-capability--version-handshake)):

| Version | Value | Single source | What a change means |
|------|------|------|----------|
| MCP JSON-RPC version | date string `2026-07-28` | [ADR-0034](./adr/0034-mcp-2026-07-28-stateless.md) | The external protocol between the MCP client and the MCP server; stateless, gated per request, with temporary legacy-era support for harnesses on the previous revision (ADR-0007) |
| Internal bridge protocol version | monotonic integer (currently `1`) | `BRIDGE_PROTOCOL_VERSION` in [`src/packages/core/src/protocol.rs`](../src/packages/core/src/protocol.rs) | The wire contract between the MCP server, native host, and extension |
| Extension/binary release version | SemVer (such as `0.1.0`) | `Cargo.toml` (see [ADR-0013](./adr/0013-ci-and-toolchain.md)) | The version of release artifacts; release discipline is in [release.md](./release.md) |

This doc focuses on the **internal bridge protocol version**: a small integer that is
incremented only when the bridge wire contract (the `BridgeReq`/`BridgeResp` shapes, the
authentication handshake, op/capability semantics) changes **incompatibly**. Backward-compatible
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
**intended** negotiation flow, layered on top of the existing connection authentication
(peer attestation, the HMAC challenge-response, and the role-declaring attach frame; see
[architecture.md section 3.3](./architecture.md#33-internal-bridge-protocol-broker---native-hosts-and-relays)):

1. After authentication passes, the extension reports its `protocolVersion` and its list
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
[architecture.md section 5.2](./architecture.md#52-native-host-reconnect)). The
`PROTOCOL_MISMATCH` error code is already in place in the contract, ready to enable once
the wiring lands.

## Additive host-handled control frames (ADR-0032): no version bump

[ADR-0032](./adr/0032-host-owned-policy-settings.md) added six control
frames for the host-owned policy and the shared language preference -
`policy_get`, `policy_current`, `legacy_settings`, `lang_get`, `lang_set`,
`lang_current` (see
[architecture.md section 11.3](./architecture.md#113-host-owned-policy-and-language-sync-adr-0032)).
They did NOT bump `BRIDGE_PROTOCOL_VERSION`: every frame is additive and
host-handled, the `BridgeReq`/`BridgeResp` envelopes are untouched, and
both old-peer combinations degrade to the pre-ADR-0032 behavior:

| Skew | Behavior |
|------|----------|
| New extension, old host | The host never pushes a policy frame, so per the never-speak-first rule the extension never sends one either (an old host would classify the unknown frame as forwardable and the MCP server's strict parse would tear the browser leg down). The extension stays on its legacy local settings indefinitely - exactly the pre-ADR-0032 system. |
| Old extension, new host | The old extension drops the unfamiliar `policy_current` push on the floor (pinned by test, not assumed) and keeps enforcing its local settings; the new host still applies its own policy at dispatch, so the combined enforcement is never more permissive than the old extension alone. |

The `policy_current` frame's `reason` field (Phase 4) is additive and
optional the same way: an old host omits it, and the extension reads the
missing field as "never send the legacy bag" - fail closed on the absence
of the signal. When the deferred capability handshake above lands, the
advertised capability set should be computed from the effective policy,
which ADR-0032 makes possible but does not wire.

One platform consequence of the same record is a breaking change without a
version bump: ADR-0032 phase 5 retired the `requireEnrollment` opt-out, so
a Mac without a Secure Enclave (pre-T2 Intel hardware) can no longer
enroll and the bridge stays blocked there permanently - deliberate
fail-closed behavior with no recovery path, since every grant and policy
signature hangs off the enclave key that hardware cannot hold.

## Related

- Error taxonomy and `PROTOCOL_MISMATCH`: [architecture.md section 11.1](./architecture.md#111-error-taxonomy-error_specs),
  [`src/packages/core/src/error.rs`](../src/packages/core/src/error.rs).
- Connection and reconnect semantics: [architecture.md section 5.2](./architecture.md#52-native-host-reconnect),
  [operations.md](./operations.md).
- Release and SemVer discipline: [release.md](./release.md).
