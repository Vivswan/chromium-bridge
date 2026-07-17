# contracts/

The **single source of truth** for cross-process contracts. Edit here, then
regenerate/verify; don't hand-edit the derived files.

## `tools.json`

The tool catalogue: for each tool, its `name`, `uiLabel` (options page),
`risk`, `scope`, `permission`, `confirmation`, model-facing `description`, and
`inputSchema`.

Derived / verified from it:

- **`src/packages/shared/src/ops.gen.ts`**: *generated* by `scripts/gen-ops.ts`
  (`just gen`): op names, UI labels, policy metadata, and a Zod arg validator
  per tool. The `BridgeCommand` request union is inferred from those
  validators, so the compile-time types and the runtime checks are the same
  artifact. CI fails if the file is out of date.
- **`src/packages/core/src/tools/catalogue.rs`**: *verified* by the
  `matches_contract` test (`cargo test`): names, descriptions, and schemas
  must match the contract.
- **`src/packages/shared/tests/ops.gen.test.ts`**: asserts the generated catalogue
  and validators match the contract; the roster test in
  `src/apps/extension/tests/shared/rosters.test.ts` asserts every op has exactly one
  handling surface in the extension (service worker, page backends, or the
  MCP server itself).

So a tool's identity lives in one place; Rust and TypeScript both fail CI if
they drift from it.

## `errors.json`

The cross-process error taxonomy: for each error, a stable `code` (for
programmatic handling), a `category`, a `retryable` flag, a user/model-facing
`message`, and the Rust `CallError` variant(s) it maps from. Rust maps
`CallError -> code` (verified by `cargo test` against this file); the extension
maps its failures to the same codes. See
[docs/architecture.md](../docs/architecture.md#11-protocol-boundary-error-taxonomy-and-handshake) for how it
fits the protocol.

## `capabilities.json`

The capability catalogue for connection-time negotiation. Each capability has a
stable `id`, a `description`, the Chrome `permissions` it needs, and the `tools`
(from `tools.json`) it covers. It is derived **conceptually** from `tools.json`
(each tool's `permission` + `scope`). On connect, the extension/host advertise
which capability ids are actually available; a tool is callable only if its
capability is advertised. The groupings and descriptions are hand-authored, so
the file is *verified* rather than generated:
`src/packages/shared/tests/capabilities.test.ts` fails CI unless every bridge-routed
tool is covered by exactly one capability and each capability's `permissions`
equal the union of its tools' permissions.

## `identity.json`

The identity constants that have no other natural home. The native-messaging
host id is declared here, and so is the extension's pinned manifest `key`
(`extensionManifestKey`): `src/apps/extension/wxt.config.ts` injects it into the
generated manifest, and Chrome derives the extension ID from it.
`scripts/gen-ops.ts` emits both into `src/packages/shared/src/identity.gen.ts`
(the extension imports `NATIVE_HOST_ID` for `connectNative` and
`PINNED_EXTENSION_ID` for its startup self-check), and
`scripts/check-extension-id.ts` (`just check-extension-id`, part of `just ci`)
verifies the Rust host and both installers against the same sources.

## `protocol-version.json`

The **internal bridge** protocol version: a small integer for the
MCP server ↔ native host ↔ extension wire contract. Distinct from the MCP
JSON-RPC version (`2025-06-18`, see
[ADR-0007](../docs/adr/0007-mcp-protocol-version-2025-06-18.md)) and from the
extension release version (Cargo is the version source). It also documents the
intended compatibility handshake: exchange version + capabilities on connect and
fail fast (`PROTOCOL_MISMATCH`) on incompatibility, rather than a late
"unknown op".

## `bridge-request.schema.json` / `bridge-response.schema.json`

JSON Schema (draft 2020-12) for the internal bridge **envelope**: the
`BridgeReq { id, op, tabId?, args }` request and `BridgeResp { id, ok, data?, error? }`
response that cross MCP server ↔ native host ↔ extension. They describe the
current wide form (`op` a plain string, `args` a flat bag of optional fields;
the per-op narrowing is the generated validators' job). The `data` payload is
intentionally unconstrained, and stable error **codes** live in `errors.json`,
not in the response schema.

Their runtime form is the hand-written Zod schemas in
`src/packages/shared/src/envelope.ts`, which the extension enforces on every
inbound native-messaging frame (`parseBridgeReq`, fail closed). The TS types
are inferred from those schemas, and the **equivalence test**
(`src/packages/shared/tests/contract-equivalence.test.ts`) diffs
`z.toJSONSchema()` of each schema against the contract file in CI, so there
is no hand-synced mirror left to drift. The request schema's `OpArgs` is
pinned to the union of every tool's `inputSchema` properties (minus the
server-consumed `browser` routing argument) by the same test.

## Adding / changing a tool

1. Edit `tools.json` (and `capabilities.json` if the tool needs a new
   capability grouping).
2. `just gen` (regenerates `src/packages/shared/src/ops.gen.ts`).
3. Update the Rust handler in `src/packages/core/src/tools/` (the test enforces
   parity).
4. Give the op a home in the extension: `SW_OPS` + a `dispatchSw` case, or
   `PAGE_OPS` + cases in both page backends. The roster and exhaustiveness
   checks fail until the partition is complete.
5. If the tool adds a new arg name, mirror it into
   `bridge-request.schema.json`'s `OpArgs` (the equivalence test tells you).
6. `cargo test` + `just ci`.

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-tool).
