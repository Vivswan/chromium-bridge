# ADR-0028: Contracts dissolved into the Rust core

- Status: Accepted
- Date: 2026-07-17
- Supersedes: the `contracts/` directory as contract source (introduced with
  the early rebuild phases); refines
  [ADR-0023](0023-workspace-monorepo-tauri-app.md) (the workspace layout no
  longer has a language-neutral contracts folder)

## Context

The cross-process contracts (tool catalogue, error taxonomy, capabilities,
protocol version, identity constants, wire-envelope schemas) lived in
`contracts/` as hand-authored JSON, with three kinds of consumers:

- the TypeScript side was *generated* from it (`ops.gen.ts`,
  `identity.gen.ts`),
- the Rust side was *verified* against it (`matches_contract`,
  `codes_match_contract`, envelope key-parity tests),
- the Zod envelope validators were *proven equivalent* to the hand-authored
  `bridge-*.schema.json` by a CI diff.

That meant the catalogue and the error taxonomy existed twice: once in JSON
and once in `catalogue.rs` / `error.rs`, with parity tests standing guard
precisely because there were two copies. The envelope schemas were a third
copy of what `protocol.rs` already declared. Every tool change touched the
JSON, the Rust, and the generated TS.

A TS-canonical alternative (make the Zod schemas the source) was rejected:
the wire contract is enforcement-core material and must not live in the
zero-security-weight UI tier (see the zero-trust refinements in AGENTS.md).
The Rust core already enforces every boundary, so it becomes the single
source.

## Decision

The Rust core is the canonical contract; `contracts/` is deleted.

1. **Tool catalogue**: `src/packages/core/src/tools/catalogue.rs` carries each
   tool's name, English model-facing description, `inputSchema`, and the
   policy metadata (risk / scope / permission / confirmation) that
   previously only existed in `tools.json`. UI labels are NOT contract
   material; they live in the extension's locale bundles (`tools.<op>` keys
   in `src/apps/extension/src/locales/*.yml`).
2. **Error taxonomy**: `ERROR_SPECS` in `src/packages/core/src/error.rs` is the
   table of stable codes (code, category, retryable, message);
   `CallError::code()` must map into it (`cargo test`).
3. **Capabilities**: `src/packages/core/src/tools/capabilities.rs`, with the
   parity invariants (every bridge-routed tool in exactly one capability,
   permissions equal the union) enforced as `cargo test` instead of a bun
   test reading JSON.
4. **Protocol version and identity**: `BRIDGE_PROTOCOL_VERSION` in
   `protocol.rs`; `NATIVE_HOST_ID` and `EXTENSION_MANIFEST_KEY` in
   `src/packages/core/src/identity.rs`.
5. **Generation**: `moon run gen` runs the core's `emit_contract` example
   (plain serde_json, no extra dependencies) and feeds `scripts/gen-ops.ts`,
   which writes `src/packages/shared/src/{ops,errors,protocol,identity}.gen.ts`.
   CI regenerates and fails on any diff, so the checked-in TS cannot drift
   from the Rust source. The emitted JSON itself is never checked in.
6. **Envelopes by double derivation**: the `BridgeReq`/`BridgeResp` types
   are the envelope contract. schemars derives a JSON Schema from them
   behind the gen-only `envelope-schema` cargo feature (enabled only by the
   `emit_envelope_schema` example; CI asserts schemars is absent from the
   shipped binary's dependency graph), `z.toJSONSchema` derives one from
   the extension's Zod validators, and `scripts/check-envelope-parity.ts`
   diffs the two after the erasure rules documented in
   `src/packages/shared/src/json-schema-normalize.ts`. The rules exist because
   the two parsers deliberately accept different languages (u64-only id vs
   integer-or-string; free-form `args` vs the strict OpArgs bag; serde
   Option null tolerance; Zod-only string/integer hardening); each rule
   erases exactly one of those documented asymmetries, and anything outside
   them fails CI. An earlier spike rejected schemars when the goal was one
   derived schema *replacing* the hand contract; as a drift *gate* with
   explicit reconciliation rules it holds, which is why the verdict
   changed.

## Consequences

- One source of truth with the trust gradient pointing the right way:
  enforcement (Rust) is canonical, UI/tooling is derived.
- Adding a tool now touches the Rust catalogue plus `moon run gen`, instead of
  JSON + Rust + gen.
- The parity tests that existed to guard the duplicate copies are gone;
  their replacements are generation idempotency (CI diff) and the envelope
  double-derivation diff.
- schemars (and five transitive crates) enter the dependency tree as a
  gen-only optional dependency, recorded in `supply-chain/config.toml`; the
  CI contract job asserts it never reaches a shipped binary.
- The `contracts/tools.json` typography exemption is gone: the catalogue's
  descriptions are plain ASCII now, enforced by a `cargo test`
  (`descriptions_are_nonempty_ascii`).
