// @chromium-bridge/shared - contract-derived types, Zod validators, and (from
// the extension rehaul onward) the i18n runtime, shared by the extension, the
// app UI, and tooling.
//
// The *.gen.ts modules are generated from the Rust core - the canonical
// contract source (ADR-0028) - by scripts/gen-ops.ts (`just gen`); everything
// else is hand-written. The hand-written envelope validators are proven
// equivalent to the Rust wire types by the CI double-derivation diff
// (scripts/check-envelope-parity.ts).

export * from "./confirm";
export * from "./enclave";
export * from "./envelope";
export * from "./errors.gen";
export * from "./identity.gen";
export * from "./ops.gen";
export * from "./protocol.gen";
export * from "./runtime-msg";
export * from "./settings";
export * from "./storage";
export * from "./util";
