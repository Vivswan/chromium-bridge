// @chromium-bridge/shared - contract-derived types, Zod validators, and (from
// the extension rehaul onward) the i18n runtime, shared by the extension, the
// app UI, and tooling.
//
// The *.gen.ts modules are generated from contracts/ by scripts/gen-ops.ts
// (`just gen`); everything else is hand-written and, where a contracts/
// *.schema.json exists, verified equivalent to it in CI.

export * from "./enclave";
export * from "./envelope";
export * from "./identity.gen";
export * from "./ops.gen";
export * from "./runtime-msg";
export * from "./settings";
export * from "./storage";
export * from "./util";
