// The extension's install-time Chrome permissions - ONE list, consumed by
// wxt.config.ts (which emits it into the generated manifest) and by the
// roster drift test (which checks every tool's declared permission is
// granted). Host access is deliberately NOT here: origins are the optional
// <all_urls> permission, granted per-origin through the allowlist flow.
export const MANIFEST_PERMISSIONS = [
  "tabs",
  "tabGroups",
  "scripting",
  "storage",
  "nativeMessaging",
  "debugger",
  "cookies",
] as const;
