// The reviewed manifest surface, in ONE place: the install-time Chrome permissions and the Chrome floor.
// Host access is deliberately NOT here: origins are the optional <all_urls> permission, granted per-origin
// through the allowlist flow.
export const MANIFEST_PERMISSIONS = [
  "tabs",
  "tabGroups",
  "scripting",
  "storage",
  "nativeMessaging",
  "debugger",
  "cookies",
] as const;

/** The oldest Chrome the extension installs on: the floor the WebAuthn presence ceremony is supported on
 * (lib/shared/webauthn-ceremony.ts). The store and `chrome://extensions` refuse an older browser outright,
 * so no code path degrades below it. */
export const MINIMUM_CHROME_VERSION = "134";
