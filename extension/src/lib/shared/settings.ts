// Read one setting from browser.storage.local, falling back to its default.
//
// The schema, the defaults, and the salvage logic live in
// @chromium-bridge/shared (settings.ts there); this module is only the
// browser.storage glue. Every read is validated: a stored value that fails its
// field's schema is replaced by that field's default, so a corrupted or
// tampered record can never smuggle an unexpected shape into the callers.

import { DEFAULTS, type Settings, salvageSetting } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";

export { DEFAULTS };

// Not cached: settings are read once per action and storage reads are cheap.
export async function getSetting<K extends keyof Settings>(key: K): Promise<Settings[K]> {
  const r = await browser.storage.local.get(key);
  return salvageSetting(key, r[key]);
}
