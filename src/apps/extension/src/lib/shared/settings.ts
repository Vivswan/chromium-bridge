// Read one setting from browser.storage.local, falling back to its default.
//
// The schema and the defaults live in @chromium-bridge/shared (settings.ts
// there); this module is only the browser.storage glue. A stored value that
// fails its field's schema reads as that field's default, so a corrupted or
// tampered record can never smuggle an unexpected shape into the callers.

import { DEFAULTS, type Settings, SettingsSchema } from "@chromium-bridge/shared/settings";
import type { ZodType } from "zod";
import { readKeyOr } from "./storage";

// The shape viewed per key: indexed by a generic K, the raw shape yields the
// union of every field's schema, this view yields ZodType<Settings[K]>.
const FIELDS: { [K in keyof Settings]: ZodType<Settings[K]> } = SettingsSchema.shape;

// Not cached: settings are read once per action and storage reads are cheap.
export function getSetting<K extends keyof Settings>(key: K): Promise<Settings[K]> {
  return readKeyOr(key, FIELDS[key], DEFAULTS[key]);
}
