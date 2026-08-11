// Single source of truth for the BROWSER-OWNED configurable settings: their
// schema, their defaults, and the salvage helper that recovers a usable
// Settings from whatever is actually in storage.
//
// Only fields the browser itself owns live here (ADR-0032): the site-scope
// opt-in, tab grouping, and the display language. The 15 policy fields are
// host-owned (the generated policy contract in policy.gen.ts governs them
// post-cutover), their legacy schemas live in legacy-settings.ts for the two
// permanent pre-cutover consumers, and `requireEnrollment` is retired -
// enrollment is simply required.
//
// The Settings type is inferred from the schema, and DEFAULTS is derived by
// parsing an empty bag - so a new setting is added in exactly one place.

import { z } from "zod";

// The canonical TS-side list of accepted uiLanguage values (ADR-0032
// decision 7). Language stays browser-owned (decision 1), so this list is
// NOT generated from the Rust core; the host's hand-kept copy
// (src/packages/core/src/lang.rs UI_LANGUAGES) is pinned against this one by
// tests/lang-parity.test.ts. Everything TS-side (the settings schema below,
// the runtime-message enum, the pickers) derives from here.
export const UI_LANGUAGES = ["auto", "en", "zh_CN", "zh_TW"] as const;

export type UiLanguageValue = (typeof UI_LANGUAGES)[number];

export const SettingsSchema = z.object({
  allowAllSites: z.boolean().default(false),
  // Collect tab_open tabs into a "Chromium Bridge" group. See ADR-0018.
  groupTabs: z.boolean().default(true),
  // The extension UI's display language (ADR-0027 i18n). Defaults to "en":
  // English is the canonical language on every surface, and Chinese is an
  // explicit choice, never an inherited one. "auto" (opt-in) resolves from
  // the browser UI language (zh -> zh_CN, zh-Hant/TW/HK/MO -> zh_TW, else
  // en). Distinct from Chrome's own default_locale: this is the user's
  // explicit choice for in-extension UI.
  uiLanguage: z.enum(UI_LANGUAGES).default("en"),
});

export type Settings = z.infer<typeof SettingsSchema>;

export type SettingKey = keyof Settings;

// Frozen: salvage hands these instances out as fallbacks, so a caller
// mutating its "copy" must throw instead of quietly rewriting the defaults
// for everyone after it.
export const DEFAULTS: Readonly<Settings> = Object.freeze(SettingsSchema.parse({}));

/**
 * Recover a usable Settings from an untrusted storage bag, field by field:
 * a value that fails its own schema falls back to that field's default
 * without discarding the healthy fields around it. Missing fields get their
 * defaults from the schema itself.
 */
export function salvageSettings(stored: unknown): Settings {
  const bag: Record<string, unknown> =
    typeof stored === "object" && stored !== null ? (stored as Record<string, unknown>) : {};
  return Object.fromEntries(
    Object.entries(SettingsSchema.shape).map(([key, schema]) => {
      const parsed = schema.safeParse(bag[key]);
      return [key, parsed.success ? parsed.data : DEFAULTS[key as SettingKey]];
    }),
  ) as Settings;
}

/**
 * Validate one setting read from storage, falling back to the field's
 * default when the stored value is missing or fails its schema.
 */
export function salvageSetting<K extends SettingKey>(key: K, value: unknown): Settings[K] {
  const parsed = SettingsSchema.shape[key].safeParse(value);
  return parsed.success ? (parsed.data as Settings[K]) : DEFAULTS[key];
}
