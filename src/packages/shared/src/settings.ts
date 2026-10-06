// Single source of truth for the BROWSER-OWNED configurable settings: their
// schema and their defaults. The storage reads over them are the extension's
// (lib/shared/settings.ts there).
//
// Only fields the browser itself owns live here: the site-scope opt-in, tab
// grouping, and the display language. The policy fields are host-owned
// (the generated policy contract in policy.gen.ts governs them), and
// `requireEnrollment` is retired - enrollment is simply required.
//
// The Settings type is inferred from the schema, and DEFAULTS is derived by
// parsing an empty bag - so a new setting is added in exactly one place.

import { z } from "zod";

// The canonical TS-side list of accepted uiLanguage values. Language stays
// browser-owned, so this list is NOT generated from the Rust core; the host's
// hand-kept copy (src/packages/core/src/lang.rs UI_LANGUAGES) is pinned against
// this one by tests/lang-parity.test.ts. Everything TS-side (the settings
// schema below, the runtime-message enum, the pickers) derives from here.
export const UI_LANGUAGES = ["auto", "en", "zh_CN", "zh_TW"] as const;

export type UiLanguageValue = (typeof UI_LANGUAGES)[number];

export const SettingsSchema = z.object({
  allowAllSites: z.boolean().default(false),
  // Collect tab_open tabs into a "Chromium Bridge" group.
  groupTabs: z.boolean().default(true),
  // The extension UI's display language. Defaults to "en": English is the
  // canonical language on every surface, and Chinese is an explicit choice,
  // never an inherited one. "auto" (opt-in) resolves from the browser UI
  // language (zh -> zh_CN, zh-Hant/TW/HK/MO -> zh_TW, else en). Distinct from
  // Chrome's own default_locale: this is the user's explicit choice for
  // in-extension UI.
  uiLanguage: z.enum(UI_LANGUAGES).default("en"),
});

export type Settings = z.infer<typeof SettingsSchema>;

export type SettingKey = keyof Settings;

// Frozen: salvage hands these instances out as fallbacks, so a caller
// mutating its "copy" must throw instead of quietly rewriting the defaults
// for everyone after it.
export const DEFAULTS: Readonly<Settings> = Object.freeze(SettingsSchema.parse({}));
