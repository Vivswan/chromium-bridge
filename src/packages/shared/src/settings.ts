// The browser-owned settings and their defaults; the storage reads live in the extension (lib/shared/settings.ts)
// and the policy fields are host-owned (generated/policy.ts). DEFAULTS is parsed from an empty bag, so a setting
// is added in exactly one place.

import { z } from "zod";

// Language stays browser-owned, so this list is not generated from the Rust core; lang.rs UI_LANGUAGES is pinned
// to it by tests/lang-parity.test.ts.
export const UI_LANGUAGES = ["auto", "en", "zh_CN", "zh_TW"] as const;

export type UiLanguageValue = (typeof UI_LANGUAGES)[number];

export const SettingsSchema = z.object({
  allowAllSites: z.boolean().default(false),
  groupTabs: z.boolean().default(true),
  // "en", never the browser language: English is canonical on every surface and Chinese an explicit choice.
  // "auto" (opt-in) resolves zh -> zh_CN, zh-Hant/TW/HK/MO -> zh_TW, else en.
  uiLanguage: z.enum(UI_LANGUAGES).default("en"),
});

export type Settings = z.infer<typeof SettingsSchema>;

export type SettingKey = keyof Settings;

// Frozen: salvage hands these instances out as fallbacks, so a caller
// mutating its "copy" must throw instead of quietly rewriting the defaults
// for everyone after it.
export const DEFAULTS: Readonly<Settings> = Object.freeze(SettingsSchema.parse({}));
