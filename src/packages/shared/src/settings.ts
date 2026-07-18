// Single source of truth for the configurable settings: their schema, their
// defaults, and the salvage helper that recovers a usable Settings from
// whatever is actually in storage.
//
// The Settings type is inferred from the schema, and DEFAULTS is derived by
// parsing an empty bag - so a new setting is added in exactly one place.

import { z } from "zod";

export const SettingsSchema = z.object({
  pageEvalEnabled: z.boolean().default(true),
  evalMask: z.boolean().default(true),
  confirmHighRiskClick: z.boolean().default(true),
  // Confirm every page_eval (ADR-0008). Off = run unprompted.
  confirmPageEval: z.boolean().default(true),
  // Per-action Touch ID confirmations (ADR-0031): route the page_eval /
  // page_upload confirmations through the host's Secure-Enclave
  // user-presence gate. Default ON; it takes effect only on a capable,
  // enrolled device (macOS + a pinned host key). Off = those confirmations
  // use the off-DOM extension window (still confirmed, not hardware-gated).
  // The AUTH/enrollment Touch ID (the host-identity key) is mandatory and is
  // NOT governed by this setting.
  touchIdConfirm: z.boolean().default(true),
  // Confirm every tab_close. Off = close unprompted.
  confirmTabClose: z.boolean().default(true),
  warnPreciseSnapshot: z.boolean().default(true),
  // Same-origin re-prompt window for click/submit only; page_eval is excluded
  // and always reconfirms (ADR-0008).
  confirmGraceMs: z.int().nonnegative().default(60000),
  clickToastTimeoutMs: z.int().nonnegative().default(30000),
  evalToastTimeoutMs: z.int().nonnegative().default(45000),
  // Tool/op names that are blocked. Deliberately plain strings, not the op
  // enum: entries that match no op are inert (nothing dispatches them), while
  // an enum would make salvage drop the WHOLE list over one stale entry and
  // silently re-enable every disabled tool - fail-open, the wrong direction.
  disabledTools: z.array(z.string()).default([]),
  allowAllSites: z.boolean().default(false),
  // Route ALL page ops through chrome.debugger (CDP). See ADR-0017.
  cdpMode: z.boolean().default(false),
  // Collect tab_open tabs into a "Chromium Bridge" group. See ADR-0018.
  groupTabs: z.boolean().default(true),
  // page_upload is OFF by default: attaching a local file to a page is a
  // local-file egress vector.
  fileUploadEnabled: z.boolean().default(false),
  // page_handle_dialog is OFF by default: a blocked dialog cannot show an
  // in-page confirm, so the opt-in is the gate.
  handleDialogEnabled: z.boolean().default(false),
  // Refuse bridge ops until a host key is paired + pinned (ADR-0021).
  requireEnrollment: z.boolean().default(true),
  // 0 = verify host identity only at pairing + on demand. >0 = on connect,
  // re-verify against the pin when the last successful verification is older
  // than this many ms (lazy check, no scheduler; each re-verify prompts
  // Touch ID).
  hostReverifyMs: z.int().nonnegative().default(0),
  // The extension UI's display language (ADR-0027 i18n). Defaults to "en":
  // English is the canonical language on every surface, and Chinese is an
  // explicit choice, never an inherited one. "auto" (opt-in) resolves from
  // the browser UI language (zh -> zh_CN, zh-Hant/TW/HK/MO -> zh_TW, else
  // en). Distinct from Chrome's own default_locale: this is the user's
  // explicit choice for in-extension UI.
  uiLanguage: z.enum(["auto", "en", "zh_CN", "zh_TW"]).default("en"),
});

export type Settings = z.infer<typeof SettingsSchema>;

export type SettingKey = keyof Settings;

// Frozen (including the nested array): salvage hands these instances out as
// fallbacks, so a caller mutating its "copy" must throw instead of quietly
// rewriting the defaults for everyone after it.
export const DEFAULTS: Readonly<Settings> = deepFreeze(SettingsSchema.parse({}));

function deepFreeze<T>(value: T): T {
  for (const inner of Object.values(value as object)) {
    if (typeof inner === "object" && inner !== null) deepFreeze(inner);
  }
  return Object.freeze(value);
}

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
