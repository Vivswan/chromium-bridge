// Runtime i18n with a user-chosen display language, the desktop sibling of
// the extension's i18n runtime: the same three locales, the same "auto"
// semantics (bare "zh" means Simplified, Chrome's own convention), the same
// positional $1 substitutions. Bundles are statically imported - the corpus
// is small and the webview is local, so there is nothing to lazy-load - and
// the choice persists in localStorage (display preference only; no security
// weight).

import { en, type MessageKey } from "@/locales/en";
import { zh_CN } from "@/locales/zh_CN";
import { zh_TW } from "@/locales/zh_TW";

export type UiLanguage = "auto" | "en" | "zh_CN" | "zh_TW";
export type UiLocale = Exclude<UiLanguage, "auto">;
export type { MessageKey };

const BUNDLES: Record<UiLocale, Record<MessageKey, string>> = { en, zh_CN, zh_TW };

const STORAGE_KEY = "uiLanguage";

/** Map a BCP-47 tag onto our three locales. */
export function resolveUiLocale(uiLanguage: UiLanguage, systemLang: string): UiLocale {
  if (uiLanguage !== "auto") return uiLanguage;
  const tag = systemLang.toLowerCase();
  if (tag === "zh" || tag.startsWith("zh-")) {
    return /^zh-(hant|tw|hk|mo)/.test(tag) ? "zh_TW" : "zh_CN";
  }
  return "en";
}

function readStoredLanguage(): UiLanguage {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === "en" || raw === "zh_CN" || raw === "zh_TW" || raw === "auto") return raw;
  } catch {
    // Storage unavailable: fall through to auto.
  }
  return "auto";
}

let uiLanguage: UiLanguage = readStoredLanguage();
let version = 0;
const listeners = new Set<() => void>();

export function getUiLanguage(): UiLanguage {
  return uiLanguage;
}

export function setUiLanguage(lang: UiLanguage): void {
  uiLanguage = lang;
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // Display preference only; losing persistence is acceptable.
  }
  version += 1;
  for (const listener of listeners) listener();
}

export function activeLocale(): UiLocale {
  return resolveUiLocale(uiLanguage, navigator.language);
}

/** Translate `key`, substituting $1, $2, ... from `subs`. English is the
 * fallback for any locale gap (the types make gaps impossible for checked-in
 * bundles, but the guard costs nothing). */
export function t(key: MessageKey, subs?: readonly string[]): string {
  const message = BUNDLES[activeLocale()][key] ?? en[key];
  if (!subs || subs.length === 0) return message;
  return message.replace(/\$(\d)/g, (whole, index: string) => {
    const value = subs[Number(index) - 1];
    return value ?? whole;
  });
}

export function subscribeLocale(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getLocaleVersion(): number {
  return version;
}
