import type { PublicPath } from "wxt/browser";
import { browser } from "wxt/browser";
import type { GeneratedI18nStructure } from "#i18n";
import { getSetting } from "./shared/settings";

// Runtime i18n with a USER-CHOSEN display language.
//
// browser.i18n.getMessage always answers in the BROWSER's UI language and
// cannot honor the uiLanguage setting, so this module loads the compiled
// _locales/<locale>/messages.json bundles itself and resolves keys against the
// chosen locale, falling back to English and finally to getMessage.
//
// The message corpus is deliberately simple (flat keys after underscore
// flattening, positional $1 substitutions, no plurals), so this stays a lookup
// plus one replace. The #i18n import is TYPE-ONLY (erased at transpile), so
// this module is safe in the background graph before `wxt prepare` generates
// the #i18n module. Ported from cloud-speech-for-chrome's i18n-runtime.ts.

export type UiLanguage = "auto" | "en" | "zh_CN" | "zh_TW";
export type UiLocale = Exclude<UiLanguage, "auto">;

export type MessageKey = keyof GeneratedI18nStructure & string;

/** Map a browser BCP-47 tag onto our three locales. Bare "zh" means
 * Simplified by Chrome's own locale convention. */
export function resolveUiLocale(uiLanguage: UiLanguage, browserLang: string): UiLocale {
  if (uiLanguage !== "auto") return uiLanguage;
  const tag = browserLang.toLowerCase();
  if (tag === "zh" || tag.startsWith("zh-")) {
    return /^zh-(hant|tw|hk|mo)/.test(tag) ? "zh_TW" : "zh_CN";
  }
  return "en";
}

type MessageMap = Record<string, string>;

let activeLocale: UiLocale = "en";
let activeMessages: MessageMap | null = null;
let enMessages: MessageMap | null = null;
let version = 0;
let initPromise: Promise<void> | null = null;
// Monotonic guard: refreshes can overlap (rapid switches, storage events) and
// fetch latencies vary; only the NEWEST refresh may commit its result.
let refreshSeq = 0;
let latestRefresh: Promise<void> = Promise.resolve();
let lastAttemptedLocale: UiLocale | null = null;
const listeners = new Set<() => void>();

function messagesUrl(locale: UiLocale): string {
  // _locales/ is emitted by the @wxt-dev/i18n build module but is not part of
  // WXT's generated PublicPath union, hence the cast.
  return browser.runtime.getURL(`/_locales/${locale}/messages.json` as PublicPath);
}

async function loadMessages(locale: UiLocale): Promise<MessageMap> {
  const response = await fetch(messagesUrl(locale));
  if (!response.ok) throw new Error(`Loading ${locale} messages failed: ${response.status}`);
  const raw = (await response.json()) as Record<string, { message?: unknown }>;
  const map: MessageMap = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value?.message === "string") map[key] = value.message;
  }
  return map;
}

async function refreshLocale(): Promise<void> {
  const seq = ++refreshSeq;
  try {
    const uiLanguage = (await getSetting("uiLanguage")) as UiLanguage;
    const locale = resolveUiLocale(uiLanguage, browser.i18n.getUILanguage());
    lastAttemptedLocale = locale;
    if (locale === activeLocale && activeMessages !== null) return;

    const active = await loadMessages(locale);
    // The en fallback map is best-effort: its failure must not discard a
    // successfully loaded active locale.
    let en = locale === "en" ? active : enMessages;
    if (en === null) en = await loadMessages("en").catch(() => null);

    // Superseded by a newer refresh while fetching; its result wins.
    if (seq !== refreshSeq) return;

    activeLocale = locale;
    activeMessages = active;
    enMessages = en;
    version += 1;
    for (const listener of listeners) listener();
  } catch (error) {
    // Keep whatever is already loaded; before the first successful load t()
    // degrades to browser-locale getMessage. Never block the UI.
    console.warn("[bb] could not load locale messages:", error);
  }
}

/** Load the chosen locale's messages and keep them in sync with the setting.
 * Idempotent and never rejects; the watcher is registered before the first
 * load so a change landing mid-load is never missed. */
export function initI18n(): Promise<void> {
  initPromise ??= (async () => {
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes.uiLanguage) {
        latestRefresh = refreshLocale();
      }
    });
    latestRefresh = refreshLocale();
    let awaited: Promise<void>;
    do {
      awaited = latestRefresh;
      await awaited;
      try {
        const uiLanguage = (await getSetting("uiLanguage")) as UiLanguage;
        const want = resolveUiLocale(uiLanguage, browser.i18n.getUILanguage());
        if (want !== lastAttemptedLocale) latestRefresh = refreshLocale();
      } catch {
        break;
      }
    } while (awaited !== latestRefresh);
  })();
  return initPromise;
}

function format(message: string, substitutions?: string[]): string {
  if (!substitutions?.length) return message;
  return message.replace(/\$(\d)/g, (_, index: string) => substitutions[Number(index) - 1] ?? "");
}

export function t(key: MessageKey, substitutions?: string[]): string {
  const flat = key.replaceAll(".", "_");
  const message = activeMessages?.[flat] ?? enMessages?.[flat];
  if (message !== undefined) return format(message, substitutions);
  try {
    const fromBrowser = browser.i18n.getMessage(
      flat as Parameters<typeof browser.i18n.getMessage>[0],
      substitutions,
    );
    if (fromBrowser) return fromBrowser;
  } catch {
    // fakeBrowser in tests may lack getMessage; fall through to the key.
  }
  return key;
}

export const i18n = { t };

export function getActiveLocale(): UiLocale {
  return activeLocale;
}

/** Notifies whenever the resolved locale's messages change (for remounts). */
export function subscribeLocale(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function getLocaleVersion(): number {
  return version;
}

/** Keep the document's lang attribute in sync with the active locale, so
 * assistive tech announces the UI in the right language. No-op in the SW
 * (no document). Call once per page after initI18n. */
export function syncHtmlLang(): void {
  if (typeof document === "undefined") return;
  const apply = () => {
    document.documentElement.lang = activeLocale.replace("_", "-");
  };
  apply();
  subscribeLocale(apply);
}
