// Display names for the browser-path resolver's keys, and a locale-aware
// list formatter for showing several of them in a sentence.

import { activeLocale } from "@/lib/i18n";

const DISPLAY_NAMES: Record<string, string> = {
  chrome: "Google Chrome",
  chromium: "Chromium",
  brave: "Brave",
  edge: "Microsoft Edge",
  vivaldi: "Vivaldi",
  opera: "Opera",
};

// A key the UI does not know yet still renders (as itself) rather than
// disappearing from the list.
export function browserDisplayName(key: string): string {
  return DISPLAY_NAMES[key] ?? key;
}

const BCP47: Record<string, string> = { en: "en", zh_CN: "zh-CN", zh_TW: "zh-TW" };

export function formatBrowserList(keys: readonly string[]): string {
  const names = keys.map(browserDisplayName);
  return new Intl.ListFormat(BCP47[activeLocale()] ?? "en", {
    style: "long",
    type: "conjunction",
  }).format(names);
}
