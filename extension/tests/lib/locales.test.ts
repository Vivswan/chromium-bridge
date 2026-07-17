// Every user-facing string ships in all three locales. Fails the moment a key
// is added to one locale file but not the others, or a $n placeholder drifts
// between languages. The runtime (lib/i18n.ts) falls back to English per key,
// but a missing key would silently show English in a Chinese UI - this catches
// it at build time instead.

import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";
import { parse } from "yaml";

const LOCALES_DIR = resolve(__dirname, "../../src/locales");
const BASE_LOCALE = "en.yml";

function flatten(value: unknown, prefix = ""): Map<string, string> {
  const keys = new Map<string, string>();
  if (value === null || typeof value !== "object") return keys;
  for (const [key, child] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (child !== null && typeof child === "object") {
      for (const [k, v] of flatten(child, path)) keys.set(k, v);
    } else {
      keys.set(path, String(child));
    }
  }
  return keys;
}

function placeholders(text: string): string[] {
  return (text.match(/\$\d+/g) ?? []).sort();
}

const localeFiles = readdirSync(LOCALES_DIR).filter((f) => f.endsWith(".yml"));
const flattened = new Map(
  localeFiles.map((file) => [
    file,
    flatten(parse(readFileSync(resolve(LOCALES_DIR, file), "utf8"))),
  ]),
);

describe("locale files", () => {
  test("ship exactly the three supported locales", () => {
    expect(localeFiles.sort()).toEqual(["en.yml", "zh_CN.yml", "zh_TW.yml"]);
  });

  const base = flattened.get(BASE_LOCALE);
  if (!base) throw new Error(`${BASE_LOCALE} missing`);

  for (const file of localeFiles.filter((f) => f !== BASE_LOCALE)) {
    const locale = flattened.get(file);
    if (!locale) throw new Error(`${file} missing`);

    test(`${file} has exactly the keys of ${BASE_LOCALE}`, () => {
      const missing = [...base.keys()].filter((k) => !locale.has(k));
      const extra = [...locale.keys()].filter((k) => !base.has(k));
      expect(missing, `keys missing from ${file}`).toEqual([]);
      expect(extra, `keys in ${file} that ${BASE_LOCALE} lacks`).toEqual([]);
    });

    test(`${file} keeps every $n placeholder from ${BASE_LOCALE}`, () => {
      for (const [key, enValue] of base) {
        const localized = locale.get(key);
        if (localized === undefined) continue; // reported by the key test
        expect(placeholders(localized), `placeholders drifted for ${key} in ${file}`).toEqual(
          placeholders(enValue),
        );
      }
    });

    test(`${file} has no empty values`, () => {
      const empty = [...locale.entries()].filter(([, v]) => v.trim() === "").map(([k]) => k);
      expect(empty, `empty values in ${file}`).toEqual([]);
    });
  }
});
