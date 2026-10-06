// The one read of a browser.storage.local record. Storage is extension-private but still an input: every
// record is parsed against its schema before a caller sees it, and a record that is present but fails the
// schema is `corrupt`, never folded into `absent` by this reader. Each caller decides what absent and corrupt
// mean for it: a gate fails closed on corrupt (kill.ts), a display collapses both to its fallback.

import { browser } from "wxt/browser";
import type { ZodType, z } from "zod";

export type Stored<T> =
  | { readonly state: "absent" }
  | { readonly state: "corrupt" }
  | { readonly state: "valid"; readonly value: T };

function classify<T>(raw: unknown, schema: ZodType<T>): Stored<T> {
  if (raw === undefined) return { state: "absent" };
  const parsed = schema.safeParse(raw);
  return parsed.success ? { state: "valid", value: parsed.data } : { state: "corrupt" };
}

export async function readKey<T>(key: string, schema: ZodType<T>): Promise<Stored<T>> {
  const { [key]: raw } = await browser.storage.local.get(key);
  return classify(raw, schema);
}

/** Several records from ONE storage get, each classified on its own. A caller that folds records together
 * reads them here, so the fold never sees a pair that tore across a write landing between two separate gets. */
export async function readKeys<S extends Record<string, ZodType>>(
  schemas: S,
): Promise<{ readonly [K in keyof S]: Stored<z.output<S[K]>> }> {
  const raw = await browser.storage.local.get(Object.keys(schemas));
  return Object.fromEntries(
    Object.entries(schemas).map(([key, schema]) => [key, classify(raw[key], schema)]),
  ) as { [K in keyof S]: Stored<z.output<S[K]>> };
}

/** The collapsed read: `fallback` for an absent or corrupt record alike. Only for callers whose fallback
 * grants nothing (a display null, an empty list, a setting's default). */
export async function readKeyOr<T, F>(
  key: string,
  schema: ZodType<T>,
  fallback: F,
): Promise<T | F> {
  const stored = await readKey(key, schema);
  return stored.state === "valid" ? stored.value : fallback;
}
