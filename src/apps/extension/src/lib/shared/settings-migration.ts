// Versioned settings migration. Settings live as flat keys in
// browser.storage.local (read field-by-field with per-field Zod salvage in
// shared/settings.ts). This module stamps a schema version and runs ordered,
// one-way migrations once per install/upgrade, so a future rename or unit
// change to a setting has a home that transforms existing stored values
// instead of silently dropping them to defaults.
//
// Serialized with the same Web Lock the settings writes use, so a migration
// cannot interleave with a concurrent write from another extension context.

import { browser } from "wxt/browser";

const VERSION_KEY = "settingsVersion";

/** A one-way transform from the version before it to the one after. Receives
 * the raw storage bag and returns the keys to write (a partial patch); it must
 * be idempotent enough to survive a retry. */
export type Migration = (bag: Record<string, unknown>) => Record<string, unknown>;

/** A ladder: its rungs, and the version the first rung lifts from. The explicit
 * floor is what makes retiring the oldest rung safe: without it every stored
 * version would silently renumber the moment `migrations[0]` is deleted, and
 * the wrong rung would run on every existing store.
 *
 *   retire rung 0, raise firstVersion  -> current unchanged, every stored version keeps its meaning
 *   stored < firstVersion              -> too old to climb: no rung runs, the store is stamped current
 *                                         and per-field salvage in shared/settings.ts owns the values
 */
export type Ladder = {
  readonly firstVersion: number;
  readonly migrations: readonly Migration[];
};

export const SETTINGS_LADDER: Ladder = {
  firstVersion: 0,
  migrations: [
    // v0 -> v1: the initial stamp; no stored key changes shape.
    () => ({}),
  ],
};

export function currentVersion(ladder: Ladder): number {
  return ladder.firstVersion + ladder.migrations.length;
}

export const SETTINGS_VERSION = currentVersion(SETTINGS_LADDER);

/** What a store needs written to stand on the ladder's top. A newer extension's
 * store is left alone: this build cannot read its shape, and the owner may be
 * about to run. */
export type Climb =
  | { readonly outcome: "current" }
  | { readonly outcome: "newer" }
  | { readonly outcome: "too-old"; readonly write: Record<string, unknown> }
  | { readonly outcome: "climbed"; readonly write: Record<string, unknown> };

/** The version a stored bag stands on. An unstamped store is the pre-stamp era,
 * version 0 by the settings ladder's definition. */
function storedVersion(bag: Record<string, unknown>): number {
  const raw = bag[VERSION_KEY];
  return typeof raw === "number" && Number.isInteger(raw) && raw >= 0 ? raw : 0;
}

/** Pure: the patch that lifts `bag` to the ladder's top, stamp included, so a
 * single storage write lands the whole climb or none of it. */
export function climb(ladder: Ladder, bag: Record<string, unknown>): Climb {
  const stored = storedVersion(bag);
  const top = currentVersion(ladder);
  if (stored === top) return { outcome: "current" };
  if (stored > top) return { outcome: "newer" };
  if (stored < ladder.firstVersion) {
    return { outcome: "too-old", write: { [VERSION_KEY]: top } };
  }
  let write: Record<string, unknown> = {};
  for (const migration of ladder.migrations.slice(stored - ladder.firstVersion)) {
    write = { ...write, ...migration({ ...bag, ...write }) };
  }
  return { outcome: "climbed", write: { ...write, [VERSION_KEY]: top } };
}

const LOCK = "chromium-bridge-settings-write";

/** Run any pending migrations and stamp the current version. Idempotent: a
 * second call is a no-op once the store is at SETTINGS_VERSION. */
export function migrateSettings(): Promise<void> {
  return navigator.locks.request(LOCK, async () => {
    // The whole store, raw: a migration rung is handed keys and shapes the current schema no longer describes,
    // so there is nothing to classify the bag against before the climb.
    const result = climb(SETTINGS_LADDER, await browser.storage.local.get(null));
    if (result.outcome === "current" || result.outcome === "newer") return;
    await browser.storage.local.set(result.write);
  });
}
