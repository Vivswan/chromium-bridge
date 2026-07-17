// Versioned settings migration. Settings live as flat keys in
// browser.storage.local (read field-by-field with per-field Zod salvage in
// shared/settings.ts). This module stamps a schema VERSION and runs ordered,
// one-way migrations once per install/upgrade, so a future rename or unit
// change to a setting has a home that transforms existing stored values
// instead of silently dropping them to defaults.
//
// Serialized with the same Web Lock the settings writes use, so a migration
// cannot interleave with a concurrent write from another extension context.

import { browser } from "wxt/browser";

const VERSION_KEY = "settingsVersion";

// The current schema version. Bump when adding a migration below.
export const SETTINGS_VERSION = 1;

/** A one-way transform from the version before it to the one after. Receives
 * the raw storage bag and returns the keys to write (a partial patch); it must
 * be idempotent enough to survive a retry. Index i migrates vi -> v(i+1). */
export type Migration = (bag: Record<string, unknown>) => Record<string, unknown>;

// No migrations yet (v0 -> v1 is the initial stamp). Add here in order when a
// setting is renamed or its representation changes; each entry advances the
// version by one. Example (do not uncomment - illustrative):
//   MIGRATIONS[1] = (bag) => ({ hostReverifyMs: bag.reverifyIntervalMs }); // v1 -> v2
export const MIGRATIONS: Migration[] = [];

const LOCK = "chromium-bridge-settings-write";

/** Run any pending migrations and stamp the current version. Idempotent: a
 * second call is a no-op once the store is at SETTINGS_VERSION. */
export function migrateSettings(): Promise<void> {
  return navigator.locks.request(LOCK, async () => {
    const bag = await browser.storage.local.get(null);
    const raw = bag[VERSION_KEY];
    let from = typeof raw === "number" && Number.isInteger(raw) && raw >= 0 ? raw : 0;
    if (from >= SETTINGS_VERSION) return;

    let current: Record<string, unknown> = { ...bag };
    while (from < SETTINGS_VERSION) {
      const migration = MIGRATIONS[from];
      if (migration) {
        const patch = migration(current);
        current = { ...current, ...patch };
        await browser.storage.local.set(patch);
      }
      from += 1;
    }
    await browser.storage.local.set({ [VERSION_KEY]: SETTINGS_VERSION });
  });
}

/** Tests only: run the migration ladder over a plain bag, no storage. */
export function runMigrationsForTests(
  bag: Record<string, unknown>,
  from: number,
  to: number,
  migrations = MIGRATIONS,
): Record<string, unknown> {
  let current = { ...bag };
  for (let v = from; v < to; v++) {
    const migration = migrations[v];
    if (migration) current = { ...current, ...migration(current) };
  }
  return { ...current, [VERSION_KEY]: to };
}
