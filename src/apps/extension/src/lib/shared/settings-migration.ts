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

/** A one-way transform from the version before it to the one after. Receives
 * the raw storage bag and returns the keys to write (a partial patch); it must
 * be idempotent enough to survive a retry. Index i migrates vi -> v(i+1). */
export type Migration = (bag: Record<string, unknown>) => Record<string, unknown>;

// The ladder: MIGRATIONS[i] migrates vi -> v(i+1). Append when a setting is
// renamed or its representation changes. Example (illustrative):
//   (bag) => ({ groupTabs: bag.groupBridgeTabs }), // v1 -> v2
export const MIGRATIONS: readonly Migration[] = [
  // v0 -> v1: the initial stamp; no stored key changes shape.
  () => ({}),
];

/** The current schema version, DERIVED from the ladder: bumping the version
 * without writing its migration (or vice versa) cannot happen - the version
 * IS the ladder's length. */
export const SETTINGS_VERSION = MIGRATIONS.length;

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
      const patch = rung(from)(current);
      current = { ...current, ...patch };
      await browser.storage.local.set(patch);
      from += 1;
    }
    await browser.storage.local.set({ [VERSION_KEY]: SETTINGS_VERSION });
  });
}

/** The migration for vX -> v(X+1). Throws on a hole instead of skipping it:
 * stamping data as migrated when no transform ran would be permanent, while
 * the throw is recoverable - migrations are idempotent, so the next run
 * retries from the same version. Unreachable while SETTINGS_VERSION is
 * derived from the ladder; kept as the backstop for a sparse array or an
 * out-of-range `from`. */
function rung(v: number, migrations: readonly Migration[] = MIGRATIONS): Migration {
  const migration = migrations[v];
  if (!migration) {
    throw new Error(`settings migration v${v} -> v${v + 1} is missing from the ladder`);
  }
  return migration;
}

/** Tests only: run the migration ladder over a plain bag, no storage. */
export function runMigrationsForTests(
  bag: Record<string, unknown>,
  from: number,
  to: number,
  migrations: readonly Migration[] = MIGRATIONS,
): Record<string, unknown> {
  let current = { ...bag };
  for (let v = from; v < to; v++) {
    current = { ...current, ...rung(v, migrations)(current) };
  }
  return { ...current, [VERSION_KEY]: to };
}
