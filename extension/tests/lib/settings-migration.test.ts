// The settings migration ladder: version stamping and ordered one-way
// transforms. The pure runner (runMigrationsForTests) exercises the sequencing
// without storage; migrateSettings is covered against fakeBrowser.

import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing";
import {
  type Migration,
  migrateSettings,
  runMigrationsForTests,
  SETTINGS_VERSION,
} from "@/lib/shared/settings-migration";

beforeEach(() => {
  fakeBrowser.reset();
});

describe("runMigrationsForTests", () => {
  test("applies migrations in order and stamps the target version", () => {
    const migrations: Migration[] = [
      (bag) => ({ b: (bag.a as number) + 1 }), // v0 -> v1
      (bag) => ({ c: (bag.b as number) * 10 }), // v1 -> v2
    ];
    const out = runMigrationsForTests({ a: 1 }, 0, 2, migrations);
    expect(out).toEqual({ a: 1, b: 2, c: 20, settingsVersion: 2 });
  });

  test("a partial range runs only the migrations in it", () => {
    const migrations: Migration[] = [() => ({ ran0: true }), () => ({ ran1: true })];
    const out = runMigrationsForTests({}, 1, 2, migrations);
    expect(out).toEqual({ ran1: true, settingsVersion: 2 });
  });
});

describe("migrateSettings", () => {
  test("stamps the current version on a fresh store", async () => {
    await migrateSettings();
    const { settingsVersion } = await fakeBrowser.storage.local.get("settingsVersion");
    expect(settingsVersion).toBe(SETTINGS_VERSION);
  });

  test("is idempotent: a second run does not change the version", async () => {
    await migrateSettings();
    await migrateSettings();
    const { settingsVersion } = await fakeBrowser.storage.local.get("settingsVersion");
    expect(settingsVersion).toBe(SETTINGS_VERSION);
  });

  test("leaves an already-current store untouched", async () => {
    await fakeBrowser.storage.local.set({
      settingsVersion: SETTINGS_VERSION,
      pageEvalEnabled: false,
    });
    await migrateSettings();
    const { pageEvalEnabled } = await fakeBrowser.storage.local.get("pageEvalEnabled");
    expect(pageEvalEnabled).toBe(false);
  });
});
