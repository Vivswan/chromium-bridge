// The settings ladder. The floor, not the rung count, fixes which rung a stored
// version climbs: the control is one hand-authored ladder with its first rung
// retired, reading the same v2 store right with the floor raised and wrong
// without. The live ladder is one no-op rung, so every fixture here is invented.

import { beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import {
  type Climb,
  climb,
  type Ladder,
  type Migration,
  migrateSettings,
  SETTINGS_VERSION,
} from "@/lib/shared/settings-migration";

beforeEach(() => {
  fakeBrowser.reset();
  vi.restoreAllMocks();
});

describe("climb", () => {
  const parseRetries: Migration = (bag) => ({ retries: Number(bag.retries) }); // v1 -> v2
  const addBackoff: Migration = () => ({ backoffMs: 500 }); // v2 -> v3
  const full: Ladder = { firstVersion: 1, migrations: [parseRetries, addBackoff] };
  const retiredAndRaised: Ladder = { firstVersion: 2, migrations: [addBackoff] };
  const retiredFloorKept: Ladder = { firstVersion: 1, migrations: [addBackoff] };
  const v1 = { retries: "3", settingsVersion: 1 };
  const v2 = { retries: 3, settingsVersion: 2 };
  const v3 = { retries: 3, backoffMs: 500, settingsVersion: 3 };

  test.each<[string, Ladder, Record<string, unknown>, Climb]>([
    [
      "v1 climbs both rungs",
      full,
      v1,
      { outcome: "climbed", write: { retries: 3, backoffMs: 500, settingsVersion: 3 } },
    ],
    [
      "v2 climbs the last rung",
      full,
      v2,
      { outcome: "climbed", write: { backoffMs: 500, settingsVersion: 3 } },
    ],
    ["v3 stands on the top", full, v3, { outcome: "current" }],
    ["v4 is a newer extension's store", full, { settingsVersion: 4 }, { outcome: "newer" }],
    [
      "an unstamped store is v0, below this ladder's floor",
      full,
      { retries: "3" },
      { outcome: "too-old", write: { settingsVersion: 3 } },
    ],
    [
      "a malformed stamp reads as v0, below this ladder's floor",
      full,
      { retries: "3", settingsVersion: "2" },
      { outcome: "too-old", write: { settingsVersion: 3 } },
    ],
    [
      "retired and raised: v2 still climbs",
      retiredAndRaised,
      v2,
      { outcome: "climbed", write: { backoffMs: 500, settingsVersion: 3 } },
    ],
    [
      "retired and raised: v1 is too old",
      retiredAndRaised,
      v1,
      { outcome: "too-old", write: { settingsVersion: 3 } },
    ],
    [
      "floor kept: the same v2 store reads as the top, backoff never added",
      retiredFloorKept,
      v2,
      { outcome: "current" },
    ],
    [
      "floor kept: v1 gets the wrong rung, retries stays a string",
      retiredFloorKept,
      v1,
      { outcome: "climbed", write: { backoffMs: 500, settingsVersion: 2 } },
    ],
  ])("%s", (_case, ladder, bag, expected) => {
    expect(climb(ladder, bag)).toEqual(expected);
  });
});

describe("migrateSettings", () => {
  // The storage.local.set request sequence is the contract: one combined write
  // carries the climb and its stamp, a store this build cannot read gets none,
  // and a second run writes nothing.
  test.each<[string, Record<string, unknown>, Record<string, unknown>[]]>([
    ["a fresh store is stamped in one write", {}, [{ settingsVersion: SETTINGS_VERSION }]],
    [
      "a current store is left alone",
      { settingsVersion: SETTINGS_VERSION, pageEvalEnabled: false },
      [],
    ],
    [
      "a newer store is left alone",
      { settingsVersion: SETTINGS_VERSION + 1, pageEvalEnabled: false },
      [],
    ],
  ])("%s, and a second run writes nothing", async (_case, stored, writes) => {
    await fakeBrowser.storage.local.set(stored);
    const set = vi.spyOn(fakeBrowser.storage.local, "set");
    const after = { ...stored, ...Object.assign({}, ...writes) };
    await migrateSettings();
    expect(set.mock.calls.map(([patch]) => patch)).toEqual(writes);
    expect(await fakeBrowser.storage.local.get(null)).toEqual(after);
    await migrateSettings();
    expect(set.mock.calls.map(([patch]) => patch)).toEqual(writes);
    expect(await fakeBrowser.storage.local.get(null)).toEqual(after);
  });
});
