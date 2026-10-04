import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { Scratch, writeTree } from "../lib.ts";
import { runShard, type ShardResult } from "../mutants-shard.ts";

// cargo-mutants writes one outcome file per class, empty when the class is empty, and exits 2 or 3 when a
// mutant survived: facts the shard relies on and nothing here enforces. Pinned on hand-written outcome
// files and a fake cargo that records the command it was given and exits with the case's status.

const scratch = new Scratch();
afterAll(() => scratch.remove());

function mutantsOut(files: Record<string, string>): string {
  const dir = scratch.dir("mutants.out");
  writeTree(
    dir,
    Object.fromEntries(Object.entries(files).map(([name, text]) => [`${name}.txt`, text])),
  );
  return dir;
}

function shard(status: number, dir: string): ShardResult & { argv: string[][] } {
  const argv: string[][] = [];
  const result = runShard(
    "3",
    "8",
    (command) => {
      argv.push(command);
      return status;
    },
    dir,
  );
  return { ...result, argv };
}

const header = "== outcome summary ==";
const argv = [["cargo", "mutants", "--no-shuffle", "--shard", "3/8"]];
const empty = { missed: "", timeout: "", unviable: "" };
const missed = "src/lib.rs:12:5: replace f -> u32 with 0\n";
const timeout = "src/io.rs:40:9: replace read -> bool with true\n";

describe("runShard", () => {
  test.each<[string, number, Record<string, string>, ShardResult]>([
    ["a clean shard exits 0 and prints the bare header", 0, empty, { summary: [header], exit: 0 }],
    [
      "missed mutants are listed under their class and the shard stays green",
      2,
      { ...empty, missed },
      { summary: [header, "-- missed --", missed.trimEnd()], exit: 0 },
    ],
    [
      "timeouts likewise, with every non-empty class in file order",
      3,
      { ...empty, timeout, unviable: "src/x.rs:1:1: replace g with ()\n" },
      {
        summary: [
          header,
          "-- timeout --",
          timeout.trimEnd(),
          "-- unviable --",
          "src/x.rs:1:1: replace g with ()",
        ],
        exit: 0,
      },
    ],
    [
      "a baseline failure is the shard's exit, with the files cargo-mutants left still printed",
      4,
      { ...empty, missed },
      { summary: [header, "-- missed --", missed.trimEnd()], exit: 4 },
    ],
    [
      "outcome files cargo-mutants never wrote (it failed before running) are skipped, not an error",
      1,
      {},
      { summary: [header], exit: 1 },
    ],
  ])("%s", (_name, status, files, expected) => {
    expect(shard(status, mutantsOut(files))).toEqual({ ...expected, argv });
  });

  test("an outcome file that exists but cannot be read is not an empty one: the error propagates", () => {
    const dir = mutantsOut(empty);
    rmSync(join(dir, "missed.txt"));
    mkdirSync(join(dir, "missed.txt"));
    expect(() => shard(2, dir)).toThrow(/EISDIR/);
  });

  test("a shard spec that is not two integers is refused before cargo runs", () => {
    let ran = false;
    const run = () => {
      ran = true;
      return 0;
    };
    for (const [index, total] of [
      ["a", "8"],
      ["3", "0"],
      ["3/8", "8"],
      ["", "8"],
    ] as const) {
      expect(() => runShard(index, total, run, mutantsOut(empty))).toThrow(/must be integers/);
    }
    expect(ran).toBe(false);
  });
});
