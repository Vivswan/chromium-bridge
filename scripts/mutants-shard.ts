#!/usr/bin/env bun

// nightly.yml's mutants job: one shard of the cargo-mutants pass. cargo-mutants exits 2 for a missed mutant and 3
// for one that timed out; both mean a mutant survived the suite, which the job reports and does not fail on. Every
// other nonzero exit (the baseline build or test failing, a usage error) is real and is the shard's exit.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { die, repoRoot, requiredEnv } from "./lib.ts";

export const survivedExits = new Set([2, 3]);
export const outcomeFiles = ["missed", "timeout", "unviable"] as const;

export interface ShardResult {
  summary: string[];
  exit: number;
}

/**
 * The outcome files with members, under a header each. cargo-mutants writes every file, empty or not, so
 * only a file it never wrote (it failed before running) is skipped; any other read failure propagates.
 */
export function outcomeSummary(mutantsOut: string): string[] {
  const lines = ["== outcome summary =="];
  for (const name of outcomeFiles) {
    let text: string;
    try {
      text = readFileSync(join(mutantsOut, `${name}.txt`), "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    if (text !== "") lines.push(`-- ${name} --`, text.trimEnd());
  }
  return lines;
}

export function runShard(
  shard: string,
  total: string,
  run: (argv: string[]) => number,
  mutantsOut: string,
): ShardResult {
  if (!/^\d+$/.test(shard) || !/^[1-9]\d*$/.test(total)) {
    throw new Error(`the shard index and total must be integers (got ${shard}/${total})`);
  }
  const status = run(["cargo", "mutants", "--no-shuffle", "--shard", `${shard}/${total}`]);
  return { summary: outcomeSummary(mutantsOut), exit: survivedExits.has(status) ? 0 : status };
}

if (import.meta.main) {
  const [shard, total] = [requiredEnv("SHARD"), requiredEnv("SHARD_TOTAL")];
  try {
    const result = runShard(
      shard,
      total,
      (argv) =>
        Bun.spawnSync(argv, { cwd: repoRoot, stdio: ["inherit", "inherit", "inherit"] }).exitCode,
      join(repoRoot, "mutants.out"),
    );
    for (const line of result.summary) console.log(line);
    process.exit(result.exit);
  } catch (error) {
    die((error as Error).message);
  }
}
