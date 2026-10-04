#!/usr/bin/env bun

// The staleness gate for the generated contract modules; moon run check-gen runs the generators first. A
// module the generators rewrote differently from the checkout, or wrote without it being tracked, fails
// the gate with the fix named. The pathspec covers every generated module and nothing else, so a
// hand-written file sharing the directory can be mid-edit without false-failing it.

import { type Env, repoRoot, runGit } from "./lib.ts";

export const generatedPathspec = "src/packages/shared/src/*.gen.ts";

export interface GenReport {
  /** Generated modules whose working tree differs from the index (what the generators just wrote vs what is staged or committed). */
  stale: string[];
  /** Generated modules the index does not know: written by the generators, never added. */
  untracked: string[];
}

const lines = (root: string, env: Env, ...args: string[]) =>
  runGit(root, env, ...args)
    .split("\n")
    .filter(Boolean);

/**
 * `env` is passed through from the caller: under the pre-commit hook it carries the hook's index, which
 * is the index this gate must judge (a test passes scripts/lib.ts gitEnv's scrubbed copy).
 */
export function checkGenerated(root: string, env: Env): GenReport {
  return {
    stale: lines(root, env, "diff", "--name-only", "--", generatedPathspec),
    untracked: lines(root, env, "status", "--porcelain", "--", generatedPathspec)
      .filter((row) => row.startsWith("?? "))
      .map((row) => row.slice(3)),
  };
}

if (import.meta.main) {
  const report = checkGenerated(repoRoot, process.env);
  if (report.stale.length > 0) {
    console.error(
      "error: generated contract code is stale - run 'moon run gen' after editing the Rust catalogue/taxonomy or wire types:",
    );
    for (const file of report.stale) console.error(file);
  }
  if (report.untracked.length > 0) {
    console.error(
      "error: the generators wrote generated modules that are not tracked - commit them:",
    );
    for (const file of report.untracked) console.error(file);
  }
  if (report.stale.length > 0 || report.untracked.length > 0) process.exit(1);
  console.log("check-gen: the generated contract modules match the checkout");
}
