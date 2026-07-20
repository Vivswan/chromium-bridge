#!/usr/bin/env bun
// Guard for .moon/workspace.yml's hasher.ignorePatterns: no TRACKED file may
// match any pattern there.
//
// The ignore list exists to keep generated and downloaded output (target/,
// build/, .wxt/, rendered icons, ...) out of every moon task hash. A missing
// pattern is safe (it can only over-invalidate a cache or fail a run
// loudly); a pattern that matches a tracked source file is the dangerous
// direction - it silently drops that file from every hash, so an edit to it
// could produce a stale cache hit. This script closes that hole: it globs
// every ignore pattern against `git ls-files` and fails on any match (e.g.
// someone naming a tracked source directory build/ or tmp/).
//
// Run via `moon run check-hasher` (part of the ci gate) and CI's
// version-consistency job.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { die, repoRoot } from "./lib.ts";

// Read hasher.ignorePatterns as real YAML (Bun.YAML, like the sibling
// check-all-green.ts / check-toolchain.ts), and fail loudly on a missing,
// empty, or malformed list - silently checking nothing is the failure mode
// this script exists to prevent.
const workspaceYml = readFileSync(join(repoRoot, ".moon/workspace.yml"), "utf8");
const workspace = Bun.YAML.parse(workspaceYml) as {
  hasher?: { ignorePatterns?: unknown };
} | null;
const ignorePatterns = workspace?.hasher?.ignorePatterns;
if (!Array.isArray(ignorePatterns) || ignorePatterns.length === 0) {
  die(".moon/workspace.yml has no non-empty hasher.ignorePatterns list");
}
const patterns = ignorePatterns.map((entry, i) => {
  if (typeof entry !== "string" || entry === "") {
    die(`hasher.ignorePatterns[${i}] is not a non-empty string: ${JSON.stringify(entry)}`);
  }
  return entry;
});

const ls = Bun.spawnSync(["git", "ls-files", "-z"], { cwd: repoRoot });
if (ls.exitCode !== 0) die(`git ls-files failed: ${ls.stderr.toString()}`);
const tracked = ls.stdout.toString().split("\0").filter(Boolean);

let failed = false;
for (const pattern of patterns) {
  const glob = new Bun.Glob(pattern);
  const hits = tracked.filter((file) => glob.match(file));
  if (hits.length > 0) {
    console.error(
      `hasher.ignorePattern '${pattern}' matches ${hits.length} TRACKED file(s) - ` +
        "these are silently dropped from every moon task hash (a stale-cache hole):",
    );
    for (const hit of hits.slice(0, 10)) console.error(`  ${hit}`);
    if (hits.length > 10) console.error(`  ... and ${hits.length - 10} more`);
    failed = true;
  }
}

if (!failed) {
  console.log(`ok: no tracked file matches any of the ${patterns.length} hasher.ignorePatterns`);
}
process.exit(failed ? 1 : 0);
