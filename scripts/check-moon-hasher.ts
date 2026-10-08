#!/usr/bin/env bun
// hasher.ignorePatterns keeps generated and downloaded output out of every moon task hash. A missing pattern
// only over-invalidates a cache or fails a run loudly; a pattern that matches a TRACKED file silently drops it
// from every hash, so an edit to it could hit a stale cache. Every pattern is globbed against `git ls-files`
// and any match fails.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { die, repoRoot } from "./lib.ts";

// A missing, empty, or malformed list fails loudly: checking nothing is the failure this gate exists to prevent.
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
