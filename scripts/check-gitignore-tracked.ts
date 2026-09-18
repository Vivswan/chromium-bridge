#!/usr/bin/env bun
// Guard: no TRACKED file may be matched by .gitignore.
//
// The managed region of .gitignore is rewritten by the fleet sync from
// upstream templates, and a template pattern can name a directory this
// repository tracks source under: the Python template's `lib/` (a
// virtualenv layout) shadowed every src/**/lib/ file. Biome and knip honor
// the ignore file, so a shadowed file silently drops out of lint, format,
// and dead-code analysis. The repo-owned override belongs below the END
// marker of .gitignore; this script fails the gate while any tracked file
// is still ignored.
//
// Run via `moon run check-ignored` (part of the ci gate) and CI's
// version-consistency job.

import { die, repoRoot } from "./lib.ts";

function trackedFiles(extraArgs: string[]): string[] {
  const ls = Bun.spawnSync(["git", "ls-files", "-z", ...extraArgs], { cwd: repoRoot });
  if (ls.exitCode !== 0) die(`git ls-files ${extraArgs.join(" ")} failed: ${ls.stderr.toString()}`);
  return ls.stdout.toString().split("\0").filter(Boolean);
}

// The positive control: an empty tracked set means the probe is blind, not
// that nothing is ignored.
const tracked = trackedFiles([]);
if (tracked.length === 0) die("git ls-files listed no tracked files - nothing can be judged");

// Only the tree's own .gitignore files: --exclude-standard would also read
// the developer's global excludes and .git/info/exclude, which no CI tool sees.
const ignored = trackedFiles(["--cached", "--ignored", "--exclude-per-directory=.gitignore"]);
if (ignored.length > 0) {
  console.error(
    `${ignored.length} TRACKED file(s) are matched by .gitignore - Biome and knip skip them silently:`,
  );
  for (const hit of ignored.slice(0, 10)) console.error(`  ${hit}`);
  if (ignored.length > 10) console.error(`  ... and ${ignored.length - 10} more`);
  die("add a repo-owned override below .gitignore's END marker (last match wins)");
}

console.log(`ok: none of the ${tracked.length} tracked files is matched by .gitignore`);
