#!/usr/bin/env bun

// No TRACKED file may be matched by .gitignore: Biome and knip honor the ignore file, so a shadowed file
// drops out of lint, format, and dead-code analysis silently. The fleet sync rewrites the managed region of
// .gitignore, and a template pattern can name a directory this repository tracks source under (the Python
// template's `lib/` once hid every src/**/lib/ file); the repo-owned override belongs below the END marker.
// Only the tree's own .gitignore files count: --exclude-standard would also read the developer's global
// excludes and .git/info/exclude, which no CI tool sees.

import { repoRoot } from "./lib.ts";

export type IgnoredReport = { status: "clean" } | { status: "ignored"; files: string[] };

type Env = Record<string, string | undefined>;

function gitLsFiles(cwd: string, env: Env, args: string[]): string {
  const run = Bun.spawnSync(["git", "ls-files", ...args], { cwd, env });
  if (run.exitCode !== 0) {
    throw new Error(`git ls-files ${args.join(" ")} failed: ${run.stderr.toString().trim()}`);
  }
  return run.stdout.toString();
}

/** List the tracked files under `cwd` that .gitignore matches. Throws when .gitignore itself is not
 * tracked: the file the gate reads must be in the index, or an empty result proves nothing. */
export function checkIgnored(cwd: string, env: Env = process.env): IgnoredReport {
  gitLsFiles(cwd, env, ["--error-unmatch", ".gitignore"]);
  const files = gitLsFiles(cwd, env, [
    "--cached",
    "--ignored",
    "--exclude-per-directory=.gitignore",
  ])
    .split("\n")
    .filter(Boolean);
  return files.length === 0 ? { status: "clean" } : { status: "ignored", files };
}

if (import.meta.main) {
  const report = checkIgnored(repoRoot);
  if (report.status === "ignored") {
    console.error(
      "check-ignored: tracked files matched by .gitignore (Biome and knip skip them silently); " +
        "add a repo-owned override below .gitignore's END marker:",
    );
    for (const file of report.files) console.error(file);
    process.exit(1);
  }
  console.log("check-ignored: no tracked file is matched by .gitignore");
}
