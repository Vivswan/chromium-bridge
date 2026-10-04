#!/usr/bin/env bun

// Re-lock the workspace's own crates and packages after a version bump, then commit exactly the lockfiles.
// release-please bumps Cargo.toml and the extension package.json (extra-files) and no lockfile, and every
// `--locked` cargo step refuses a lockfile whose member version lags its manifest, so the release PR hook
// (.github/workflows/update-release-pr.yml) runs this and pushes the commit it makes. bun's frozen install
// tolerates the lag, but the SBOM is generated from the committed lockfiles, so bun.lock is refreshed too.

import { dirname, join } from "node:path";
import { $ } from "bun";
import { type Env, repoRoot } from "./lib.ts";

export const COMMIT_SUBJECT = "chore(release): refresh the lockfiles after the version bump";

export interface Refresh {
  /** Repo-relative lockfiles the refresh rewrote, in `git diff` order. */
  changed: string[];
  committed: boolean;
}

/**
 * `env` is the child processes' whole environment: a caller under a git hook strips GIT_DIR and friends
 * (scripts/lib.ts gitEnv) so the commit lands in `root`, not in the hook's repository.
 */
export async function refreshLockfiles(root: string, env: Env): Promise<Refresh> {
  const run = (cmd: string[], cwd = root) => $`${cmd}`.cwd(cwd).env(env);
  const lines = (text: string) => text.split("\n").filter(Boolean);
  const tracked = async (...patterns: string[]) =>
    lines(await run(["git", "ls-files", "--", ...patterns]).text());

  // `--offline` fails on a runner with an empty registry cache (the member re-lock still reads every
  // dependency's index entry), so the network stays available.
  const cargoLocks = await tracked("Cargo.lock", "*/Cargo.lock");
  for (const lock of cargoLocks) {
    await run([
      "cargo",
      "update",
      "--workspace",
      "--manifest-path",
      join(dirname(lock), "Cargo.toml"),
    ]);
  }
  const bunLocks = await tracked("bun.lock", "*/bun.lock");
  for (const lock of bunLocks) {
    await run(["bun", "install", "--lockfile-only"], join(root, dirname(lock)));
  }

  const lockfiles = [...cargoLocks, ...bunLocks];
  const changed = lines(await run(["git", "diff", "--name-only", "--", ...lockfiles]).text());
  if (changed.length === 0) return { changed, committed: false };
  await run(["git", "commit", "--quiet", "--message", COMMIT_SUBJECT, "--", ...lockfiles]);
  return { changed, committed: true };
}

if (import.meta.main) {
  const result = await refreshLockfiles(repoRoot, process.env);
  for (const lock of result.changed) console.log(`refreshed ${lock}`);
  console.log(
    result.committed
      ? `committed ${result.changed.length} lockfile(s)`
      : "lockfiles already match their manifests; nothing to commit",
  );
}
