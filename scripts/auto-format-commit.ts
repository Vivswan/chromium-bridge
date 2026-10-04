#!/usr/bin/env bun

// auto-format.yml: after biome rewrote the checkout, commit the result to the pull request's branch, or
// report that nothing changed. The commit is the GitHub Actions bot's (only the id-prefixed address links
// it to that account), and the workflow token travels in the push URL, never into the checkout's git
// config.

import { $ } from "bun";
import { type Env, repoRoot, requiredEnv } from "./lib.ts";

export const COMMIT_SUBJECT = "style: apply automated formatting";
export const BOT = {
  name: "github-actions[bot]",
  email: "41898282+github-actions[bot]@users.noreply.github.com",
};

/** `env` is the child git's whole environment (a test passes scripts/lib.ts gitEnv's scrubbed copy). */
export async function commitFormatting(
  root: string,
  env: Env,
  remote: string,
  branch: string,
): Promise<{ committed: boolean }> {
  const git = (args: string[]) => $`git ${args}`.cwd(root).env(env);
  await git(["add", "--all"]);
  const staged = await git(["diff", "--cached", "--quiet"]).nothrow();
  if (staged.exitCode === 0) return { committed: false };
  await git([
    "-c",
    `user.name=${BOT.name}`,
    "-c",
    `user.email=${BOT.email}`,
    "commit",
    "--quiet",
    "--message",
    COMMIT_SUBJECT,
  ]);
  await git(["push", "--quiet", remote, `HEAD:refs/heads/${branch}`]);
  return { committed: true };
}

if (import.meta.main) {
  const remote = `https://x-access-token:${requiredEnv("GH_TOKEN")}@github.com/${requiredEnv("GITHUB_REPOSITORY")}.git`;
  const branch = requiredEnv("HEAD_REF");
  const result = await commitFormatting(repoRoot, process.env, remote, branch);
  console.log(result.committed ? `pushed "${COMMIT_SUBJECT}" to ${branch}` : "nothing to format");
}
