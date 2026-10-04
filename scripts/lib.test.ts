import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gitEnv } from "./lib";

// The incident: a pre-commit hook in a linked worktree exports GIT_DIR (that worktree's private gitdir) and
// GIT_INDEX_FILE; a scratch `git init` inheriting them re-initialised the shared repository as bare.
const scratch: string[] = [];

function git(cwd: string, env: Record<string, string>, ...args: string[]): string {
  const run = Bun.spawnSync(["git", ...args], { cwd, env });
  if (run.exitCode !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr.toString()}`);
  return run.stdout.toString().trim();
}

function tempDir(tag: string): string {
  const dir = mkdtempSync(join(tmpdir(), `lib-gitenv-${tag}-`));
  scratch.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("gitEnv", () => {
  test("a scratch git init under a worktree hook's GIT_DIR leaves the hook's repository untouched", () => {
    const victim = tempDir("victim");
    const clean = gitEnv();
    git(victim, clean, "init", "-q");
    git(
      victim,
      clean,
      "-c",
      "user.name=t",
      "-c",
      "user.email=t@example.com",
      "commit",
      "-q",
      "--allow-empty",
      "-m",
      "init",
    );
    const linked = join(victim, "wt");
    git(victim, clean, "worktree", "add", "-q", linked, "-b", "wt");
    const linkedGitDir = join(victim, ".git", "worktrees", "wt");
    const headBefore = readFileSync(join(victim, ".git", "HEAD"), "utf8");
    const hookEnv: Record<string, string> = {
      ...clean,
      GIT_DIR: linkedGitDir,
      GIT_INDEX_FILE: join(linkedGitDir, "index"),
    };

    // The hazard is real: an inheriting child re-initialises the victim as a bare repository.
    git(tempDir("hazard"), hookEnv, "init", "-q");
    expect(git(victim, clean, "config", "--get", "core.bare")).toBe("true");
    git(victim, clean, "config", "core.bare", "false");

    const safe = tempDir("safe");
    git(safe, gitEnv(hookEnv), "init", "-q");
    expect(git(victim, clean, "config", "--get", "core.bare")).toBe("false");
    expect(readFileSync(join(victim, ".git", "HEAD"), "utf8")).toBe(headBefore);
    expect(git(safe, gitEnv(hookEnv), "rev-parse", "--git-dir")).toBe(".git");
  });

  test("every GIT_* variable is dropped and nothing else is", () => {
    const env = gitEnv({
      PATH: "/usr/bin",
      GIT_DIR: "/repo/.git",
      GIT_INDEX_FILE: "/repo/.git/index",
      GIT_CEILING_DIRECTORIES: "/",
      LC_ALL: "C.UTF-8",
      EMPTY: undefined,
    });
    expect(env).toEqual({ PATH: "/usr/bin", LC_ALL: "C.UTF-8" });
  });
});
