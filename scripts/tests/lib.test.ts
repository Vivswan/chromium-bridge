import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { gitEnv, runGit, Scratch, selectMode } from "../lib";

// The incident: a pre-commit hook in a linked worktree exports GIT_DIR (that worktree's private gitdir) and
// GIT_INDEX_FILE; a scratch `git init` inheriting them re-initialised the shared repository as bare.
const scratch = new Scratch();
afterEach(() => scratch.remove());
const tempDir = (tag: string) => scratch.dir(`lib-${tag}`);
const git = (cwd: string, env: Record<string, string>, ...args: string[]) =>
  runGit(cwd, env, ...args).trim();

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
});

// A workflow step names the mode on the command line: a misspelt, missing, doubled, or flag-shaped mode must
// fail the step with the usage, never run a default mode.
describe("selectMode", () => {
  test("exactly one named mode is selected; anything else prints the usage and exits 2", () => {
    const modes = { build: "b", publish: "p" };
    const exits: unknown[] = [];
    const lines: unknown[] = [];
    const exit = spyOn(process, "exit").mockImplementation(((code: unknown) => {
      exits.push(code);
      throw new Error("exit");
    }) as never);
    const error = spyOn(console, "error").mockImplementation((line: unknown) => {
      lines.push(line);
    });
    try {
      const outcome = (argv: string[]) => {
        try {
          return selectMode(modes, argv, "scripts/x.ts");
        } catch {
          return "exit";
        }
      };
      const argvs = [
        ["build"],
        [],
        ["build", "publish"],
        ["toString"],
        ["--build"],
        ["--", "build"],
      ];
      expect({ outcomes: argvs.map(outcome), exits, lines: new Set(lines) }).toEqual({
        outcomes: ["b", "exit", "exit", "exit", "exit", "exit"],
        exits: [2, 2, 2, 2, 2],
        lines: new Set(["usage: bun scripts/x.ts build | publish"]),
      });
    } finally {
      exit.mockRestore();
      error.mockRestore();
    }
  });
});
