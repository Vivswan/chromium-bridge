import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { checkIgnored } from "./check-ignored";
import { gitEnv } from "./lib.ts";

// Hand-written scratch repositories mirroring the incident: a .gitignore pattern that names a directory the
// tree tracks source under.
const scratch: string[] = [];

function git(cwd: string, ...args: string[]) {
  const run = Bun.spawnSync(["git", ...args], { cwd, env: gitEnv });
  if (run.exitCode !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr.toString()}`);
}

function repo(files: Record<string, string>, forced: string[] = []): string {
  const dir = mkdtempSync(join(tmpdir(), "check-ignored-"));
  scratch.push(dir);
  git(dir, "init", "-q");
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  git(dir, "add", "-A");
  for (const path of forced) git(dir, "add", "-f", path);
  return dir;
}

afterEach(() => {
  for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("checkIgnored", () => {
  test("a tracked file under an ignored directory is reported; untracked ignored files are not", () => {
    const dir = repo(
      { ".gitignore": "lib/\n", "src/lib/mod.ts": "export {};\n", "lib/scratch.txt": "x\n" },
      ["src/lib/mod.ts"],
    );
    expect(checkIgnored(dir, gitEnv)).toEqual({ status: "ignored", files: ["src/lib/mod.ts"] });
  });

  test("a repo-owned negation below the pattern (last match wins) clears the shadowed file", () => {
    const dir = repo({
      ".gitignore": "lib/\n!src/**/lib/\n",
      "src/lib/mod.ts": "export {};\n",
    });
    expect(checkIgnored(dir, gitEnv)).toEqual({ status: "clean" });
  });

  test("an untracked .gitignore fails the gate instead of judging an empty rule set", () => {
    const dir = repo({ "src/mod.ts": "export {};\n" });
    writeFileSync(join(dir, ".gitignore"), "src/\n");
    expect(() => checkIgnored(dir, gitEnv)).toThrow("error-unmatch");
  });
});
