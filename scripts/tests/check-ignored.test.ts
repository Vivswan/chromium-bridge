import { afterEach, describe, expect, test } from "bun:test";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { checkIgnored } from "../check-ignored";
import { gitEnv, runGit, Scratch, writeTree } from "../lib.ts";

// Hand-written scratch repositories mirroring the incident: a .gitignore pattern that names a directory the
// tree tracks source under.
const scratch = new Scratch();
afterEach(() => scratch.remove());

function repo(files: Record<string, string>, forced: string[] = []): string {
  const dir = scratch.dir("check-ignored");
  runGit(dir, gitEnv(), "init", "-q");
  writeTree(dir, files);
  runGit(dir, gitEnv(), "add", "-A");
  for (const path of forced) runGit(dir, gitEnv(), "add", "-f", path);
  return dir;
}

describe("checkIgnored", () => {
  test("a tracked file under an ignored directory is reported; untracked ignored files are not", () => {
    const dir = repo(
      { ".gitignore": "lib/\n", "src/lib/mod.ts": "export {};\n", "lib/scratch.txt": "x\n" },
      ["src/lib/mod.ts"],
    );
    expect(checkIgnored(dir, gitEnv())).toEqual({ status: "ignored", files: ["src/lib/mod.ts"] });
  });

  test("a repo-owned negation below the pattern (last match wins) clears the shadowed file", () => {
    const dir = repo({
      ".gitignore": "lib/\n!src/**/lib/\n",
      "src/lib/mod.ts": "export {};\n",
    });
    expect(checkIgnored(dir, gitEnv())).toEqual({ status: "clean" });
  });

  test("an untracked .gitignore fails the gate instead of judging an empty rule set", () => {
    const dir = repo({ "src/mod.ts": "export {};\n" });
    writeFileSync(join(dir, ".gitignore"), "src/\n");
    expect(() => checkIgnored(dir, gitEnv())).toThrow("error-unmatch");
  });
});
