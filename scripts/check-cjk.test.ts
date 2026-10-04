import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { CONTROL_FILE, checkCjk } from "./check-cjk";
import { gitEnv } from "./lib.ts";

// Hand-written scratch repositories; every CJK fixture is a \u escape so this file passes the gate itself.
const HAN = "\u4E2D";
const scratch: string[] = [];

function git(cwd: string, ...args: string[]) {
  const run = Bun.spawnSync(["git", ...args], { cwd, env: gitEnv });
  if (run.exitCode !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr.toString()}`);
}

function repo(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "check-cjk-"));
  scratch.push(dir);
  git(dir, "init", "-q");
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  git(dir, "add", "-A");
  return dir;
}

afterEach(() => {
  for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("checkCjk", () => {
  test("CJK in a canonical file is reported with its path and line; the allowed files are not", () => {
    const dir = repo({
      [CONTROL_FILE]: `title: ${HAN}\n`,
      "README.md": `# Title\n\nprobe ${HAN} line\n`,
      "README.zh_CN.md": `${HAN}\n`,
      "docs/sub/probe.zh_CN.md": `${HAN}\n`,
    });
    expect(checkCjk(dir, gitEnv)).toEqual({
      status: "hits",
      hits: `README.md:3:probe ${HAN} line`,
    });
  });

  test("a tree whose CJK sits only in allowed files, nested translated docs included, is clean", () => {
    const dir = repo({
      [CONTROL_FILE]: `title: ${HAN}\n`,
      "README.md": "# Title\n",
      "docs/sub/probe.zh_CN.md": `${HAN}\n`,
      "src/apps/extension/src/lib/native-language-names.ts": `export const zh = "${HAN}";\n`,
    });
    expect(checkCjk(dir, gitEnv)).toEqual({ status: "clean" });
  });

  test("a control file without CJK fails the gate instead of passing it vacuously", () => {
    const dir = repo({ [CONTROL_FILE]: "title: plain\n", "README.md": "# Title\n" });
    expect(() => checkCjk(dir, gitEnv)).toThrow("engine is blind");
  });

  test("a missing control file fails the gate, never a clean verdict", () => {
    const dir = repo({ "README.md": "# Title\n" });
    expect(() => checkCjk(dir, gitEnv)).toThrow("engine is blind");
  });
});
