import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CONTROL_FILE, checkCjk, grepEnv } from "../check-cjk";
import { gitEnv, runGit, Scratch, writeTree } from "../lib.ts";

// Hand-written scratch repositories; every CJK fixture is a \u escape so this file passes the gate itself.
const HAN = "\u4E2D";
const scratch = new Scratch();
afterEach(() => scratch.remove());
const tempDir = (tag: string) => scratch.dir(`check-cjk-${tag}`);

function repo(files: Record<string, string>): string {
  const dir = tempDir("repo");
  runGit(dir, gitEnv(), "init", "-q");
  writeTree(dir, files);
  runGit(dir, gitEnv(), "add", "-A");
  return dir;
}

describe("checkCjk", () => {
  test("CJK in a canonical file is reported with its path and line; the allowed files are not", () => {
    const dir = repo({
      [CONTROL_FILE]: `title: ${HAN}\n`,
      "README.md": `# Title\n\nprobe ${HAN} line\n`,
      "README.zh_CN.md": `${HAN}\n`,
      "docs/sub/probe.zh_CN.md": `${HAN}\n`,
    });
    expect(checkCjk(dir, gitEnv())).toEqual({
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
    expect(checkCjk(dir, gitEnv())).toEqual({ status: "clean" });
  });

  test("a control file without CJK fails the gate instead of passing it vacuously", () => {
    const dir = repo({ [CONTROL_FILE]: "title: plain\n", "README.md": "# Title\n" });
    expect(() => checkCjk(dir, gitEnv())).toThrow("engine is blind");
  });

  test("a missing control file fails the gate, never a clean verdict", () => {
    const dir = repo({ "README.md": "# Title\n" });
    expect(() => checkCjk(dir, gitEnv())).toThrow("engine is blind");
  });
});

describe("grepEnv", () => {
  // A fake git standing in for PCRE2's locale behaviour: it accepts the class only under the LC_ALL values
  // in FAKE_GIT_ACCEPT (`*` for any), refusing with git's exit 128 otherwise, and logs each call's locale.
  const FAKE_GIT = [
    "#!/bin/sh",
    'printf "LC_ALL=%s LANG=%s\\n" "$LC_ALL" "$LANG" >> "$FAKE_GIT_LOG"',
    'case ",$FAKE_GIT_ACCEPT," in *",*,"*) ok=1 ;; *",$LC_ALL,"*) ok=1 ;; *) ok=0 ;; esac',
    'if [ "$ok" = 1 ]; then case " $* " in *" -qIP "*) exit 0 ;; *) exit 1 ;; esac; fi',
    'echo "fatal: character code point value in \\x{} or \\o{} is too large" >&2',
    "exit 128",
    "",
  ].join("\n");

  function fakeGit(accept: string, locale: Record<string, string>) {
    const dir = tempDir("fake-git");
    writeFileSync(join(dir, "git"), FAKE_GIT);
    chmodSync(join(dir, "git"), 0o755);
    const log = join(dir, "calls.log");
    const env = { PATH: dir, FAKE_GIT_ACCEPT: accept, FAKE_GIT_LOG: log, ...locale };
    return {
      env,
      calls: () => (existsSync(log) ? readFileSync(log, "utf8").trimEnd().split("\n") : []),
    };
  }

  test("an inherited UTF-8 ctype locale is kept as is, with no LC_ALL imposed", () => {
    const kept: Record<string, string>[] = [
      { LANG: "en_US.UTF-8" },
      { LC_CTYPE: "UTF-8" },
      { LC_ALL: "C.utf8" },
    ];
    for (const locale of kept) {
      const env = fakeGit("*", locale).env;
      expect(grepEnv(tempDir("tree"), env)).toBe(env);
    }
    const fake = fakeGit("*", { LANG: "en_US.UTF-8" });
    expect(checkCjk(tempDir("tree"), fake.env)).toEqual({ status: "clean" });
    expect(fake.calls()).toEqual(["LC_ALL= LANG=en_US.UTF-8", "LC_ALL= LANG=en_US.UTF-8"]);
  });

  test("under LC_ALL=C the first candidate the engine accepts wins (macOS without C.UTF-8)", () => {
    const fake = fakeGit("en_US.UTF-8", { LC_ALL: "C" });
    expect(grepEnv(tempDir("tree"), fake.env).LC_ALL).toBe("en_US.UTF-8");
    expect(fake.calls()).toEqual(["LC_ALL=C.UTF-8 LANG=", "LC_ALL=en_US.UTF-8 LANG="]);
  });

  test("no accepted candidate refuses, naming every locale tried", () => {
    const fake = fakeGit("", { LC_ALL: "C" });
    expect(() => grepEnv(tempDir("tree"), fake.env)).toThrow(
      "C.UTF-8: fatal: character code point value in \\x{} or \\o{} is too large; en_US.UTF-8: fatal:",
    );
  });
});
