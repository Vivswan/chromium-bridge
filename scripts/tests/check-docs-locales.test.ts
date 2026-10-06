import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkLocales, type LocaleReport, problemsOf } from "../check-docs-locales";
import { Scratch, writeTree } from "../lib";

const script = join(dirname(fileURLToPath(import.meta.url)), "..", "check-docs-locales.ts");
const scratch = new Scratch();
afterEach(() => scratch.remove());

const ENGLISH = { "docs/a.md": "# A\n", "docs/sec/b.md": "# B\n", "README.md": "# R\n" };
const absent = (locale: LocaleReport["locale"]): LocaleReport => ({ locale, present: false });
const full = (locale: LocaleReport["locale"]): LocaleReport => ({
  locale,
  present: true,
  missing: [],
  extra: [],
  readmeMissing: false,
});

// The contract the rewrite's locale directories must meet: every English page has its mirror and
// nothing exists in one language only. Both directions are judged, the README rides along, and the
// old `.zh_CN.md` suffix files are not a locale.
describe("checkLocales", () => {
  const cases: ReadonlyArray<
    readonly [
      name: string,
      files: Record<string, string>,
      reports: LocaleReport[],
      problems: string[],
    ]
  > = [
    [
      "no locale directory and no locale README: nothing to judge",
      { ...ENGLISH, "README.zh_CN.md": "# old suffix\n", "docs/a.zh_CN.md": "# old suffix\n" },
      [absent("zh-cn"), absent("zh-tw")],
      [],
    ],
    [
      "a partial mirror: a page missing, a page mirroring nothing, and the README missing",
      { ...ENGLISH, "docs/zh-cn/a.md": "# A\n", "docs/zh-cn/extra.md": "# X\n" },
      [
        {
          locale: "zh-cn",
          present: true,
          missing: ["sec/b.md"],
          extra: ["extra.md"],
          readmeMissing: true,
        },
        absent("zh-tw"),
      ],
      [
        "README.zh-cn.md is missing (docs/zh-cn/ exists)",
        "docs/zh-cn/sec/b.md is missing (docs/sec/b.md has no mirror)",
        "docs/zh-cn/extra.md mirrors nothing under docs/",
      ],
    ],
    [
      "a locale README alone makes the locale present, so the whole tree is then required",
      { ...ENGLISH, "README.zh-tw.md": "# R\n" },
      [
        absent("zh-cn"),
        {
          locale: "zh-tw",
          present: true,
          missing: ["a.md", "sec/b.md"],
          extra: [],
          readmeMissing: false,
        },
      ],
      [
        "docs/zh-tw/a.md is missing (docs/a.md has no mirror)",
        "docs/zh-tw/sec/b.md is missing (docs/sec/b.md has no mirror)",
      ],
    ],
    [
      "both locales mirroring docs/ file-for-file with their READMEs",
      {
        ...ENGLISH,
        "README.zh-cn.md": "# R\n",
        "README.zh-tw.md": "# R\n",
        "docs/zh-cn/a.md": "# A\n",
        "docs/zh-cn/sec/b.md": "# B\n",
        "docs/zh-tw/a.md": "# A\n",
        "docs/zh-tw/sec/b.md": "# B\n",
      },
      [full("zh-cn"), full("zh-tw")],
      [],
    ],
  ];

  test.each(cases)("%s", (_name, files, reports, problems) => {
    const root = scratch.dir("docs-locales");
    writeTree(root, files);
    const actual = checkLocales(root);
    expect(actual).toEqual(reports);
    expect(problemsOf(actual)).toEqual(problems);
  });
});

// The shell contract the check-docs-locales task relies on. A root with a missing or empty docs/
// would otherwise read as a tree with nothing to mirror.
test("the CLI exits 0 with no locale tree, 1 on a partial mirror, and 2 on a missing or empty docs/", () => {
  const root = scratch.dir("docs-locales-cli");
  writeTree(root, ENGLISH);
  const run = (at: string) =>
    spawnSync("bun", [script, "--root", at], { encoding: "utf8", cwd: root });

  const outcome = (result: ReturnType<typeof run>) => ({
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  });

  expect(outcome(run(root))).toEqual({
    status: 0,
    stdout: "check-docs-locales: no locale tree yet (zh-cn, zh-tw absent)\n",
    stderr: "",
  });

  writeTree(root, { "docs/zh-cn/a.md": "# A\n", "README.zh-cn.md": "# R\n" });
  expect(outcome(run(root))).toEqual({
    status: 1,
    stdout: "",
    stderr:
      "check-docs-locales: 1 problem(s)\n  docs/zh-cn/sec/b.md is missing (docs/sec/b.md has no mirror)\n",
  });

  const elsewhere = join(root, "elsewhere");
  expect(outcome(run(elsewhere))).toEqual({
    status: 2,
    stdout: "",
    stderr: `check-docs-locales: ${join(elsewhere, "docs")} is not a directory; the English docs tree is the reference\n`,
  });

  const empty = join(root, "empty");
  mkdirSync(join(empty, "docs"), { recursive: true });
  writeTree(empty, { "README.zh-cn.md": "# R\n" });
  expect(outcome(run(empty))).toEqual({
    status: 2,
    stdout: "",
    stderr: `check-docs-locales: ${join(empty, "docs")} holds no .md page; the English docs tree is the reference\n`,
  });
});

// The check-docs-locales task's flags reach the check through this parser: a mistyped or valueless flag must
// fail the task, never check the cwd by default.
test("the CLI exits 2 with the usage on an unknown flag and a --root without its value", () => {
  const root = scratch.dir("docs-locales-args");
  const outcomes = [["--bogus"], ["--root"]].map((args) => {
    const result = spawnSync("bun", [script, ...args], { encoding: "utf8", cwd: root });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  });
  expect(outcomes).toEqual([
    { status: 2, stdout: "", stderr: expect.stringMatching(/usage:/) },
    { status: 2, stdout: "", stderr: expect.stringMatching(/usage:/) },
  ]);
});
