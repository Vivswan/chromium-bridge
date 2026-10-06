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
const full = (locale: LocaleReport["locale"]): Extract<LocaleReport, { present: true }> => ({
  locale,
  present: true,
  missing: [],
  extra: [],
  generatedDrift: [],
  structureDrift: [],
  readmeMissing: false,
});

// The contract a locale directory must meet: every English page has its mirror and nothing exists
// in one language only. Both directions are judged, the README rides along, and the
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
          generatedDrift: [],
          structureDrift: [],
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
          generatedDrift: [],
          structureDrift: [],
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
    [
      "a generated region in a translated page must equal the English one byte for byte; a translated page without the region, or with another name's region, is drift too",
      {
        "docs/a.md":
          "# A\n<!-- BEGIN GENERATED: map (bun x) -->\ngraph TD\n<!-- END GENERATED: map -->\n",
        "docs/sec/b.md":
          "# B\n<!-- BEGIN GENERATED: map -->\ngraph TD\n<!-- END GENERATED: map -->\n",
        "docs/c.md": "# C\n<!-- BEGIN GENERATED: map -->\ngraph TD\n<!-- END GENERATED: map -->\n",
        "README.md": "# R\n",
        "docs/zh-cn/a.md":
          "# \u7532\n<!-- BEGIN GENERATED: map (bun x) -->\ngraph LR\n<!-- END GENERATED: map -->\n",
        "docs/zh-cn/sec/b.md": "# \u4e59\n",
        "docs/zh-cn/c.md":
          "# \u4e19\n<!-- BEGIN GENERATED: chart -->\ngraph TD\n<!-- END GENERATED: chart -->\n",
        "README.zh-cn.md": "# R\n",
        "docs/zh-tw/a.md":
          "# \u7532\n<!-- BEGIN GENERATED: map (bun x) -->\ngraph TD\n<!-- END GENERATED: map -->\n",
        "docs/zh-tw/sec/b.md":
          "# \u4e59\n<!-- BEGIN GENERATED: map -->\ngraph TD\n<!-- END GENERATED: map -->\n",
        "docs/zh-tw/c.md":
          "# \u4e19\n<!-- BEGIN GENERATED: map -->\ngraph TD\n<!-- END GENERATED: map -->\n",
        "README.zh-tw.md": "# R\n",
      },
      [
        {
          ...full("zh-cn"),
          generatedDrift: [
            "docs/zh-cn/a.md: generated region map",
            "docs/zh-cn/c.md: generated region chart",
            "docs/zh-cn/c.md: generated region map",
            "docs/zh-cn/sec/b.md: generated region map",
          ],
        },
        full("zh-tw"),
      ],
      [
        "docs/zh-cn/a.md: generated region map differs from the English page's; copy it byte for byte",
        "docs/zh-cn/c.md: generated region chart differs from the English page's; copy it byte for byte",
        "docs/zh-cn/c.md: generated region map differs from the English page's; copy it byte for byte",
        "docs/zh-cn/sec/b.md: generated region map differs from the English page's; copy it byte for byte",
      ],
    ],
    [
      "a translation keeps the English page's structure: a dropped heading, a lost fence (inside a list item " +
        "included), a missing table row (an indented one included), a renamed flag, a changed double-backtick or " +
        "triple-backtick span, or a span whose interior spaces differ is drift; prose, fence contents, a table's " +
        "delimiter row, a marker line with trailing text inside a fence, a span wrapped across indented lines (its " +
        "line break reads as one space), and the headings, rows, and backticks inside a fence are not; the root README " +
        "is judged too",
      {
        "docs/a.md":
          "# A\n\nRun `pair --reset` then `revoke`, or ``echo `whoami` ``. Use ```doctor --fix``` too.\n\n## B\n\n~~~text\n```\n~~~ not a closer\n# not a heading\n| not | a row |\n`not " +
          "code`\n~~~\n\n| k | v |\n| --- | --- |\n| `x` | 1 |\n\n1. Run `doctor\n   --fix` now.\n\n   ```sh\n   echo ok\n   ```\n\n   | i | j |\n   | --- | --- |\n   | `y` | 2 |\n",
        "docs/sec/b.md": "# B\n\nPlain `one` and `two\nthree` and `printf '%s' 'a  b'`.\n",
        "README.md": "# R\n\n- `doctor --fix`\n",
        "docs/zh-cn/a.md":
          "# \u7532\n\n\u57f7\u884c `pair --reset`, \u6216 ``echo `hostname` ``. Use ```doctor --list``` too.\n\n| k | v |\n| --- | --- |\n\n1. \u57f7\u884c `doctor --fix` now.\n\n   | i | j |\n   | --- | --- |\n",
        "docs/zh-cn/sec/b.md":
          "# \u4e59\n\n\u7d14 `one` \u8207 `two three` \u8207 `printf '%s' 'a b'`.\n",
        "README.zh-cn.md": "# R\n\n- `doctor --fix`\n- `doctor --fix`\n",
        "docs/zh-tw/a.md":
          "# \u7532\n\n\u57f7\u884c `pair --reset` \u518d `revoke`, \u6216 ``echo `whoami` ``. Use ```doctor --fix``` too.\n\n## " +
          "\u4e59\n\n~~~text\n```\n\u4e0d\u540c\u7684\u5167\u5bb9\n~~~\n\n| \u9375 | \u503c |\n| --- | --- |\n| `x` | 1 |\n\n1. \u57f7\u884c `doctor\n   --fix` now.\n\n   ```sh\n   \u597d\n  " +
          " ```\n\n   | i | j |\n   | --- | --- |\n   | `y` | 2 |\n",
        "docs/zh-tw/sec/b.md":
          "# \u4e59\n\n\u7d14 `two three` \u8207 `one` \u8207 `printf '%s' 'a  b'`.\n",
        "README.zh-tw.md": "# R\n\n- `doctor --fix`\n",
      },
      [
        {
          ...full("zh-cn"),
          structureDrift: [
            "docs/zh-cn/a.md: headings 1 vs 2 in the English",
            "docs/zh-cn/a.md: fences 0 vs 2 in the English",
            "docs/zh-cn/a.md: tableRows 2 vs 4 in the English",
            "docs/zh-cn/a.md: English only `doctor --fix`",
            "docs/zh-cn/a.md: translation only `doctor --list`",
            "docs/zh-cn/a.md: translation only `echo `hostname``",
            "docs/zh-cn/a.md: English only `echo `whoami``",
            "docs/zh-cn/a.md: English only `revoke`",
            "docs/zh-cn/a.md: English only `x`",
            "docs/zh-cn/a.md: English only `y`",
            "docs/zh-cn/sec/b.md: English only `printf '%s' 'a  b'`",
            "docs/zh-cn/sec/b.md: translation only `printf '%s' 'a b'`",
            "README.zh-cn.md: translation only `doctor --fix`",
          ],
        },
        full("zh-tw"),
      ],
      [
        "docs/zh-cn/a.md: headings 1 vs 2 in the English; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/a.md: fences 0 vs 2 in the English; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/a.md: tableRows 2 vs 4 in the English; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/a.md: English only `doctor --fix`; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/a.md: translation only `doctor --list`; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/a.md: translation only `echo `hostname``; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/a.md: English only `echo `whoami``; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/a.md: English only `revoke`; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/a.md: English only `x`; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/a.md: English only `y`; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/sec/b.md: English only `printf '%s' 'a  b'`; a translation keeps the English page's headings, fences, table rows, and inline code",
        "docs/zh-cn/sec/b.md: translation only `printf '%s' 'a b'`; a translation keeps the English page's headings, fences, table rows, and inline code",
        "README.zh-cn.md: translation only `doctor --fix`; a translation keeps the English page's headings, fences, table rows, and inline code",
      ],
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
