import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync, symlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type Finding, parseCli, probePage } from "../docs-probe";
import { gitEnv, runGit, Scratch, writeTree } from "../lib";

const script = join(dirname(fileURLToPath(import.meta.url)), "..", "docs-probe.ts");
const scratch = new Scratch();
afterEach(() => scratch.remove());

const CAP = 5;
/** The pinned columns: the key, subject, and kind are the CLI baseline test's business. */
const seen = (findings: readonly Finding[]) =>
  findings.map(({ file, line, message }) => ({ file, line, message }));
const over = (noun: string, words: number) =>
  `${noun} of ${words} words; the cap is ${CAP}. Split it, or turn its facts into bullets, a table, or numbered steps`;

// The readings the docs gate relies on, each a cross-file fact: the renderer's GENERATED markers
// (render-architecture-map.ts) must hide the region from the word count, a backticked repository
// path must be checked only where the tree anchors it, Markdown's block structure decides what is
// prose, and a finding's line is the prose line, never a fenced copy above it.
describe("probePage", () => {
  const cases: ReadonlyArray<
    readonly [
      name: string,
      page: string,
      findings: readonly Pick<Finding, "file" | "line" | "message">[],
    ]
  > = [
    [
      "a paragraph over the cap, at its line, while a short one is silent",
      "# T\n\nshort one.\n\none two three four five six.\n",
      [{ file: "docs/p.md", line: 5, message: over("paragraph", 6) }],
    ],
    [
      "a list item over the cap",
      "- one two three four five\n- one two three four five six seven\n",
      [{ file: "docs/p.md", line: 2, message: over("list item", 7) }],
    ],
    [
      "a loose list item is one item, its paragraphs counted together",
      "- one two three\n\n  four five six\n",
      [{ file: "docs/p.md", line: 1, message: over("list item", 6) }],
    ],
    [
      "a loose item under a heading is located by its first paragraph, not by a needle spanning two",
      "# Heading\n\n- Start\n\n  one two three four five\n",
      [{ file: "docs/p.md", line: 3, message: over("list item", 6) }],
    ],
    [
      "a loose item around a nested list counts its own paragraphs, and the nested item keeps its own line",
      "- parent starts\n\n  - child alpha beta gamma delta epsilon\n\n  parent ends\n  next line\n  another line\n  last line\n",
      [
        { file: "docs/p.md", line: 1, message: over("list item", 10) },
        { file: "docs/p.md", line: 3, message: over("list item", 6) },
      ],
    ],
    [
      "prose inside the region the map renderer writes counts nothing",
      [
        "# T",
        "",
        "<!-- BEGIN GENERATED: architecture-map (bun scripts/render-architecture-map.ts) -->",
        "one two three four five six seven eight.",
        "<!-- END GENERATED: architecture-map -->",
        "",
      ].join("\n"),
      [],
    ],
    [
      "a code span showing a tag or a comment is prose, so it and the words after it count",
      "A `<em>` `<!-- x -->` one two three four five six.\n",
      [{ file: "docs/p.md", line: 1, message: over("paragraph", 11) }],
    ],
    [
      "an inline comment holding a `>` ends at its own `-->`, so the prose after it still counts",
      "A <!-- see <span --> one two three four five six.\n",
      [{ file: "docs/p.md", line: 1, message: over("paragraph", 7) }],
    ],
    [
      "a formatting tag joins the words around it and a break tag separates them, whatever their attributes hold",
      'one<em title="a > b">two</em>three four<br title="a > b">five six seven eight\n',
      [{ file: "docs/p.md", line: 1, message: over("paragraph", 6) }],
    ],
    [
      "escaped comment syntax is prose the reader sees, so it counts",
      "A &lt;!-- one two three four five six.\n",
      [{ file: "docs/p.md", line: 1, message: over("paragraph", 8) }],
    ],
    [
      "a fenced block and a table count nothing, however long",
      "```text\none two three four five six seven\n```\n\n| a | b |\n| - | - |\n| one two three four five six | seven |\n",
      [],
    ],
    [
      "a named path that does not exist and a dead relative link, while a real one is silent",
      "See `docs/gone.md`, [x](./missing.md), and `docs/real.md`.\n",
      [
        { file: "docs/p.md", line: 1, message: "`docs/gone.md` does not exist" },
        { file: "docs/p.md", line: 1, message: "link target ./missing.md does not exist" },
      ],
    ],
    [
      "a path quoted in a fence before the prose that names it is reported at the prose line",
      "```text\n`docs/gone.md`\n```\n\nSee `docs/gone.md`.\n",
      [{ file: "docs/p.md", line: 5, message: "`docs/gone.md` does not exist" }],
    ],
    [
      "a path quoted in indented code before the prose that names it is reported at the prose line",
      "# P\n\n    `docs/gone.md`\n\nSee `docs/gone.md`.\n",
      [{ file: "docs/p.md", line: 5, message: "`docs/gone.md` does not exist" }],
    ],
    [
      "a path inside a one-line HTML comment before the prose that names it is reported at the prose line",
      "# P\n\n<!-- `docs/gone.md` -->\n\nSee `docs/gone.md`.\n",
      [{ file: "docs/p.md", line: 5, message: "`docs/gone.md` does not exist" }],
    ],
    [
      "a bare file name, a placeholder, a slug, and a tree this repository lacks are left alone",
      "`package.json`, `<dir>/x.md`, `owner/repo`, and `agents/openai.yaml`.\n",
      [],
    ],
  ];

  test.each(cases)("%s", (_name, page, findings) => {
    const root = scratch.dir("docs-probe");
    writeTree(root, { "docs/real.md": "# Real\n", "docs/p.md": page });
    expect(seen(probePage(page, "docs/p.md", { root, maxWords: CAP, paths: true }))).toEqual([
      ...findings,
    ]);
  });
});

// Which pages are translations is check-docs-locales' call (docs/<locale>/ and the root README), so a
// zh-cn segment deeper in the tree, or a locale-suffixed name elsewhere, is an English page under the cap.
describe("a locale page skips the word cap and keeps its path and link findings", () => {
  const pages: ReadonlyArray<readonly [page: string, capped: boolean]> = [
    ["docs/zh-cn/p.md", false],
    ["README.zh-tw.md", false],
    ["docs/guides/zh-cn/x.md", true],
    ["docs/README.zh-cn.md", true],
  ];
  test.each(pages)("%s", (page, capped) => {
    const root = scratch.dir("docs-probe-locale");
    const text = "one two three four five six.\n\nSee [x](./missing.md) and `docs/gone.md`.\n";
    writeTree(root, { "docs/real.md": "# Real\n", [page]: text });
    expect(seen(probePage(text, page, { root, maxWords: CAP, paths: true }))).toEqual([
      ...(capped ? [{ file: page, line: 1, message: over("paragraph", 6) }] : []),
      { file: page, line: 3, message: "`docs/gone.md` does not exist" },
      { file: page, line: 3, message: "link target ./missing.md does not exist" },
    ]);
  });
});

// A built icon or a tool cache exists after a build and not on a fresh clone, so a page naming one
// got a different verdict in two worktrees of the same commit (one had built the extension, one had
// not). A path git ignores is not a repository file wherever the probe runs, built or fresh, and a
// directory token keeps its slash so a `build/` rule still matches it. The scratch repository's git
// runs with GIT_* scrubbed, so this file can run inside the pre-commit hook.
describe("a path or link target that git ignores is not part of the repository", () => {
  const states: ReadonlyArray<readonly [state: string, files: Record<string, string>]> = [
    ["built: the artifact exists", { "build/out.png": "" }],
    ["fresh: the artifact was never built", {}],
  ];
  test.each(states)("%s", (_state, artifact) => {
    const root = scratch.dir("docs-probe-ignored");
    runGit(root, gitEnv(), "init", "-q");
    writeTree(root, {
      ".gitignore": "build/\n",
      "docs/real.md": "# Real\n",
      "docs/p.md":
        "See `build/out.png`, `build/`, [out](../build/out.png), [root](../), and `docs/real.md`.\n",
      ...artifact,
    });
    expect(
      seen(
        probePage(readFileSync(join(root, "docs/p.md"), "utf8"), "docs/p.md", {
          root,
          maxWords: 20,
          paths: true,
        }),
      ),
    ).toEqual([
      {
        file: "docs/p.md",
        line: 1,
        message: "`build/out.png` is not part of the repository (git ignores it)",
      },
      {
        file: "docs/p.md",
        line: 1,
        message: "`build/` is not part of the repository (git ignores it)",
      },
      {
        file: "docs/p.md",
        line: 1,
        message: "link target ../build/out.png is not part of the repository (git ignores it)",
      },
    ]);
  });
});

// A path beyond a symlink makes git refuse the whole check-ignore batch (bun's dependency store is
// reached through such symlinks), and a refusal read as "nothing ignored" would pass the page. The
// probe fails closed instead: the error names the path so the author can see what git refused.
test("a git check-ignore failure fails the probe instead of passing the page", () => {
  const root = scratch.dir("docs-probe-symlink");
  runGit(root, gitEnv(), "init", "-q");
  // The refused path is spelled so git's own message contains "not a git repository": only the
  // anchored "fatal: not a git repository" means nothing is ignored.
  writeTree(root, {
    "real/x.md": "# X\n",
    "docs/p.md": "See [x](../link/not%20a%20git%20repository.md).\n",
  });
  symlinkSync(join(root, "real"), join(root, "link"));
  expect(() =>
    probePage(readFileSync(join(root, "docs/p.md"), "utf8"), "docs/p.md", {
      root,
      maxWords: CAP,
      paths: true,
    }),
  ).toThrow(/git check-ignore failed .*link\/not a git repository\.md/s);
});

// Two link targets that differ by one space are two files, so their allowances must differ; only
// prose is whitespace-normalized, since a rewrapped paragraph is still the same paragraph.
test("path and link subjects are fingerprinted as written", () => {
  const root = scratch.dir("docs-probe-keys");
  writeTree(root, {
    "docs/p.md": "[x](./missing%20file.md) and [y](./missing%20%20file.md).\n",
    "docs/q.md": "one two three four five six\n",
    "docs/r.md": "one two three\nfour five six\n",
  });
  const probe = (page: string) =>
    probePage(readFileSync(join(root, page), "utf8"), page, { root, maxWords: CAP, paths: true });
  const [x, y] = probe("docs/p.md");
  expect(x?.key).not.toBe(y?.key);
  const [q] = probe("docs/q.md");
  const [r] = probe("docs/r.md");
  expect(q?.key.split(" ")[1]).toBe(r?.key.split(" ")[1]);
});

// Also the shell contract the moon task relies on: a glob that matches nothing exits non-zero.
test("the baseline keys on the unit, so a line shift keeps it valid and an edit makes it stale", () => {
  const root = scratch.dir("docs-probe-cli");
  writeTree(root, { "docs/a.md": "# A\n\none two three four.\n" });
  const run = (...args: string[]) => {
    const result = spawnSync("bun", [script, "--root", root, "--max-words", "3", ...args], {
      encoding: "utf8",
      cwd: root,
    });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  };

  const printed = run("--print-baseline", "docs/**/*.md");
  expect(printed.status).toBe(0);
  expect(printed.stdout).toMatch(
    /^docs\/a\.md [0-9a-f]{8} {2}# paragraph: one two three four\.\n$/,
  );
  writeTree(root, { exact: printed.stdout, empty: "# nothing allowed\n" });

  expect(run("--baseline", "exact", "docs/**/*.md")).toEqual({
    status: 0,
    stdout: "docs-probe: 1 page(s) clean (cap 3 words); 1 finding(s) allowed by exact\n",
    stderr: "",
  });
  expect(run("--baseline", "empty", "docs/**/*.md")).toEqual({
    status: 1,
    stdout: "",
    stderr: [
      "docs-probe: 1 finding(s) outside the baseline, 0 stale baseline line(s)",
      "  docs/a.md:3: paragraph of 4 words; the cap is 3. Split it, or turn its facts into bullets, a table, or numbered steps",
      "",
    ].join("\n"),
  });

  // Two lines inserted above the paragraph: the same allowance still holds.
  writeTree(root, { "docs/a.md": "# A\n\nA short lead.\n\none two three four.\n" });
  expect(run("--baseline", "exact", "docs/**/*.md")).toEqual({
    status: 0,
    stdout: "docs-probe: 1 page(s) clean (cap 3 words); 1 finding(s) allowed by exact\n",
    stderr: "",
  });

  // The paragraph edited: the old allowance is stale and the new text is a fresh finding.
  writeTree(root, { "docs/a.md": "# A\n\none two three five.\n" });
  const edited = run("--baseline", "exact", "docs/**/*.md");
  const key = printed.stdout.split("  #")[0];
  expect(edited).toEqual({
    status: 1,
    stdout: "",
    stderr: [
      "docs-probe: 1 finding(s) outside the baseline, 1 stale baseline line(s)",
      "  docs/a.md:3: paragraph of 4 words; the cap is 3. Split it, or turn its facts into bullets, a table, or numbered steps",
      `  ${key}: no finding fires for this unit any more; remove the line from exact`,
      "",
    ].join("\n"),
  });

  writeTree(root, {
    "docs/a.md": "# A\n\none two three four.\n",
    "docs/zh-cn/a.md": "# A\n\none two three four five six.\n",
  });
  expect(run("--baseline", "exact", "docs/**/*.md")).toEqual({
    status: 0,
    stdout:
      "docs-probe: 2 page(s) clean (cap 3 words; 1 locale page(s) paths and links only); 1 finding(s) allowed by exact\n",
    stderr: "",
  });
  // A glob spelled with ./ names the same pages, so the labels, the allowances, and the locale count hold.
  expect(run("--baseline", "exact", "./docs/**/*.md")).toEqual({
    status: 0,
    stdout:
      "docs-probe: 2 page(s) clean (cap 3 words; 1 locale page(s) paths and links only); 1 finding(s) allowed by exact\n",
    stderr: "",
  });
  // Without the path check a locale page would pass with nothing probed, so the pair is refused.
  expect(run("--shape-only", "docs/**/*.md")).toEqual({
    status: 2,
    stdout: "",
    stderr:
      "docs-probe: --shape-only leaves a locale page with nothing to check: docs/zh-cn/a.md\n",
  });

  expect(run("--baseline", "exact", "nowhere/**/*.md")).toEqual({
    status: 2,
    stdout: "",
    stderr: `docs-probe: nowhere/**/*.md matches no file under ${realpathSync.native(root)}\n`,
  });
});

// The check-docs-probe task's flags reach the probe through this parser: a mistyped or valueless flag, or no
// page at all, must fail the task, never probe with defaults; a --root given last still places every --base.
test("the CLI refuses an unknown flag, a flag without its value, and no page; a full flag set parses whole", () => {
  const root = scratch.dir("docs-probe-args");
  writeTree(root, { "docs/a.md": "# A\n" });
  const refused: ReadonlyArray<readonly [args: string[], message: RegExp]> = [
    [["--bogus", "docs/a.md"], /usage:/],
    [["--root"], /usage:/],
    [["--max-words", "0", "docs/a.md"], /positive integer/],
    [[], /usage:/],
  ];
  for (const [args, message] of refused) {
    expect(() => parseCli(["--root", root, ...args])).toThrow(message);
  }
  expect(
    parseCli(["--base", "docs", "--max-words", "5", "--shape-only", "--root", root, "docs/a.md"]),
  ).toEqual({
    root: realpathSync(root),
    bases: [realpathSync(join(root, "docs"))],
    maxWords: 5,
    paths: false,
    baseline: undefined,
    printBaseline: false,
    pages: ["docs/a.md"],
  });
});
