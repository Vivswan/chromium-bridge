import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type Finding, probePage } from "../docs-probe";
import { gitEnv, runGit, Scratch, writeTree } from "../lib";

const script = join(dirname(fileURLToPath(import.meta.url)), "..", "docs-probe.ts");
const scratch = new Scratch();
afterEach(() => scratch.remove());

const CAP = 5;
const over = (noun: string, words: number) =>
  `${noun} of ${words} words; the cap is ${CAP}. Split it, or turn its facts into bullets, a table, or numbered steps`;

// The readings the docs gate relies on, each a cross-file fact: the renderer's GENERATED markers
// (render-architecture-map.ts) must hide the region from the word count, a backticked repository
// path must be checked only where the tree anchors it, Markdown's block structure decides what is
// prose, and a finding's line is the prose line the baseline keys on, never a fenced copy above it.
describe("probePage", () => {
  const cases: ReadonlyArray<readonly [name: string, page: string, findings: readonly Finding[]]> =
    [
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
    expect(probePage(page, "docs/p.md", { root, maxWords: CAP, paths: true })).toEqual([
      ...findings,
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
      probePage(readFileSync(join(root, "docs/p.md"), "utf8"), "docs/p.md", {
        root,
        maxWords: 20,
        paths: true,
      }),
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

// The shell contract the moon task relies on (`set -e` stops on a non-zero exit): the gate fails in
// both directions of the baseline, and a glob that matches nothing is an error, never a vacuous pass.
test("the CLI exits 0 on an exact baseline, 1 on an unlisted finding or a stale line, and 2 on an empty glob", () => {
  const root = scratch.dir("docs-probe-cli");
  writeTree(root, {
    "docs/a.md": "# A\n\none two three four.\n",
    "exact": "docs/a.md:3\n",
    "empty": "# nothing allowed\n",
    "stale": "docs/a.md:3\ndocs/a.md:9\n",
  });
  const run = (...args: string[]) => {
    const result = spawnSync("bun", [script, "--root", root, "--max-words", "3", ...args], {
      encoding: "utf8",
      cwd: root,
    });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  };

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
  expect(run("--baseline", "stale", "docs/a.md")).toEqual({
    status: 1,
    stdout: "",
    stderr: [
      "docs-probe: 0 finding(s) outside the baseline, 1 stale baseline line(s)",
      "  docs/a.md:9: no finding fires here any more; remove the line from stale",
      "",
    ].join("\n"),
  });
  expect(run("--baseline", "exact", "nowhere/**/*.md")).toEqual({
    status: 2,
    stdout: "",
    stderr: `docs-probe: nowhere/**/*.md matches no file under ${realpathSync.native(root)}\n`,
  });
});
