import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readArchitecture, renderArchitectureMermaid } from "../arch-lint";
import { conceptCounts, diagramProblems } from "../check-architecture-page";
import { Scratch, writeTree } from "../lib";
import { spliceMap } from "../render-architecture-map";

const script = join(dirname(fileURLToPath(import.meta.url)), "..", "check-architecture-page.ts");
const scratch = new Scratch();
afterEach(() => scratch.remove());

function repo(): string {
  const root = scratch.dir("arch-page");
  writeTree(root, {
    "architecture.yml": "layers:\n  core: [src/]\n  checks: [tests/]\nedges:\n  checks: [core]\n",
    "src/a.ts": "export function run() {}\nexport const k = 1;\n",
    "tests/a.test.ts": "export {};\n",
  });
  return root;
}

const diagram = (label: string) => `\`\`\`mermaid\nflowchart LR\n  a["${label}"]\n\`\`\``;
const DEMO = "Demonstrated by: [a](../tests/a.test.ts)";

// The pins a box must survive: its file exists, its symbols are exported, and its concept diagram
// closes with a demonstration link that resolves. The last case is a cross-file fact: the map
// render-architecture-map.ts splices in is path-only and inside a GENERATED region, so it needs no
// demonstration line and its labels must read as paths, or the generated map would fail the page.
describe("diagramProblems", () => {
  const cases: ReadonlyArray<readonly [name: string, body: string, problems: string[]]> = [
    [
      "a box naming a missing file",
      `## C\n\n${diagram("src/gone.ts run()")}\n\n${DEMO}\n`,
      ['"src/gone.ts run()": src/gone.ts does not exist'],
    ],
    [
      "a fence quoted in a block quote ends with the quote, so the diagram after it is still checked",
      `> \`\`\`text\n> quoted, never closed\n\n## C\n\n${diagram("src/gone.ts run()")}\n\n${DEMO}\n`,
      ['"src/gone.ts run()": src/gone.ts does not exist'],
    ],
    [
      "a quote marker indented one space continues the quote, so the fenced text stays text",
      `> \`\`\`text\n > example\n> \`\`\`mermaid\n> flowchart LR a["src/gone.ts"]\n> \`\`\`\n`,
      [],
    ],
    [
      "an inline ```mermaid``` run is code, not a fence opener, so the diagram after it is checked",
      `## C\n\n\`\`\`mermaid\`\`\`\n\n\`\`\`mermaid\ngraph TD\n a["src/gone.ts"]\n\`\`\`\n\n${DEMO}\n`,
      ['"src/gone.ts": src/gone.ts does not exist'],
    ],
    [
      "a box with a numeric id naming a missing file",
      `## C\n\n\`\`\`mermaid\nflowchart TD\n  123["src/gone.ts"]\n\`\`\`\n\n${DEMO}\n`,
      ['"src/gone.ts": src/gone.ts does not exist'],
    ],
    [
      "a box naming a symbol its file does not export",
      `## C\n\n${diagram("src/a.ts fly()")}\n\n${DEMO}\n`,
      ['"src/a.ts fly()": src/a.ts exports no fly'],
    ],
    [
      "a concept diagram with no demonstration line before the next heading",
      `## C\n\n${diagram("src/a.ts run()")}\n\n## D\n\n${DEMO}\n`,
      ['line 5: the diagram has no "Demonstrated by:" line before the next heading'],
    ],
    [
      "a demonstration link that resolves to no file",
      `## C\n\n${diagram("src/a.ts run()")}\n\nDemonstrated by: [a](../tests/gone.test.ts)\n`,
      ['line 5: "../tests/gone.test.ts" names a file that does not exist'],
    ],
    [
      "a box with real exports, a caption-only box, and a resolving demonstration link are clean",
      `## C\n\n\`\`\`mermaid\nflowchart LR\n  a["src/a.ts run() k"] --> b["the live page"]\n\`\`\`\n\n${DEMO}\n`,
      [],
    ],
  ];

  test.each(cases)("%s", (_name, body, problems) => {
    const root = repo();
    const page = `# Architecture\n\n${body}`;
    expect(diagramProblems(page, { root, pagePath: join(root, "docs/architecture.md") })).toEqual(
      problems,
    );
  });

  test("a diagram inside a multi-line HTML comment is not rendered, so it is neither counted nor checked", () => {
    const root = repo();
    const page = `# Architecture\n\n## C\n\n<!--\n${diagram("src/gone.ts fly()")}\n-->\n`;
    expect(diagramProblems(page, { root, pagePath: join(root, "docs/architecture.md") })).toEqual(
      [],
    );
    expect(conceptCounts(page)).toEqual({ diagrams: 0, demonstrations: 0 });
  });

  test("the rendered module map inside its GENERATED region is not a concept diagram and passes the pins", () => {
    const root = repo();
    const map = renderArchitectureMermaid(readArchitecture(join(root, "architecture.yml")));
    const page = spliceMap(
      "# Architecture\n\n## Map\n\n<!-- BEGIN GENERATED: architecture-map -->\n<!-- END GENERATED: architecture-map -->\n",
      "architecture-map",
      map,
    );
    expect(diagramProblems(page, { root, pagePath: join(root, "docs/architecture.md") })).toEqual(
      [],
    );
    expect(conceptCounts(page)).toEqual({ diagrams: 0, demonstrations: 0 });
  });
});

// The shell contract the check-architecture task relies on: the diagram count is pinned, so a
// diagram that vanishes or appears fails until --expect-diagrams moves with it on purpose.
describe("the CLI's --expect-diagrams pin", () => {
  const outcomes: ReadonlyArray<
    readonly [expected: string, outcome: { status: number; stdout: string; stderr: string }]
  > = [
    [
      "2",
      {
        status: 1,
        stdout: "",
        stderr: [
          "check-architecture-page: docs/architecture.md: 1 problem(s)",
          "  expected 2 concept diagrams, found 1; change --expect-diagrams only when a diagram was added or removed on purpose",
          "",
        ].join("\n"),
      },
    ],
    [
      "1",
      {
        status: 0,
        stdout:
          "check-architecture-page: docs/architecture.md names real code (concept diagrams: 1)\n",
        stderr: "",
      },
    ],
  ];

  test.each(outcomes)(
    "--expect-diagrams %s against a page with one diagram",
    (expected, outcome) => {
      const root = repo();
      writeTree(root, {
        "docs/architecture.md": `# Architecture\n\n## C\n\n${diagram("src/a.ts run()")}\n\n${DEMO}\n`,
      });
      const result = spawnSync(
        "bun",
        [script, "--root", root, "--page", "docs/architecture.md", "--expect-diagrams", expected],
        { encoding: "utf8", cwd: root },
      );
      expect({ status: result.status, stdout: result.stdout, stderr: result.stderr }).toEqual(
        outcome,
      );
    },
  );
});

// The check-architecture task's flags reach the page check through this parser: a mistyped or valueless
// flag, a missing --page, or a non-numeric --expect-diagrams must fail the task, never check with defaults.
test("the CLI exits 2 with the usage on an unknown flag, a missing --page, and a malformed --expect-diagrams", () => {
  const root = repo();
  const cases: ReadonlyArray<readonly [args: string[], stderr: RegExp]> = [
    [["--page", "docs/architecture.md", "--bogus"], /usage:/],
    [["--page"], /usage:/],
    [[], /--page is required/],
    [["--page", "docs/architecture.md", "--expect-diagrams", "two"], /whole number/],
  ];
  const outcomes = cases.map(([args]) => {
    const result = spawnSync("bun", [script, "--root", root, ...args], {
      encoding: "utf8",
      cwd: root,
    });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  });
  expect(outcomes).toEqual(
    cases.map(([, stderr]) => ({ status: 2, stdout: "", stderr: expect.stringMatching(stderr) })),
  );
});
