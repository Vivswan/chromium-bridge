import { afterEach, describe, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { findPlanningRefs, scanFiles } from "../check-planning-refs";
import { gitEnv, Scratch } from "../lib";

const script = join(dirname(fileURLToPath(import.meta.url)), "..", "check-planning-refs.ts");
const scratch = new Scratch();
afterEach(() => scratch.remove());
const repo = () => scratch.dir("check-planning-refs");

// Every tag shape the scrub removed, as it stood in the tree, each caught by exactly the pattern named
// for it. A regex rewrite that lets one shape through fails here, not in the next sweep.
describe("findPlanningRefs", () => {
  const planted: ReadonlyArray<readonly [text: string, pattern: string]> = [
    [
      "// ONE policy snapshot for the whole decision (ADR-0032 decision 4):",
      "design record number",
    ],
    ["// Mirrors the retired ADR text verbatim.", "bare design record word"],
    ["// see docs/adr/0034-mcp-stateless.md", "retired records directory"],
    ["// Sequence-suppressed (decision 7): only a strictly newer push applies", "decision tag"],
    ["// Plus the decision-4 in-flight rule at vitest granularity", "decision tag"],
    ['describe("the scope-stamped ratchet (findings 1 and 2)", () => {});', "finding tag"],
    ["// Amended at Phase 3 implementation: the ratchet is not enforced", "phase tag"],
    ["// It must not count as the panic's phase-1 refusal", "phase tag"],
    ['  "a fresh key to recover (E2F-1)."', "audit code"],
    ['  "re-pair to recover (U1)";', "parenthesized audit code"],
    [
      "// Exact shape, not toMatchObject (CS-5): the blocked arm must carry NO",
      "parenthesized audit code",
    ],
    [
      'test("H1: known-A -> revoke -> re-pair A retains the ratchet", () => {});',
      "audit code in a test title",
    ],
    [
      'describe("policy consumption hardening (durable prior pin H1, F2 latch, F3/H4 undo)", () => {});',
      "audit code in a test title",
    ],
    [
      'test("dispatch refuses from its OWN single read when blocked (the barrier race, SFX-1a)", () => {});',
      "audit code in a test title",
    ],
    [
      'test("U1 backstop: a pinned-scope record is refused at the write", () => {});',
      "audit code in a test title",
    ],
    ['test.each(cases)("H1: %s survives a restart", () => {});', "audit code in a test title"],
    ['it.skip("CS-5: exact shape of the blocked arm", () => {});', "audit code in a test title"],
    ['describe.only("F2 latch", () => {});', "audit code in a test title"],
    ['test.todo("U1 backstop at the write");', "audit code in a test title"],
    [
      'test.concurrent("S4: the barrier refuses first", async () => {});',
      "audit code in a test title",
    ],
    [
      'test.each(cases.map((c) => [c, resolve("tmp/x")]))("H1 survives $name", () => {});',
      "audit code in a test title",
    ],
    ['test.each([["a)", "(b"]])("CS-5 keeps the shape", () => {});', "audit code in a test title"],
  ];

  test.each(planted)("flags %j as %s with its line", (text, pattern) => {
    expect(findPlanningRefs("x.ts", `// clean line\n${text}\n`)).toEqual([
      { path: "x.ts", line: 2, pattern, text: text.trim() },
    ]);
  });

  test("a wrapped test call and an apostrophe inside the title hide nothing", () => {
    const wrapped = [
      "test(",
      '  "the host\'s durable prior pin H1 survives a restart",',
      "  async () => {});",
    ].join("\n");
    expect(findPlanningRefs("x.ts", wrapped)).toEqual([
      {
        path: "x.ts",
        line: 2,
        pattern: "audit code in a test title",
        text: '"the host\'s durable prior pin H1 survives a restart",',
      },
    ]);
  });

  // Shapes a text scanner misreads and a parser does not: a comment with an apostrophe inside the
  // `.each` argument, and a title template whose hole holds another template.
  test("comments inside .each arguments and nested templates in a title hide nothing", () => {
    const text = [
      "test.each([",
      "  // the worker's refusal",
      "  [undefined],",
      '])("H1 survives", () => {});',
      // biome-ignore lint/suspicious/noTemplateCurlyInString: the template is the fixture under test
      "test(`${file ? `lang-${file}` : file} H1 survives`, () => {});",
    ].join("\n");
    expect(findPlanningRefs("x.ts", text).map((h) => h.line)).toEqual([4, 5]);
  });

  test("a file the parser rejects is a hit at the failing line, not a crash", () => {
    expect(findPlanningRefs("x.ts", "export const a = 1;\ntest(\n")).toEqual([
      { path: "x.ts", line: 3, pattern: "cannot parse (Expected `)` but found `EOF`)", text: "" },
    ]);
  });

  test("the reasons that replaced the tags, and look-alike prose, are clean", () => {
    const text = [
      "// ONE policy snapshot for the whole decision, never a live re-read mid-decision:",
      "// a decision never re-reads live policy; the final decision stands",
      "// findings are listed in the PR body; two-phase commit is not used here",
      "// F12: open DevTools. H1: page heading. A hash like 0xF2 is not a code. (S) marks a site.",
      '// The UI calls it ("H1" means a page heading).',
      'test("pressing F12 opens DevTools", () => {});',
      "// adr is also a filename stem in /usr/share/dict, which this never scans",
    ].join("\n");
    expect(findPlanningRefs("x.ts", text)).toEqual([]);
  });
});

describe("scanFiles", () => {
  test("reports a planted tag with its path and line, and nothing for a clean file", () => {
    const dir = repo();
    writeFileSync(join(dir, "clean.ts"), "// states the rule itself\nexport const a = 1;\n");
    writeFileSync(join(dir, "tagged.ts"), "export const b = 2;\n// per ADR-0032 decision 3\n");
    expect(scanFiles(dir, ["clean.ts", "tagged.ts"])).toEqual([
      {
        path: "tagged.ts",
        line: 2,
        pattern: "design record number",
        text: "// per ADR-0032 decision 3",
      },
    ]);
  });
});

// Once per covered file class, the red run is the control for the green one. The bare `*.rs` pathspecs
// reach nested files only because git's `*` crosses `/`, which nothing else here checks.
const coveredPaths: ReadonlyArray<readonly [path: string, comment: string]> = [
  ["docs/guide.md", "#"],
  ["scripts/tool.ts", "//"],
  ["tests/interop/client.test.ts", "//"],
  ["src/packages/core/src/policy/store.rs", "//"],
  ["src/packages/core/Cargo.toml", "#"],
  ["tests/protocol/e2e.py", "#"],
];

function writeAndStageFile(root: string, rel: string, lines: string[]): void {
  const env = gitEnv();
  const file = join(root, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${lines.join("\n")}\n`);
  execFileSync("git", ["-C", root, "add", rel], { stdio: "pipe", env });
}

test.each(coveredPaths)(
  "the CLI exits 1 on a tracked tag in %s and 0 once it is gone",
  (rel, comment) => {
    const root = repo();
    const env = gitEnv();
    execFileSync("git", ["-C", root, "init", "-q"], { stdio: "pipe", env });
    writeAndStageFile(root, rel, [
      `${comment} Guide`,
      "",
      `${comment} The gate refuses (ADR-0032 decision 4).`,
    ]);

    const red = spawnSync("bun", [script, root], { encoding: "utf8", env });
    expect({ status: red.status, stdout: red.stdout, stderr: red.stderr }).toEqual({
      status: 1,
      stdout: "",
      stderr:
        `${rel}:3: design record number: ${comment} The gate refuses (ADR-0032 decision 4).\n` +
        "check-planning-refs: 1 planning reference(s) in 1 file(s). Replace each with the reason it " +
        "stood for, or delete it when the sentence already states the rule.\n",
    });

    writeAndStageFile(root, rel, [
      `${comment} Guide`,
      "",
      `${comment} The gate refuses until the push verified.`,
    ]);
    const green = spawnSync("bun", [script, root], { encoding: "utf8", env });
    expect({ status: green.status, stdout: green.stdout, stderr: green.stderr }).toEqual({
      status: 0,
      stdout: "check-planning-refs: 1 file(s) clean\n",
      stderr: "",
    });
  },
);

// The negative control for the cases above: the pathspecs select, they do not scan the whole tree, so a
// tag in an unlisted class is invisible and the red runs above come from the roots reaching their files.
test("a tag in a file class no pathspec names is not scanned", () => {
  const root = repo();
  const env = gitEnv();
  execFileSync("git", ["-C", root, "init", "-q"], { stdio: "pipe", env });
  writeAndStageFile(root, "notes/scratch.txt", ["The gate refuses (ADR-0032 decision 4)."]);
  const run = spawnSync("bun", [script, root], { encoding: "utf8", env });
  expect({ status: run.status, stderr: run.stderr }).toEqual({ status: 0, stderr: "" });
  expect(run.stdout).toMatch(/^check-planning-refs: 0 file\(s\) clean/);
});

// Given an explicit root, the CLI must read THAT root's index even under a hook's GIT_DIR and GIT_INDEX_FILE.
//   hook repo = a second scratch repo, its variables inherited unstripped  -> the isolation is the script's own
//   the page tagged in the index, clean in the working tree                -> hook run exits 1, plain run exits 0
test("under a hook an explicit root is judged by its own staged content, not the hook's repository", () => {
  const target = repo();
  const setup = gitEnv();
  execFileSync("git", ["-C", target, "init", "-q"], { stdio: "pipe", env: setup });
  mkdirSync(join(target, "docs"));
  const page = join(target, "docs", "guide.md");
  writeFileSync(page, "# Guide\n\nThe gate refuses (ADR-0032 decision 4).\n");
  execFileSync("git", ["-C", target, "add", "docs/guide.md"], { stdio: "pipe", env: setup });
  writeFileSync(page, "# Guide\n\nThe gate refuses until this connection's push verified.\n");

  const hookRepo = repo();
  execFileSync("git", ["-C", hookRepo, "init", "-q"], { stdio: "pipe", env: setup });
  const hookGitDir = join(hookRepo, ".git");
  const hookIndex = join(hookGitDir, "index");
  const headBefore = readFileSync(join(hookGitDir, "HEAD"), "utf8");

  const hooked = spawnSync("bun", [script, target], {
    encoding: "utf8",
    env: { ...setup, GIT_DIR: hookGitDir, GIT_INDEX_FILE: hookIndex },
  });
  expect({ status: hooked.status, stdout: hooked.stdout }).toEqual({ status: 1, stdout: "" });
  expect(hooked.stderr).toContain("docs/guide.md:3: design record number: The gate refuses");
  expect({
    hookIndexExists: existsSync(hookIndex),
    head: readFileSync(join(hookGitDir, "HEAD"), "utf8"),
  }).toEqual({ hookIndexExists: false, head: headBefore });

  const plain = spawnSync("bun", [script, target], { encoding: "utf8", env: setup });
  expect({ status: plain.status, stderr: plain.stderr }).toEqual({ status: 0, stderr: "" });

  // git's own pre-commit hook exports GIT_INDEX_FILE without GIT_DIR in an ordinary checkout, so that
  // variable alone must already select the staged content.
  const plainHook = spawnSync("bun", [script, target], {
    encoding: "utf8",
    env: { ...setup, GIT_INDEX_FILE: hookIndex },
  });
  expect({ status: plainHook.status, stdout: plainHook.stdout, stderr: plainHook.stderr }).toEqual({
    status: 1,
    stdout: "",
    stderr: expect.stringContaining("docs/guide.md:3: design record number: The gate refuses"),
  });
});

// `git cat-file --batch` reads one request per line, so a tracked path with a newline in it would turn
// into two requests and shift every later answer onto the wrong path. The scan refuses such a path.
test("a tracked path containing a newline fails the staged scan instead of misreading it", () => {
  const root = repo();
  const env = gitEnv();
  execFileSync("git", ["-C", root, "init", "-q"], { stdio: "pipe", env });
  mkdirSync(join(root, "docs"));
  const odd = "docs/a.md\nb.md";
  writeFileSync(join(root, "docs", "a.md"), "clean\n");
  writeFileSync(join(root, "docs", "b.md"), "clean\n");
  writeFileSync(join(root, odd), "tagged (ADR-0032 decision 4)\n");
  execFileSync("git", ["-C", root, "add", "docs/a.md", "docs/b.md", odd], { stdio: "pipe", env });
  expect(() => scanFiles(root, ["docs/a.md", odd, "docs/b.md"], "index", env)).toThrow(
    /a tracked path with a newline cannot be scanned/,
  );
});
