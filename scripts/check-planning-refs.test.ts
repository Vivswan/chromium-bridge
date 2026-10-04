import { afterEach, describe, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { findPlanningRefs, gitEnv, scanFiles } from "./check-planning-refs";

const script = join(dirname(fileURLToPath(import.meta.url)), "check-planning-refs.ts");
const scratchDirs: string[] = [];

afterEach(() => {
  for (const dir of scratchDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "check-planning-refs-"));
  scratchDirs.push(dir);
  return dir;
}

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
    ['  "re-pair to recover (U1)",', "parenthesized audit code"],
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
  ];

  test.each(planted)("flags %j as %s with its line", (text, pattern) => {
    expect(findPlanningRefs("x.ts", `clean line\n${text}\n`)).toEqual([
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
      { path: "x.ts", line: 1, pattern: "audit code in a test title", text: "test(" },
    ]);
  });

  test("the reasons that replaced the tags, and look-alike prose, are clean", () => {
    const text = [
      "// ONE policy snapshot for the whole decision, never a live re-read mid-decision:",
      "// a decision never re-reads live policy; the final decision stands",
      "// findings are listed in the PR body; two-phase commit is not used here",
      "F12: open DevTools. H1: page heading. A hash like 0xF2 is not a code. (S) marks a site.",
      'test("pressing F12 opens DevTools", () => {});',
      "// adr is also a filename stem in /usr/share/dict, which this never scans",
    ].join("\n");
    expect(findPlanningRefs("x.ts", text)).toEqual([]);
  });

  test("the gate's own source is clean under its own patterns, so widening COVERED to scripts/ cannot trip on it", () => {
    expect(findPlanningRefs("check-planning-refs.ts", readFileSync(script, "utf8"))).toEqual([]);
  });
});

describe("scanFiles", () => {
  test("reports a planted tag with its path and line, and nothing for a clean file", () => {
    const dir = scratch();
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

// The shell contract the moon task relies on (`set -e` stops on a non-zero exit): over a git tree with
// one tracked, covered file carrying a tag the CLI exits 1 and names the line; with the tag gone the
// same tree exits 0. The red run is the control for the green one. Every git child runs under gitEnv(),
// so under the pre-commit hook (which exports GIT_DIR and GIT_INDEX_FILE) the temp repo stays a temp
// repo instead of becoming the hook's index.
test("the CLI exits 1 on a tracked covered tag and 0 once it is gone", () => {
  const root = scratch();
  const env = gitEnv();
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", root, ...args], { stdio: "pipe", env });
  git("init", "-q");
  mkdirSync(join(root, "docs"));
  const page = join(root, "docs", "guide.md");
  writeFileSync(page, "# Guide\n\nThe gate refuses (ADR-0032 decision 4).\n");
  git("add", "docs/guide.md");

  const red = spawnSync("bun", [script, root], { encoding: "utf8", env });
  expect({ status: red.status, stdout: red.stdout }).toEqual({ status: 1, stdout: "" });
  expect(red.stderr).toContain("docs/guide.md:3: design record number: The gate refuses");

  writeFileSync(page, "# Guide\n\nThe gate refuses until this connection's push verified.\n");
  git("add", "docs/guide.md");
  const green = spawnSync("bun", [script, root], { encoding: "utf8", env });
  expect({ status: green.status, stderr: green.stderr }).toEqual({ status: 0, stderr: "" });
  expect(green.stdout).toMatch(/^check-planning-refs: 1 file\(s\) clean/);
});
