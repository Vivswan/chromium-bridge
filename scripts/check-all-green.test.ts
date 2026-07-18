import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { findGateGaps, GATE } from "./check-all-green";

// A minimal exempt list for the synthetic workflows (the real EXEMPT default
// is exercised by the "real ci.yml" test below).
const exempt = { [GATE]: "the gate itself", skipped: "informational" };

function workflow(jobIds: string[], needs: string[]): string {
  const jobs = jobIds.map((id) => `  ${id}:\n    runs-on: ubuntu-latest\n    steps: []`).join("\n");
  const needsYaml = needs.map((n) => `      - ${n}`).join("\n");
  return `name: CI\non: [push]\njobs:\n${jobs}\n  ${GATE}:\n    needs:\n${needsYaml}\n    runs-on: ubuntu-latest\n    steps: []\n`;
}

describe("findGateGaps", () => {
  test("passes when every non-exempt job is in needs", () => {
    const yaml = workflow(["rust", "browser", "skipped"], ["rust", "browser"]);
    expect(findGateGaps(yaml, exempt)).toEqual([]);
  });

  test("names a job missing from needs", () => {
    const yaml = workflow(["rust", "browser", "skipped", "new-job"], ["rust", "browser"]);
    const errors = findGateGaps(yaml, exempt);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('"new-job"');
    expect(errors[0]).toContain("NOT required for merge");
  });

  test("flags a needs entry whose job no longer exists", () => {
    const errors = findGateGaps(workflow(["rust", "skipped"], ["rust", "removed-job"]), exempt);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('"removed-job"');
  });

  test("flags an exempt job that is also in needs (contradiction)", () => {
    const errors = findGateGaps(workflow(["rust", "skipped"], ["rust", "skipped"]), exempt);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('"skipped"');
    expect(errors[0]).toContain("exempt");
  });

  test("flags an exempt entry whose job no longer exists (allowlist rot)", () => {
    const errors = findGateGaps(workflow(["rust"], ["rust"]), exempt);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('"skipped"');
    expect(errors[0]).toContain("not a job");
  });

  test("accepts a scalar needs value", () => {
    const yaml = `jobs:\n  rust:\n    runs-on: ubuntu-latest\n  ${GATE}:\n    needs: rust\n    runs-on: ubuntu-latest\n`;
    expect(findGateGaps(yaml, { [GATE]: "the gate itself" })).toEqual([]);
  });

  test("fails when the gate job itself is missing", () => {
    const yaml = "jobs:\n  rust:\n    runs-on: ubuntu-latest\n";
    expect(findGateGaps(yaml, exempt)).toEqual([`workflow has no "${GATE}" job`]);
  });

  test("fails on a workflow without jobs", () => {
    expect(findGateGaps("name: CI\n", exempt)).toEqual(["workflow has no jobs map"]);
  });

  test("a job named like an Object.prototype member cannot ride the prototype chain", () => {
    for (const id of ["constructor", "toString", "hasOwnProperty"]) {
      const errors = findGateGaps(workflow(["rust", "skipped", id], ["rust"]), exempt);
      expect(errors).toHaveLength(1);
      expect(errors[0]).toContain(`"${id}"`);
    }
  });

  test("flags an exempt entry with a blank justification", () => {
    const errors = findGateGaps(workflow(["rust", "skipped"], ["rust"]), {
      ...exempt,
      skipped: "  ",
    });
    expect(errors).toEqual(['exempt entry "skipped" has no justification']);
  });

  // The production check: today's ci.yml, with the real EXEMPT default.
  test("the real ci.yml is complete", () => {
    const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
    const real = readFileSync(resolve(root, ".github/workflows/ci.yml"), "utf8");
    expect(findGateGaps(real)).toEqual([]);
  });
});
