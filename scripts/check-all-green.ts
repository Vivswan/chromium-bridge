#!/usr/bin/env bun

// all-green needs-completeness gate: branch protection requires exactly one
// check, all-green, whose `needs` list is hand-maintained. A job added to
// ci.yml but forgotten from that list is silently not required for merge -
// the merge gate fails open. This script parses the workflow and fails CI
// naming any job that is neither in all-green's needs nor explicitly exempted
// below, so the only way to add an unrequired job is a reviewed edit here.
//
// It verifies the hand-written YAML rather than generating it (the workflow
// stays hand-readable), and is dependency-free on purpose (Bun.YAML + node
// builtins) so the all-green job can run it without a bun install. It runs
// INSIDE all-green so the check itself cannot be dropped from the merge gate.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const GATE = "all-green";

// Jobs deliberately NOT required for merge. Every entry carries its reason;
// anything absent from this list must appear in all-green's needs.
export const EXEMPT: Record<string, string> = {
  [GATE]: "the aggregate gate itself - a job cannot need itself",
  coverage:
    "informational by design: no threshold, must never block a merge (see the job's comment in ci.yml)",
};

interface Workflow {
  jobs?: Record<string, { needs?: string | string[] }>;
}

/** Returns the list of completeness violations in the given workflow YAML
 * (empty = the merge gate covers every non-exempt job). `exempt` is
 * injectable for the unit tests; production always uses EXEMPT. */
export function findGateGaps(yamlText: string, exempt: Record<string, string> = EXEMPT): string[] {
  const jobs = (Bun.YAML.parse(yamlText) as Workflow | null)?.jobs;
  if (!jobs || typeof jobs !== "object") return ["workflow has no jobs map"];
  const gate = jobs[GATE];
  if (!gate) return [`workflow has no "${GATE}" job`];
  const needs = typeof gate.needs === "string" ? [gate.needs] : (gate.needs ?? []);

  const errors: string[] = [];
  for (const id of Object.keys(jobs)) {
    // Object.hasOwn, not `in`: a job named like an Object.prototype member
    // ("constructor", "toString") must not ride the prototype chain into an
    // exemption.
    if (Object.hasOwn(exempt, id)) {
      // Exempt AND required is a contradiction: one of the two is stale.
      if (needs.includes(id)) {
        errors.push(`job "${id}" is exempt (${exempt[id]}) but listed in ${GATE}.needs`);
      }
    } else if (!needs.includes(id)) {
      errors.push(
        `job "${id}" is missing from ${GATE}.needs: it is NOT required for merge. ` +
          `Add it to the needs list (or exempt it, with a reason, in scripts/check-all-green.ts).`,
      );
    }
  }
  // Stale entries point both ways: a need for a job that no longer exists
  // makes all-green permanently skipped (and every merge blocked), and an
  // exemption for a removed job is allowlist rot.
  for (const id of needs) {
    if (!Object.hasOwn(jobs, id)) {
      errors.push(`${GATE}.needs lists "${id}", which is not a job in ci.yml`);
    }
  }
  for (const [id, reason] of Object.entries(exempt)) {
    if (!Object.hasOwn(jobs, id))
      errors.push(`exempt list names "${id}", which is not a job in ci.yml`);
    if (reason.trim() === "") errors.push(`exempt entry "${id}" has no justification`);
  }
  return errors;
}

if (import.meta.main) {
  const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
  const workflow = resolve(root, ".github/workflows/ci.yml");
  const errors = findGateGaps(readFileSync(workflow, "utf8"));
  if (errors.length > 0) {
    for (const e of errors) console.error(`check-all-green: ${e}`);
    process.exit(1);
  }
  console.log(
    `check-all-green: every non-exempt ci.yml job is in ${GATE}.needs ` +
      `(exempt: ${Object.keys(EXEMPT).join(", ")})`,
  );
}
