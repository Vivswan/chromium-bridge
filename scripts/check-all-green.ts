#!/usr/bin/env bun

// all-green needs-completeness gate: branch protection requires exactly one
// check, all-green, whose `needs` list is hand-maintained. A job added to
// ci.yml but forgotten from that list is silently not required for merge -
// the merge gate fails open. This script parses the workflow and fails CI
// naming any job that is neither in all-green's needs nor explicitly exempted
// below, so the only way to add an unrequired job is a reviewed edit here.
// It also enforces the other direction: jobs listed in DOWNSTREAM (release)
// must keep `needs: [all-green]`, so nothing that publishes can quietly
// detach from the gate.
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
  release:
    "downstream of the gate (needs: [all-green]), so it cannot also be required by it; DOWNSTREAM below keeps it attached",
};

// Jobs that must run strictly AFTER the gate: each listed job must exist and
// its `needs` must contain the gate. Exemption alone would let a future edit
// silently drop `needs: [all-green]` from the release job and resurrect the
// deploy-from-red-main incident this structure exists to prevent.
export const DOWNSTREAM: Record<string, string> = {
  release: "releases, release-PR refreshes, and site deploys must only ever happen on a green main",
};

interface Workflow {
  jobs?: Record<string, { needs?: string | string[] }>;
}

/** Returns the list of completeness violations in the given workflow YAML
 * (empty = the merge gate covers every non-exempt job and every downstream
 * job hangs off the gate). `exempt` and `downstream` are injectable for the
 * unit tests; production always uses EXEMPT and DOWNSTREAM. */
export function findGateGaps(
  yamlText: string,
  exempt: Record<string, string> = EXEMPT,
  downstream: Record<string, string> = DOWNSTREAM,
): string[] {
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
  // Downstream enforcement: a job that must follow the gate has to actually
  // exist and actually need it, or the constraint is fiction.
  for (const [id, reason] of Object.entries(downstream)) {
    if (reason.trim() === "") errors.push(`downstream entry "${id}" has no justification`);
    // Object.hasOwn for the same prototype-chain reason as above.
    const job = Object.hasOwn(jobs, id) ? jobs[id] : undefined;
    if (!job) {
      errors.push(`downstream list names "${id}", which is not a job in ci.yml`);
      continue;
    }
    const jobNeeds = typeof job.needs === "string" ? [job.needs] : (job.needs ?? []);
    if (!jobNeeds.includes(GATE)) {
      errors.push(
        `job "${id}" must run downstream of ${GATE} (${reason}), ` +
          `but its needs [${jobNeeds.join(", ")}] does not include ${GATE}`,
      );
    }
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
      `(exempt: ${Object.keys(EXEMPT).join(", ")}; ` +
      `downstream of the gate: ${Object.keys(DOWNSTREAM).join(", ")})`,
  );
}
