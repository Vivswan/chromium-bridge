#!/usr/bin/env bun

// Gen-only tooling must stay out of the shipped binary's graph, and only `cargo tree -e normal` sees that
// graph: the core's self dev-dependency switches the envelope-schema feature on workspace-wide, so
// cargo-deny (even with dev-dependencies excluded) sees a core -> schemars edge that never links.
//
//   ts-rs     -> refused anywhere in the graph
//   schemars  -> allowed only through rmcp (its runtime tool-schema model)
//
// p256 is not gen-only: the WebAuthn assertion verifier ships it (src/packages/core/src/webauthn), with
// the decision in docs/security/rationale.md.

import { die, repoRoot } from "./lib.ts";

export const refusedCrates = ["ts-rs"] as const;
const binary = "chromium-bridge";

/** A crate's row in `cargo tree` is `<prefix> name vX.Y.Z`, one space before the name. */
const inTree = (tree: string, crate: string) => tree.includes(` ${crate} v`);

export function leakedCrates(tree: string): string[] {
  return refusedCrates.filter((crate) => inTree(tree, crate));
}

/**
 * The inverse tree of schemars with `--prefix depth` (the depth digit glued to the name). It must start
 * at depth 0 with schemars itself, or it did not resolve, and rmcp must be its only depth-1 row. A
 * depth-10 row starts with "10", so depth 1 is "1" followed by a non-digit.
 */
export function schemarsProblems(inverse: string): string[] {
  const rows = inverse.split("\n");
  if (!rows.some((row) => /^0schemars /.test(row))) {
    return ["could not resolve the schemars inverse tree:", inverse];
  }
  if (rows.some((row) => /^1[^0-9]/.test(row) && !/^1rmcp /.test(row))) {
    return [`schemars reached the ${binary} binary graph outside rmcp:`, inverse];
  }
  return [];
}

export function isolationProblems(tree: string, inverse: () => string): string[] {
  const problems = leakedCrates(tree).map(
    (crate) => `${crate} leaked into the ${binary} binary dependency graph`,
  );
  if (inTree(tree, "schemars")) problems.push(...schemarsProblems(inverse()));
  return problems;
}

if (import.meta.main) {
  const cargoTree = (...args: string[]): string => {
    const argv = ["cargo", "tree", "-e", "normal", "-p", binary, "--locked", ...args];
    const run = Bun.spawnSync(argv, { cwd: repoRoot, stdout: "pipe", stderr: "pipe" });
    if (run.exitCode !== 0) die(`${argv.join(" ")} failed:\n${run.stderr.toString()}`);
    return run.stdout.toString();
  };
  const problems = isolationProblems(cargoTree(), () =>
    cargoTree("-i", "schemars", "--prefix", "depth"),
  );
  if (problems.length > 0) {
    for (const line of problems) console.error(line);
    process.exit(1);
  }
  console.log(`check-gen-isolation: gen-only tooling stays out of the ${binary} binary graph`);
}
