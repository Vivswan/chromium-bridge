// @vitest-environment node
//
// Biome's GritQL matches Biome's own CST node names, and Biome renames or reshapes nodes between versions; a renamed
// node compiles into a pattern that matches nothing, so the module-scope-let rule would go green with every bare `let`
// still in place. The plugin runs here against a hand-written fixture holding the two shapes it must flag beside every
// nesting it must not.

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

const PLUGIN = fileURLToPath(new URL("../../lint/module-scope-let.grit", import.meta.url));

// Line 1 and line 2 are the module-scope forms; every later line nests its `let` in a construct the rule excludes.
const FIXTURE = [
  "let flagged = 1;",
  "export let alsoFlagged = 2;",
  "const kept = 3;",
  "function inFunction() { let a = 1; return a + flagged + kept; }",
  "const inArrow = () => { let b = 0; b += 1; return b; };",
  "if (kept) { let inBlock = 1; console.log(inBlock); }",
  "switch (kept) { case 3: let inCase = 1; console.log(inCase); break; default: let inDefault = 2; console.log(inDefault); }",
  "class WithStatic { static { let inStatic = 1; console.log(inStatic); } method() { let inMethod = 2; return inMethod; } }",
  "for (let i = 0; i < 1; i += 1) console.log(i, inFunction, inArrow, WithStatic, alsoFlagged);",
  "namespace Inner { let inNamespace = 1; export const out = inNamespace; }",
].join("\n");

interface Diagnostic {
  message: string;
  location: { start: { line: number } };
}

test("the plugin flags exactly the module-scope lets of the fixture, with the inLife message", () => {
  const dir = mkdtempSync(join(tmpdir(), "module-scope-let-"));
  try {
    writeFileSync(join(dir, "fixture.ts"), FIXTURE);
    writeFileSync(
      join(dir, "biome.json"),
      JSON.stringify({
        linter: { enabled: true, rules: { recommended: false } },
        formatter: { enabled: false },
        plugins: [PLUGIN],
      }),
    );
    const run = spawnSync(
      "bun",
      ["run", "biome", "lint", `--config-path=${dir}`, "--reporter=json", join(dir, "fixture.ts")],
      { encoding: "utf8" },
    );
    expect(run.error, "biome did not start").toBeUndefined();
    const report = JSON.parse(run.stdout) as { diagnostics: Diagnostic[] };
    expect(
      report.diagnostics.map((d) => ({ line: d.location.start.line, message: d.message })),
    ).toEqual([
      { line: 1, message: expect.stringContaining("inLife") },
      { line: 2, message: expect.stringContaining("inLife") },
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
