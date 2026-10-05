import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Scratch, writeTree } from "../lib";
import { spliceMap } from "../render-architecture-map";

const script = join(dirname(fileURLToPath(import.meta.url)), "..", "render-architecture-map.ts");
const scratch = new Scratch();
afterEach(() => scratch.remove());

const PAGE = [
  "# Page",
  "",
  "A quoted pair, which is page text:",
  "",
  "```markdown",
  "<!-- BEGIN GENERATED: architecture-map -->",
  "<!-- END GENERATED: architecture-map -->",
  "```",
  "",
  "<!-- BEGIN GENERATED: architecture-map (a hint) -->",
  "stale body",
  "<!-- END GENERATED: architecture-map -->",
  "",
].join("\n");

// The splice lands between the live markers only (a quoted pair inside a fence is page text), and a
// second render of the same map changes nothing, which is what lets --check compare bytes.
test("spliceMap replaces the live region, leaves the quoted markers, and is idempotent", () => {
  const once = spliceMap(PAGE, "architecture-map", "graph TD\n  a --> b");
  expect(once).toBe(
    [
      "# Page",
      "",
      "A quoted pair, which is page text:",
      "",
      "```markdown",
      "<!-- BEGIN GENERATED: architecture-map -->",
      "<!-- END GENERATED: architecture-map -->",
      "```",
      "",
      "<!-- BEGIN GENERATED: architecture-map (a hint) -->",
      "```mermaid",
      "graph TD",
      "  a --> b",
      "```",
      "<!-- END GENERATED: architecture-map -->",
      "",
    ].join("\n"),
  );
  expect(spliceMap(once, "architecture-map", "graph TD\n  a --> b")).toBe(once);
  expect(() => spliceMap("# No region\n", "architecture-map", "graph TD")).toThrow(
    'region "architecture-map" needs exactly one BEGIN and one END marker, found 0 and 0',
  );
});

// The shell contract the check-architecture task relies on: --check exits 1 while the committed
// region differs from the declaration and 0 once a render wrote it, without ever writing itself.
test("the CLI's --check fails on drift, a render writes the map, and --check then passes", () => {
  const root = scratch.dir("render-map");
  writeTree(root, {
    "architecture.yml": "layers:\n  a: [src/a/]\n  b: [src/b/]\nedges:\n  a: [b]\n",
    "docs/page.md": PAGE,
  });
  const run = (...args: string[]) =>
    spawnSync("bun", [script, "--root", root, "--page", "docs/page.md", ...args], {
      encoding: "utf8",
      cwd: root,
    });

  const drift = run("--check");
  expect({ status: drift.status, stdout: drift.stdout, stderr: drift.stderr }).toEqual({
    status: 1,
    stdout: "",
    stderr:
      "render-architecture-map: docs/page.md region architecture-map differs from architecture.yml;" +
      " run `moon run gen-architecture-map` to rewrite it\n",
  });
  expect(readFileSync(join(root, "docs/page.md"), "utf8")).toBe(PAGE);

  const wrote = run();
  expect({ status: wrote.status, stdout: wrote.stdout, stderr: wrote.stderr }).toEqual({
    status: 0,
    stdout: "render-architecture-map: wrote docs/page.md region architecture-map\n",
    stderr: "",
  });
  expect(readFileSync(join(root, "docs/page.md"), "utf8")).toBe(
    spliceMap(PAGE, "architecture-map", 'graph TD\n  a["src/a/"]\n  b["src/b/"]\n  a --> b'),
  );

  const current = run("--check");
  expect({ status: current.status, stdout: current.stdout, stderr: current.stderr }).toEqual({
    status: 0,
    stdout: "render-architecture-map: docs/page.md region architecture-map is current\n",
    stderr: "",
  });
});
