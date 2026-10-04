import { describe, expect, test } from "bun:test";
import { isolationProblems } from "../check-gen-isolation.ts";

// `cargo tree` prints a crate as ` name vX.Y.Z` after its tree prefix, and `--prefix depth` glues the
// depth to the name, so depth 10 starts with "10": format facts of cargo's output that the gate's matches
// rest on and nothing else checks. The trees are hand-written in that format.

const clean = [
  "chromium-bridge v0.0.0 (/repo/src/apps/host)",
  "├── chromium-bridge-core v0.0.0 (/repo/src/packages/core)",
  "│   ├── rmcp v0.8.0",
  "│   │   └── schemars v1.0.4",
  "│   └── serde v1.0.219",
  "└── tokio v1.47.1",
].join("\n");

const viaRmcp = [
  "0schemars v1.0.4",
  "1rmcp v0.8.0",
  "2chromium-bridge-core v0.0.0 (/repo/src/packages/core)",
  "3chromium-bridge v0.0.0 (/repo/src/apps/host)",
].join("\n");

describe("isolationProblems", () => {
  test("schemars through rmcp alone is clean, and the inverse tree is asked for", () => {
    let asked = 0;
    expect(
      isolationProblems(clean, () => {
        asked += 1;
        return viaRmcp;
      }),
    ).toEqual([]);
    expect(asked).toBe(1);
  });

  test("a graph without schemars never asks for the inverse tree", () => {
    const tree = clean.replace("│   │   └── schemars v1.0.4\n", "");
    expect(
      isolationProblems(tree, () => {
        throw new Error("asked");
      }),
    ).toEqual([]);
  });

  test("every refused crate in the graph is named, wherever it sits", () => {
    const tree = `${clean}\n    ├── p256 v0.13.2\n└── ts-rs v10.1.0`;
    expect(isolationProblems(tree, () => viaRmcp)).toEqual([
      "p256 leaked into the chromium-bridge binary dependency graph",
      "ts-rs leaked into the chromium-bridge binary dependency graph",
    ]);
  });

  test("a crate whose name merely ends in a refused name is not a leak", () => {
    expect(isolationProblems(`${clean}\n└── ecdsa-p256 v0.1.0`, () => viaRmcp)).toEqual([]);
  });

  // The inverse tree's rows: depth digit glued to the name, so depth 10 starts with "10".
  const deep = `${viaRmcp}\n${Array.from({ length: 7 }, (_, i) => `${i + 4}crate${i} v0.1.0`).join("\n")}\n10leaf v0.1.0`;
  const outsideRmcp = `${viaRmcp}\n1chromium-bridge-core v0.0.0 (/repo/src/packages/core)`;
  test.each<[string, string, string[]]>([
    ["a depth-10 row is not a depth-1 row", deep, []],
    [
      "a direct dependent of schemars other than rmcp fails with the tree shown",
      outsideRmcp,
      ["schemars reached the chromium-bridge binary graph outside rmcp:", outsideRmcp],
    ],
    [
      "an empty inverse tree did not resolve and fails instead of passing",
      "",
      ["could not resolve the schemars inverse tree:", ""],
    ],
    [
      "an inverse tree rooted at another crate did not resolve either",
      "0serde v1.0.219\n1rmcp v0.8.0",
      ["could not resolve the schemars inverse tree:", "0serde v1.0.219\n1rmcp v0.8.0"],
    ],
  ])("%s", (_name, inverse, problems) => {
    expect(isolationProblems(clean, () => inverse)).toEqual(problems);
  });
});
