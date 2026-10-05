import { afterEach, describe, expect, test } from "bun:test";
import { join } from "node:path";
import { lintArchitecture, readArchitecture } from "../arch-lint";
import { Scratch, writeTree } from "../lib";

const scratch = new Scratch();
afterEach(() => scratch.remove());

// A tree shaped like this repository's: the extension reaches the shared package only through an
// alias the bundler resolves, a stylesheet import sits beside the module imports, two scripts load
// modules through type-asserted `require` and `module.require` receivers, a dependency store and a
// generated dot-directory live under src/ with imports that resolve nowhere, and docs/ holds no
// source file.
function tree(declaration: string): string {
  const root = scratch.dir("arch-lint");
  writeTree(root, {
    "architecture.yml": declaration,
    "docs/readme.md": "# docs\n",
    "src/shared/util.ts": "export const u = 1;\n",
    "src/ext/style.css": "body {}\n",
    "src/ext/x.ts": [
      'import { z } from "zod";',
      'import { u } from "@shared/util";',
      'import "./style.css";',
      "export const x = u + Number(z);",
      "",
    ].join("\n"),
    "src/ext/node_modules/dep/index.ts": 'import "../../../../nowhere";\n',
    "src/ext/.wxt/types.ts": 'import "../../../nowhere-else";\n',
    "scripts/t.ts": [
      'const ext = (require as NodeRequire)("../src/ext/x");',
      "export const t = Number(ext);",
      "",
    ].join("\n"),
    "scripts/u.ts": [
      'const shared = (module as NodeModule).require("../src/shared/util");',
      "export const u = Number(shared);",
      "",
    ].join("\n"),
  });
  return root;
}

const LAYERS = [
  "layers:",
  "  shared: [src/shared/]",
  "  ext: [src/ext/]",
  "  scripts: [scripts/]",
].join("\n");
const ALIASES = 'aliases:\n  "@shared/": src/shared/\n';
const EDGES = "edges:\n  ext: [shared]\n  scripts: [ext, shared]\n";

const lint = (root: string) =>
  lintArchitecture(root, readArchitecture(join(root, "architecture.yml")));

// The lint fails in both directions, and three facts the source cannot state: the alias is what
// makes the shared edge visible (without `aliases` the same import is a bare specifier and the
// declared edge reads as stale), a type-asserted `require` or `module.require` is still a load, and
// a layer owning no source file is a problem rather than a vacuous match. Pruned directories are
// never parsed, or their unresolvable imports would throw.
describe("lintArchitecture", () => {
  const cases: ReadonlyArray<readonly [name: string, declaration: string, problems: string[]]> = [
    ["the declaration equal to the tree is clean", `${LAYERS}\n${ALIASES}${EDGES}`, []],
    [
      "undeclared imports and an allowance no file draws are all problems",
      `${LAYERS}\n${ALIASES}edges:\n  scripts: [ext]\n  shared: [ext]\n`,
      [
        "forbidden import ext -> shared: src/ext/x.ts -> src/shared/util.ts; move it or declare the edge",
        "forbidden import scripts -> shared: scripts/u.ts -> src/shared/util.ts; move it or declare the edge",
        "stale allowance shared -> ext: no file draws it; remove it from architecture.yml",
      ],
    ],
    [
      "without the alias the aliased import is a bare package name and the declared edge is stale",
      `${LAYERS}\n${EDGES}`,
      ["stale allowance ext -> shared: no file draws it; remove it from architecture.yml"],
    ],
    [
      "a layer whose paths hold no source file is a problem, not an empty match",
      `${LAYERS}\n  docs: [docs/]\n${ALIASES}${EDGES}`,
      ["layer docs owns no source file; fix its paths or remove it"],
    ],
  ];

  test.each(cases)("%s", (_name, declaration, problems) => {
    expect(lint(tree(declaration))).toEqual(problems);
  });
});
