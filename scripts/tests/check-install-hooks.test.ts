import { afterEach, describe, expect, test } from "bun:test";
import { installHooks } from "../check-install-hooks";
import { Scratch, writeTree } from "../lib.ts";

// Drift answer: bun runs these scripts at install time, which no other gate observes, and a hook that reads a
// build output (the extension's former postinstall `wxt prepare` over a generated module) broke every fresh
// checkout in CI while the local trees, already built, stayed green.

const scratch = new Scratch();
afterEach(() => scratch.remove());

const manifest = (fields: Record<string, unknown>) => `${JSON.stringify(fields, null, 2)}\n`;

function workspace(packages: Record<string, Record<string, unknown>>): string {
  const root = scratch.dir("check-install-hooks");
  writeTree(root, {
    "package.json": manifest({ name: "root", workspaces: ["packages/*", "tools"] }),
    ...Object.fromEntries(
      Object.entries(packages).map(([dir, fields]) => [`${dir}/package.json`, manifest(fields)]),
    ),
  });
  return root;
}

describe("installHooks", () => {
  test("a postinstall in a workspace package is reported by file and script name", () => {
    const root = workspace({
      "packages/ext": { name: "ext", scripts: { build: "wxt build", postinstall: "wxt prepare" } },
      "packages/lib": { name: "lib", scripts: { test: "bun test" } },
    });
    expect(installHooks(root)).toEqual([
      { file: "packages/ext/package.json", script: "postinstall" },
    ]);
  });

  test("every install-time name counts, in the root manifest too; postbuild and prepublishOnly do not", () => {
    const root = scratch.dir("check-install-hooks");
    writeTree(root, {
      "package.json": manifest({
        name: "root",
        workspaces: ["tools"],
        scripts: { prepare: "husky", postbuild: "echo", prepublishOnly: "echo" },
      }),
      "tools/package.json": manifest({
        name: "tools",
        scripts: { preinstall: "echo", install: "echo" },
      }),
    });
    expect(installHooks(root)).toEqual([
      { file: "package.json", script: "prepare" },
      { file: "tools/package.json", script: "preinstall" },
      { file: "tools/package.json", script: "install" },
    ]);
  });

  test("a workspace without install-time scripts is clean", () => {
    const root = workspace({
      "packages/ext": { name: "ext", scripts: { build: "wxt build", test: "vitest run" } },
      "tools": { name: "tools" },
    });
    expect(installHooks(root)).toEqual([]);
  });
});
