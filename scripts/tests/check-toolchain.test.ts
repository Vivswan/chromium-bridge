import { afterEach, describe, expect, test } from "bun:test";
import { toolchainMismatches } from "../check-toolchain";
import { Scratch, writeTree } from "../lib";

const scratch = new Scratch();
afterEach(() => scratch.remove());

// The bun pin lives in three files no tool cross-checks for us (.prototools, package.json's packageManager,
// the template-managed .bun-version), and proto's allow-list must leave python to uv and rust to rustup.
describe("toolchainMismatches", () => {
  const prototools = (pins: string, settings = '[settings]\nbuiltin-plugins = ["bun", "moon"]\n') =>
    `# the header comment\n${pins}\n${settings}`;
  const agreeing = {
    ".prototools": prototools('proto = "0.1.0"\nbun = "1.2.3"\n'),
    "package.json": '{ "name": "x", "packageManager": "bun@1.2.3" }\n',
    ".bun-version": "1.2.3\n",
  };
  const cases: ReadonlyArray<
    readonly [name: string, files: Partial<typeof agreeing>, mismatches: string[]]
  > = [
    ["every copy agrees", {}, []],
    [
      "package.json pins another bun",
      { "package.json": '{ "packageManager": "bun@1.2.4" }' },
      [".prototools bun (1.2.3) != package.json packageManager (1.2.4)"],
    ],
    [
      "packageManager is not a bun pin",
      { "package.json": '{ "packageManager": "pnpm@9.0.0" }' },
      ["package.json packageManager (pnpm@9.0.0) is not a bun pin"],
    ],
    [
      ".bun-version lags",
      { ".bun-version": "1.2.2\n" },
      [".prototools bun (1.2.3) != .bun-version (1.2.2)"],
    ],
    [
      ".prototools has no bun pin",
      { ".prototools": prototools('proto = "0.1.0"\n') },
      [
        ".prototools does not pin bun",
        ".prototools bun (<missing>) != package.json packageManager (1.2.3)",
        ".prototools bun (<missing>) != .bun-version (1.2.3)",
      ],
    ],
    [
      ".prototools pins rust",
      { ".prototools": prototools('proto = "0.1.0"\nbun = "1.2.3"\nrust = "1.80.0"\n') },
      [
        ".prototools pins rust - rust-toolchain.toml is its only pin (proto's install breaks rustup's)",
      ],
    ],
    [
      "the allow-list is missing",
      { ".prototools": prototools('proto = "0.1.0"\nbun = "1.2.3"\n', "") },
      [
        ".prototools settings.builtin-plugins allow-list is missing (proto would provision python and rust)",
      ],
    ],
    [
      "the allow-list names the tools other provisioners own",
      {
        ".prototools": prototools(
          'proto = "0.1.0"\nbun = "1.2.3"\n',
          '[settings]\nbuiltin-plugins = ["bun", "python", "rust"]\n',
        ),
      },
      [
        ".prototools builtin-plugins includes python - python is owned by uv (.python-version)",
        ".prototools builtin-plugins includes rust - rust is owned by rustup (rust-toolchain.toml)",
      ],
    ],
  ];

  test.each(cases)("%s", (_name, files, mismatches) => {
    const root = scratch.dir("toolchain");
    writeTree(root, { ...agreeing, ...files });
    expect(toolchainMismatches(root)).toEqual(mismatches);
  });
});
