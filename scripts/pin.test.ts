// What would drift silently: the one-owner rule across two files of different grammars, which neither
// proto nor Docker enforces for us. proto reads .prototools alone, Docker reads the Containerfile alone
// (and silently lets the last of two ARG lines win), so only this reader can refuse a tool pinned in both
// files, twice in one, or in an indented form the other parser accepts. The fixtures are hand-written
// shapes of those inputs.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readPin } from "./pin.ts";

const scratch = mkdtempSync(join(tmpdir(), "pin-test-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const prototools = [
  "# header comment",
  'proto = "0.58.2"',
  'bun = "1.4.2"',
  "",
  "[settings]",
  'builtin-plugins = ["bun"]',
];
const containerfile = [
  "FROM example.com/base@sha256:0000",
  "ARG TYPOS_VERSION=1.50.3",
  "ARG CARGO_MACHETE_VERSION=0.9.2",
];

interface Case {
  name: string;
  prototools?: string[];
  containerfile?: string[];
  tool: string;
  outcome: { pin: string } | { error: RegExp };
}

const cases: Case[] = [
  { name: "a .prototools key is the pin", tool: "proto", outcome: { pin: "0.58.2" } },
  {
    name: "a Containerfile ARG is the pin, tool name mapped to UPPER_SNAKE",
    tool: "cargo-machete",
    outcome: { pin: "0.9.2" },
  },
  {
    name: "an indented key and an indented ARG are pins, as TOML and Docker read them",
    prototools: ['  proto = "0.58.2"'],
    containerfile: ["  ARG CARGO_MACHETE_VERSION=0.9.2"],
    tool: "cargo-machete",
    outcome: { pin: "0.9.2" },
  },
  {
    name: "a tool-named key under a table is not a pin, even with the table header indented",
    prototools: [
      ...prototools.slice(0, 4),
      "  [settings]",
      "  [plugins]",
      'cargo-machete = "https://example.com/plugin.wasm"',
    ],
    tool: "cargo-machete",
    outcome: { pin: "0.9.2" },
  },
  {
    name: "a tool pinned in both files has two owners",
    containerfile: [...containerfile, "ARG BUN_VERSION=9.9.9"],
    tool: "bun",
    outcome: { error: /more than once.*1\.4\.2, 9\.9\.9/ },
  },
  {
    name: "a second ARG line, indented so Docker still reads it, is a duplicate",
    containerfile: [...containerfile, "  ARG CARGO_MACHETE_VERSION=0.9.1"],
    tool: "cargo-machete",
    outcome: { error: /more than once.*0\.9\.2, 0\.9\.1/ },
  },
  {
    name: "a second key line is a duplicate",
    prototools: ['proto = "0.58.2"', 'proto = "0.1.0"'],
    tool: "proto",
    outcome: { error: /more than once.*0\.58\.2, 0\.1\.0/ },
  },
  { name: "a tool pinned nowhere", tool: "node", outcome: { error: /pinned in neither/ } },
  {
    name: "a commented-out ARG is not a pin",
    containerfile: ["# ARG CARGO_MACHETE_VERSION=0.9.2"],
    tool: "cargo-machete",
    outcome: { error: /pinned in neither/ },
  },
  {
    name: "an unreadable owner file is refused, not read as empty",
    prototools: undefined,
    containerfile,
    tool: "cargo-machete",
    outcome: { error: /cannot read \.prototools/ },
  },
  {
    name: "a tool name that is not a tool name",
    tool: "../etc",
    outcome: { error: /not a tool name/ },
  },
];

describe("readPin: one owner per pin across .prototools and the Containerfile", () => {
  test.each(cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const root = mkdtempSync(join(scratch, "case-"));
    mkdirSync(root, { recursive: true });
    if (!("prototools" in c) || c.prototools !== undefined) {
      writeFileSync(join(root, ".prototools"), `${(c.prototools ?? prototools).join("\n")}\n`);
    }
    writeFileSync(
      join(root, "Containerfile"),
      `${(c.containerfile ?? containerfile).join("\n")}\n`,
    );
    if ("pin" in c.outcome) {
      expect(readPin(c.tool, root)).toBe(c.outcome.pin);
    } else {
      expect(() => readPin(c.tool, root)).toThrow(c.outcome.error);
    }
  });
});
