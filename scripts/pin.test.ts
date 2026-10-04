// What would drift silently: the one-owner rule across two files of different grammars, which neither
// proto nor Docker enforces for us. proto reads .prototools alone, Docker reads the Containerfile alone
// and silently lets the last of two ARG lines win, so only this reader can refuse a tool pinned in both
// files, twice in the Containerfile, or in an indented form the other parser accepts. The fixtures are
// hand-written shapes of those inputs.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
  // undefined: the file is absent.
  prototools?: string[] | undefined;
  containerfile?: string[] | undefined;
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
    name: "an indented key is a pin, as TOML reads it",
    prototools: ['  proto = "0.58.2"'],
    tool: "proto",
    outcome: { pin: "0.58.2" },
  },
  {
    name: "an indented ARG is a pin, as Docker reads it",
    containerfile: ["  ARG CARGO_MACHETE_VERSION=0.9.2"],
    tool: "cargo-machete",
    outcome: { pin: "0.9.2" },
  },
  {
    name: "a tool-named key directly under [settings] is not a pin",
    prototools: ['proto = "0.58.2"', "[settings]", 'bun = "9.9.9"'],
    tool: "bun",
    outcome: { error: /pinned in neither/ },
  },
  {
    name: "a tool-named key under an indented [settings] header is not a pin either",
    prototools: ['proto = "0.58.2"', "  [settings]", 'bun = "9.9.9"'],
    tool: "bun",
    outcome: { error: /pinned in neither/ },
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
    name: "a second key line is refused by the TOML parser",
    prototools: ['proto = "0.58.2"', 'proto = "0.1.0"'],
    tool: "proto",
    outcome: { error: /not valid TOML.*redefine key 'proto'/ },
  },
  {
    name: "a second key line, indented, is refused by the TOML parser",
    prototools: ['proto = "0.58.2"', '  proto = "0.1.0"'],
    tool: "proto",
    outcome: { error: /not valid TOML.*redefine key 'proto'/ },
  },
  {
    name: "a key pinned to a non-string is refused",
    prototools: ["proto = 1"],
    tool: "proto",
    outcome: { error: /empty or non-string/ },
  },
  {
    name: "a key pinned to an empty string is refused, not printed as an empty pin",
    prototools: ['proto = ""'],
    tool: "proto",
    outcome: { error: /empty or non-string/ },
  },
  { name: "a tool pinned nowhere", tool: "node", outcome: { error: /pinned in neither/ } },
  {
    name: "a commented-out key is not a pin",
    prototools: ['# proto = "9.9.9"'],
    tool: "proto",
    outcome: { error: /pinned in neither/ },
  },
  {
    name: "a commented-out ARG is not a pin",
    containerfile: ["# ARG CARGO_MACHETE_VERSION=0.9.2"],
    tool: "cargo-machete",
    outcome: { error: /pinned in neither/ },
  },
  {
    name: "an absent .prototools is refused, not read as empty",
    prototools: undefined,
    tool: "cargo-machete",
    outcome: { error: /cannot read \.prototools/ },
  },
  {
    name: "an absent Containerfile is refused, not read as empty",
    containerfile: undefined,
    tool: "proto",
    outcome: { error: /cannot read Containerfile/ },
  },
  {
    name: "an underscore spelling is not a tool name: the ARG mapping collapses - and _, so it would alias the dashed tool's pin",
    tool: "cargo_machete",
    outcome: { error: /not a tool name/ },
  },
];

function write(root: string, file: string, lines: string[] | undefined): void {
  if (lines) writeFileSync(join(root, file), `${lines.join("\n")}\n`);
}

describe("readPin: one owner per pin across .prototools and the Containerfile", () => {
  test.each(cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const root = mkdtempSync(join(scratch, "case-"));
    write(root, ".prototools", "prototools" in c ? c.prototools : prototools);
    write(root, "Containerfile", "containerfile" in c ? c.containerfile : containerfile);
    if ("pin" in c.outcome) {
      expect(readPin(c.tool, root)).toBe(c.outcome.pin);
    } else {
      expect(() => readPin(c.tool, root)).toThrow(c.outcome.error);
    }
  });
});

// The exit status is the contract the bootstrap steps consume (`bun scripts/pin.ts <tool> | sed ... >>
// "$GITHUB_OUTPUT"` under pipefail): a refusal that printed its message but exited 0 would write an empty
// pin and stay green.
describe("the CLI's exit status", () => {
  const cli = (...args: string[]) =>
    Bun.spawnSync(["bun", join(import.meta.dir, "pin.ts"), ...args], {
      cwd: join(import.meta.dir, ".."),
      stdout: "pipe",
      stderr: "pipe",
    });

  test.each([
    ["a pinned tool prints one line and exits 0", ["proto"], 0, /^\S+\n$/, /^$/],
    ["a refused pin exits 1 with the reason on stderr", ["nope"], 1, /^$/, /pinned in neither/],
    ["no tool argument is a usage error, exit 2", [], 2, /^$/, /usage:/],
    ["two tool arguments are a usage error, exit 2", ["proto", "bun"], 2, /^$/, /usage:/],
  ])("%s", (_name, args, status, stdout, stderr) => {
    const run = cli(...args);
    expect({
      status: run.exitCode,
      stdout: run.stdout.toString(),
      stderr: run.stderr.toString(),
    }).toEqual({
      status,
      stdout: expect.stringMatching(stdout),
      stderr: expect.stringMatching(stderr),
    });
  });
});
