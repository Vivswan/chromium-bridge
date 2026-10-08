// The one-owner rule spans two files of different grammars, and neither proto nor Docker enforces it: proto
// reads .prototools alone, Docker reads the Containerfile alone and lets the last of two ARG lines win.

import { afterAll, describe, expect, test } from "bun:test";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { Scratch, writeTree } from "../lib.ts";
import { readAllPins, readPin } from "../pin.ts";
import { stepOutputs } from "./step-outputs.ts";

const scratch = new Scratch();
afterAll(() => scratch.remove());

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
  "ARG DEBIAN_SNAPSHOT=20260101T000000Z",
  "ARG TYPOS_VERSION=1.50.3",
  "ARG CARGO_MACHETE_VERSION=0.9.2",
  "ARG PROTO_VERSION",
];

function fixture(files: {
  prototools?: string[] | undefined;
  containerfile?: string[] | undefined;
}) {
  const root = scratch.dir("pin-test");
  const lines = {
    ".prototools": "prototools" in files ? files.prototools : prototools,
    Containerfile: "containerfile" in files ? files.containerfile : containerfile,
  };
  writeTree(
    root,
    Object.fromEntries(
      Object.entries(lines)
        .filter(([, content]) => content)
        .map(([file, content]) => [file, `${(content as string[]).join("\n")}\n`]),
    ),
  );
  return root;
}

interface Case {
  name: string;
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
    name: "a lowercase arg instruction is still an ARG to Docker, so still a second owner",
    containerfile: [...containerfile, "arg BUN_VERSION=9.9.9"],
    tool: "bun",
    outcome: { error: /more than once.*1\.4\.2, 9\.9\.9/ },
  },
  {
    name: "a second pair on one ARG line is still an ARG to Docker, so still a second owner",
    containerfile: [...containerfile, "ARG DEBIAN_SNAPSHOT=20260101T000000Z BUN_VERSION=9.9.9"],
    tool: "bun",
    outcome: { error: /more than once.*1\.4\.2, 9\.9\.9/ },
  },
  {
    name: "a pair after a valueless argument on one ARG line is still an ARG to Docker, so still a second owner",
    containerfile: [...containerfile, "ARG AUX BUN_VERSION=9.9.9"],
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
    name: "a second ARG line with an empty value is refused, where Docker would let the empty one win",
    containerfile: [...containerfile, "ARG CARGO_MACHETE_VERSION="],
    tool: "cargo-machete",
    outcome: { error: /Containerfile pins cargo-machete to an empty value/ },
  },
  {
    name: "a quoted ARG value is the pin without its quotes, as Docker reads it",
    containerfile: ['ARG CARGO_MACHETE_VERSION="0.9.2"'],
    tool: "cargo-machete",
    outcome: { pin: "0.9.2" },
  },
  {
    name: "a quoted ARG value with whitespace is refused, like a multi-line TOML string",
    containerfile: ['ARG CARGO_MACHETE_VERSION="0.9 .2"'],
    tool: "cargo-machete",
    outcome: { error: /Containerfile pins cargo-machete to a value with whitespace/ },
  },
  {
    name: "an escaped space is part of an ARG value to Docker, so a pin carrying one is refused the same way",
    containerfile: ["ARG CARGO_MACHETE_VERSION=0.9.2\\  AUX"],
    tool: "cargo-machete",
    outcome: { error: /Containerfile pins cargo-machete to a value with whitespace/ },
  },
  {
    name: "a second key line is refused by the TOML parser",
    prototools: ['proto = "0.58.2"', 'proto = "0.1.0"'],
    tool: "proto",
    outcome: { error: /not valid TOML/ },
  },
  {
    name: "a second key line, indented, is refused by the TOML parser",
    prototools: ['proto = "0.58.2"', '  proto = "0.1.0"'],
    tool: "proto",
    outcome: { error: /not valid TOML/ },
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
  {
    name: "a multi-line string is refused: a value with whitespace is two tokens where a build arg or a tool spec takes one",
    prototools: ['proto = """0.58.2', '9.9.9"""'],
    tool: "proto",
    outcome: { error: /whitespace/ },
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

describe("readPin: one owner per pin across .prototools and the Containerfile", () => {
  test.each(cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const root = fixture(c);
    if ("pin" in c.outcome) {
      expect(readPin(c.tool, root)).toBe(c.outcome.pin);
    } else {
      expect(() => readPin(c.tool, root)).toThrow(c.outcome.error);
    }
  });
});

// A second owner added for a tool no CI step asks for by name (every reader stays green on its own tool)
// is caught only by sweeping every pin of both files.
describe("readAllPins: every pin of both files through the one-owner rule", () => {
  test("the sweep lists each tool once, from whichever file owns it, and skips tables and valueless ARGs", () => {
    expect([...readAllPins(fixture({}))]).toEqual([
      ["bun", "1.4.2"],
      ["cargo-machete", "0.9.2"],
      ["proto", "0.58.2"],
      ["typos", "1.50.3"],
    ]);
  });

  test("a second owner for a tool nobody reads by name is refused", () => {
    const root = fixture({ containerfile: [...containerfile, "ARG BUN_VERSION=9.9.9"] });
    expect(() => readAllPins(root)).toThrow(/bun is pinned more than once.*1\.4\.2, 9\.9\.9/);
  });
});

// The exit status and the step-output record are the contract the bootstrap steps consume (`bun
// scripts/pin.ts <tool> --output <name>`): a refusal that printed its message but exited 0, or that still
// wrote a record, would hand the step an empty pin and stay green.
describe("the CLI's exit status", () => {
  const cli = (args: string[], env: Record<string, string> = {}) =>
    Bun.spawnSync(["bun", join(import.meta.dir, "..", "pin.ts"), ...args], {
      cwd: join(import.meta.dir, "../.."),
      env: { ...process.env, ...env },
      stdout: "pipe",
      stderr: "pipe",
    });

  test.each([
    ["a pinned tool prints one line and exits 0", ["proto"], 0, /^\S+\n$/, /^$/],
    [
      "--all prints one `tool version` line per pin and exits 0",
      ["--all"],
      0,
      /^(\S+ \S+\n)+$/,
      /^$/,
    ],
    ["a refused pin exits 1 with the reason on stderr", ["nope"], 1, /^$/, /pinned in neither/],
    ["no tool argument is a usage error, exit 2", [], 2, /^$/, /usage:/],
    ["two tool arguments are a usage error, exit 2", ["proto", "bun"], 2, /^$/, /usage:/],
    ["--output without a name is a usage error, exit 2", ["proto", "--output"], 2, /^$/, /usage:/],
    ["--all takes no --output, exit 2", ["--all", "--output", "x"], 2, /^$/, /usage:/],
  ])("%s", (_name, args, status, stdout, stderr) => {
    const run = cli(args);
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

  test("--output <name> writes the pin as the step output record for a pinned tool and no record for a refused one", () => {
    const file = join(scratch.dir("pin-test-output"), "output");
    writeFileSync(file, "");
    const env = { GITHUB_OUTPUT: file };
    const pinned = cli(["proto", "--output", "proto"], env);
    const refused = cli(["nope", "--output", "nope"], env);
    expect({
      pinned: pinned.exitCode,
      refused: refused.exitCode,
      records: stepOutputs(file),
    }).toEqual({
      pinned: 0,
      refused: 1,
      records: { proto: pinned.stdout.toString().trim() },
    });
  });
});
