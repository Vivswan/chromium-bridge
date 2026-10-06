import { afterAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { NATIVE_HOST_ID } from "../../src/packages/shared/src/identity.gen.ts";
import { repoRoot, Scratch, writeTree } from "../lib.ts";
import {
  allowedOrigin,
  type Browser,
  browserConfigDirs,
  chromeRegistered,
  freshMachine,
  Machine,
  manifestFile,
  multiBrowser,
  type RunBinary,
} from "../linux-registration.ts";

// What would drift silently: the checks are all that stands between a binary that writes nothing and a
// green job, and only this file runs them against a binary known to be wrong. Each check kind is pinned
// on a negative and a positive case, and both scenarios run against a binary that accepts every command
// and writes nothing, which must fail at a named step.

const scratch = new Scratch();
afterAll(() => scratch.remove());

const accepting: RunBinary = () => ({ exitCode: 0, stdout: "", stderr: "" });
const refusing: RunBinary = () => ({ exitCode: 1, stdout: "", stderr: "refused\n" });
const listing: RunBinary = () => ({
  exitCode: 0,
  stdout: "  chrome    detected      user    manifest ok         pointer n/a        /x\n",
  stderr: "",
});

function machine(binary: RunBinary): Machine {
  return new Machine(scratch.dir("linux-registration-machine"), binary, () => {});
}

function file(path: string, text: string, mode = 0o644): string {
  writeTree(dirname(path), { [basename(path)]: text });
  chmodSync(path, mode);
  return path;
}

interface Case {
  name: string;
  binary: RunBinary;
  check: (m: Machine) => void;
  outcome: "passes" | RegExp;
}

const manifestRel = `config/google-chrome/NativeMessagingHosts/${manifestFile}`;
const cases: Case[] = [
  {
    name: "ok: a refusal names the command, the status, and the binary's stderr",
    binary: refusing,
    check: (m) => m.ok("doctor", "--list"),
    outcome: /^chromium-bridge doctor --list exited 1, expected 0:\nrefused\n$/,
  },
  { name: "ok: exit 0 passes", binary: accepting, check: (m) => m.ok("--help"), outcome: "passes" },
  {
    name: "exits: the wrong code fails, with the code seen",
    binary: refusing,
    check: (m) => m.exits(3, /detected/, "doctor", "--fix"),
    outcome:
      /^chromium-bridge doctor --fix exited 1, expected 3 with stderr matching \/detected\/:\nrefused\n$/,
  },
  {
    name: "exits: the right code with the wrong line fails",
    binary: () => ({ exitCode: 3, stdout: "", stderr: "something else\n" }),
    check: (m) => m.exits(3, /detected/, "doctor", "--fix"),
    outcome: /expected 3 with stderr matching/,
  },
  {
    name: "exits: the right code and line pass",
    binary: () => ({ exitCode: 3, stdout: "", stderr: "no browser detected\n" }),
    check: (m) => m.exits(3, /detected/, "doctor", "--fix"),
    outcome: "passes",
  },
  {
    name: "refused: exit 0 is the vacuous pass and fails the step",
    binary: accepting,
    check: (m) => m.refused("doctor", "--fix"),
    outcome: /^chromium-bridge doctor --fix exited 0, expected a refusal$/,
  },
  {
    name: "refused: a nonzero exit passes",
    binary: refusing,
    check: (m) => m.refused("doctor", "--fix"),
    outcome: "passes",
  },
  {
    name: "outputMatches: silence from a command that exited 0 fails with the pattern named",
    binary: accepting,
    check: (m) => m.outputMatches(/stale/, "doctor", "--list"),
    outcome: /^chromium-bridge doctor --list printed nothing matching \/stale\/:\n$/,
  },
  {
    name: "outputMatches: the row shape doctor --list prints passes",
    binary: listing,
    check: (m) => m.outputMatches(chromeRegistered, "doctor", "--list"),
    outcome: "passes",
  },
  {
    name: "file: a missing manifest is named relative to the machine root",
    binary: accepting,
    check: (m) => m.file(m.manifest("chrome")),
    outcome: new RegExp(`^expected ${manifestRel} to be a regular file$`),
  },
  {
    name: "file: a directory at the manifest path is not a manifest (test -f, not test -e)",
    binary: accepting,
    check: (m) => {
      mkdirSync(m.manifest("chrome"), { recursive: true });
      m.file(m.manifest("chrome"));
    },
    outcome: new RegExp(`^expected ${manifestRel} to be a regular file$`),
  },
  {
    name: "file: a regular file passes",
    binary: accepting,
    check: (m) => m.file(file(m.manifest("chrome"), "{}")),
    outcome: "passes",
  },
  {
    name: "absent: a file still present fails",
    binary: accepting,
    check: (m) => m.absent(file(m.manifest("chrome"), "{}")),
    outcome: new RegExp(`^expected ${manifestRel} to be gone$`),
  },
  {
    name: "absent: nothing at the path passes",
    binary: accepting,
    check: (m) => m.absent(m.manifest("chrome")),
    outcome: "passes",
  },
  {
    name: "executable: a plain file fails even though it exists",
    binary: accepting,
    check: (m) => m.executable(file(m.wrapper("chrome"), "exec host", 0o644)),
    outcome: /^expected data\/chromium-bridge\/run-host-chrome\.sh to be executable$/,
  },
  {
    name: "executable: mode bits set passes",
    binary: accepting,
    check: (m) => m.executable(file(m.wrapper("chrome"), "exec host", 0o755)),
    outcome: "passes",
  },
  {
    name: "contains: the first missing needle is quoted with the file's text",
    binary: accepting,
    check: (m) => m.contains(file(m.manifest("chrome"), '{"name":"x"}'), '"name"', '"origin"'),
    outcome: new RegExp(
      `^expected ${manifestRel} to contain "\\\\"origin\\\\"":\\n\\{"name":"x"\\}$`,
    ),
  },
  {
    name: "contains: every needle present passes",
    binary: accepting,
    check: (m) => m.contains(file(m.manifest("chrome"), '{"name":"x"}'), '"name"', "x"),
    outcome: "passes",
  },
  {
    name: "fileIs: a byte changed in a foreign manifest fails",
    binary: accepting,
    check: (m) => m.fileIs(file(join(m.root, "foreign", manifestFile), "{}\n"), "{} \n"),
    outcome: new RegExp(
      `^expected foreign/${manifestFile} to be byte-identical to what was written:\\n\\{\\}\\n$`,
    ),
  },
  {
    name: "fileIs: identical bytes pass",
    binary: accepting,
    check: (m) => m.fileIs(file(join(m.root, "foreign", manifestFile), "{}\n"), "{}\n"),
    outcome: "passes",
  },
];

describe("each check kind fires on its negative case and passes on its positive one", () => {
  test.each(cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const m = machine(c.binary);
    if (c.outcome === "passes") {
      expect(() => c.check(m)).not.toThrow();
    } else {
      expect(() => c.check(m)).toThrow(c.outcome);
    }
  });
});

test("the binary runs against the machine's roots alone, with the rest of the environment inherited", () => {
  let seen: Record<string, string> | undefined;
  const m = machine((_args, env) => {
    seen = env;
    return { exitCode: 0, stdout: "", stderr: "" };
  });
  m.ok("--help");
  expect(seen).toMatchObject({
    HOME: m.home,
    XDG_CONFIG_HOME: m.config,
    XDG_DATA_HOME: m.data,
    PATH: process.env.PATH as string,
  });
});

test("a binary that accepts every command and writes nothing fails both scenarios at the first check of its effect", () => {
  expect(() => freshMachine(machine(accepting))).toThrow(
    /^chromium-bridge doctor --fix exited 0, expected 3 with stderr matching/,
  );
  expect(() => multiBrowser(machine(accepting))).toThrow(
    new RegExp(`^expected ${manifestRel} to be a regular file$`),
  );
});

// The checks after a refusal are reachable only through a binary that passes everything before them.
// `tamper` makes its uninstall rewrite a foreign manifest instead of leaving it.
function conforming(tamper = false): RunBinary {
  const ours = JSON.stringify({ name: NATIVE_HOST_ID, allowed_origins: [allowedOrigin] });
  return (args, env) => {
    const config = env.XDG_CONFIG_HOME as string;
    const data = env.XDG_DATA_HOME as string;
    const ok = (stdout = "") => ({ exitCode: 0, stdout, stderr: "" });
    const refused = (stderr: string) => ({ exitCode: 1, stdout: "", stderr });
    const rows = Object.entries(browserConfigDirs) as [Browser, string][];
    const manifestDirOf = (dir: string) => join(config, dir, "NativeMessagingHosts");
    const wrapperOf = (browser: Browser) => join(data, "chromium-bridge", `run-host-${browser}.sh`);
    const detected = rows.filter(([, dir]) => existsSync(join(config, dir)));
    const flag = (name: string) => {
      const at = args.indexOf(name);
      return at === -1 ? undefined : args[at + 1];
    };
    const foreign = (dir: string) => {
      const path = join(dir, manifestFile);
      if (!existsSync(path)) return false;
      return (JSON.parse(readFileSync(path, "utf8")) as { name?: string }).name !== NATIVE_HOST_ID;
    };
    const register = (dir: string, browser?: Browser) => {
      writeTree(dir, { [manifestFile]: `${ours}\n` });
      if (browser) {
        writeTree(dirname(wrapperOf(browser)), {
          [basename(wrapperOf(browser))]: `exec host --native-host --label '${browser}'\n`,
        });
        chmodSync(wrapperOf(browser), 0o755);
      }
    };
    const [command, verb] = args;
    if (command === "--help") return ok("usage\n");
    if (command === "doctor" && verb === "--list") {
      const list = detected.map(
        ([browser]) =>
          `  ${browser}  detected  user  manifest ${existsSync(wrapperOf(browser)) ? "ok" : "stale"}  pointer n/a  /x`,
      );
      return ok(`${list.join("\n")}\n`);
    }
    if (command === "doctor" && verb === "--fix") {
      const manifestDir = flag("--manifest-dir");
      if (manifestDir !== undefined) {
        // An explicit --fix overwrites a foreign manifest at our id.
        register(manifestDir);
        return ok();
      }
      const selection = flag("--browser")?.split(",");
      const targets = args.includes("--all")
        ? rows
        : selection
          ? rows.filter(([browser]) => selection.includes(browser))
          : detected;
      if (targets.length === 0) {
        return { exitCode: 3, stdout: "", stderr: "no Chromium-family browser detected\n" };
      }
      for (const [browser, dir] of targets) register(manifestDirOf(dir), browser);
      return ok();
    }
    if (command === "uninstall") {
      for (const manifestDir of args.flatMap((a, i) =>
        a === "--manifest-dir" ? [args[i + 1] as string] : [],
      )) {
        if (foreign(manifestDir)) {
          // A foreign manifest is left in place, as a warning: exit 0.
          if (tamper) {
            writeFileSync(
              join(manifestDir, manifestFile),
              '{"name":"com.other.host","description":"rewritten"}\n',
            );
          }
          continue;
        }
        rmSync(join(manifestDir, manifestFile), { force: true });
      }
      for (const [browser, dir] of rows) {
        rmSync(join(manifestDirOf(dir), manifestFile), { force: true });
        rmSync(wrapperOf(browser), { force: true });
      }
      return ok();
    }
    return refused(`unknown command ${args.join(" ")}\n`);
  };
}

describe("the scenarios against a conforming binary", () => {
  test("both scenarios pass end to end", () => {
    expect(() => freshMachine(machine(conforming()))).not.toThrow();
    expect(() => multiBrowser(machine(conforming()))).not.toThrow();
  });

  test("an uninstall that rewrites the foreign manifest fails at the byte-identical check", () => {
    expect(() => freshMachine(machine(conforming(true)))).toThrow(
      new RegExp(`^expected foreign/NativeMessagingHosts/${manifestFile} to be byte-identical`),
    );
  });
});

// The postinst's acceptance rule is shell, so it is checked as shell: the real script with the binary
// path pointed at a stub that exits as told. 0 and 3 (nothing to register) configure the package; 1 (a
// failed registration) and 2 (clap's usage error) must not.
describe("packaging/deb/postinst accepts exactly exit 0 and 3 from doctor --fix --system", () => {
  const postinst = readFileSync(join(repoRoot, "packaging/deb/postinst"), "utf8");
  test.each([
    [0, 0],
    [3, 0],
    [1, 1],
    [2, 1],
  ])("the binary exits %i, the postinst exits %i", (binaryExit, expected) => {
    const stub = join(scratch.dir("postinst-stub"), "chromium-bridge");
    writeFileSync(stub, `#!/bin/sh\nexit ${binaryExit}\n`);
    chmodSync(stub, 0o755);
    const run = Bun.spawnSync(["sh", "-c", postinst.replaceAll("/usr/bin/chromium-bridge", stub)]);
    expect(run.exitCode === 0 ? 0 : 1).toBe(expected);
  });
});
