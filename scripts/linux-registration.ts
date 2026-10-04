#!/usr/bin/env bun

// checks.yml's linux-install job: the release binary registers and unregisters itself against isolated
// HOME/XDG roots on a bare runner, so what it writes is checked where a browser would read it, never on a
// developer's machine. Each scenario is a sequence of commands and the files they must leave. A failed
// check names its step, and a command expected to refuse fails its step when it exits 0.
//
//   bun scripts/linux-registration.ts fresh-machine   -> detect, repair, refuse a foreign manifest; uninstall reverses it
//   bun scripts/linux-registration.ts multi-browser   -> --browser a,b and --all register exactly those rows; uninstall clears all

import {
  accessSync,
  constants,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { NATIVE_HOST_ID, PINNED_EXTENSION_ID } from "../src/packages/shared/src/identity.gen.ts";
import { die, repoRoot, selectMode } from "./lib.ts";

export interface Finished {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/** The binary under test behind one call, so a test can stand a fake in for it. */
export type RunBinary = (args: string[], env: Record<string, string>) => Finished;

/** Where each browser reads native-messaging manifests on Linux, under XDG_CONFIG_HOME. */
export const browserConfigDirs = {
  chrome: "google-chrome",
  chromium: "chromium",
  brave: "BraveSoftware/Brave-Browser",
  edge: "microsoft-edge",
  vivaldi: "vivaldi",
  opera: "opera",
} as const;
export type Browser = keyof typeof browserConfigDirs;
const browsers = Object.keys(browserConfigDirs) as Browser[];

export const manifestFile = `${NATIVE_HOST_ID}.json`;
export const allowedOrigin = `chrome-extension://${PINNED_EXTENSION_ID}/`;

/** An isolated machine: the binary sees these roots through HOME and the XDG variables, nothing else. */
export class Machine {
  readonly home: string;
  readonly config: string;
  readonly data: string;

  constructor(
    readonly root: string,
    private readonly binary: RunBinary,
    private readonly log: (line: string) => void = console.log,
  ) {
    this.home = join(root, "home");
    this.config = join(root, "config");
    this.data = join(root, "data");
    mkdirSync(this.home, { recursive: true });
  }

  manifest(browser: Browser): string {
    return join(this.config, browserConfigDirs[browser], "NativeMessagingHosts", manifestFile);
  }

  wrapper(browser: Browser): string {
    return join(this.data, "chromium-bridge", `run-host-${browser}.sh`);
  }

  /** The binary detects an installed browser by its config directory. */
  install(browser: Browser): void {
    mkdirSync(join(this.config, browserConfigDirs[browser]), { recursive: true });
  }

  run(...args: string[]): Finished {
    this.log(`$ chromium-bridge ${args.join(" ")}`);
    const inherited = Object.entries(process.env).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    );
    const finished = this.binary(args, {
      ...Object.fromEntries(inherited),
      HOME: this.home,
      XDG_CONFIG_HOME: this.config,
      XDG_DATA_HOME: this.data,
    });
    for (const text of [finished.stdout, finished.stderr]) if (text) this.log(text.trimEnd());
    return finished;
  }

  ok(...args: string[]): string {
    const finished = this.run(...args);
    if (finished.exitCode !== 0) {
      throw this.failed(args, `exited ${finished.exitCode}, expected 0:\n${finished.stderr}`);
    }
    return finished.stdout;
  }

  refused(...args: string[]): void {
    if (this.run(...args).exitCode === 0) throw this.failed(args, "exited 0, expected a refusal");
  }

  outputMatches(pattern: RegExp, ...args: string[]): void {
    const stdout = this.ok(...args);
    if (!pattern.test(stdout)) {
      throw this.failed(args, `printed nothing matching ${pattern}:\n${stdout}`);
    }
  }

  /** A regular file, as `test -f` judges it: a directory at a manifest path is not a manifest. */
  file(path: string): void {
    let regular = false;
    try {
      regular = statSync(path).isFile();
    } catch {
      regular = false;
    }
    if (!regular) throw new Error(`expected ${this.rel(path)} to be a regular file`);
  }

  absent(path: string): void {
    if (existsSync(path)) throw new Error(`expected ${this.rel(path)} to be gone`);
  }

  executable(path: string): void {
    try {
      accessSync(path, constants.X_OK);
    } catch {
      throw new Error(`expected ${this.rel(path)} to be executable`);
    }
  }

  contains(path: string, ...needles: string[]): void {
    this.file(path);
    const text = readFileSync(path, "utf8");
    for (const needle of needles) {
      if (!text.includes(needle)) {
        throw new Error(
          `expected ${this.rel(path)} to contain ${JSON.stringify(needle)}:\n${text}`,
        );
      }
    }
  }

  fileIs(path: string, expected: string): void {
    this.file(path);
    const text = readFileSync(path, "utf8");
    if (text !== expected) {
      throw new Error(
        `expected ${this.rel(path)} to be byte-identical to what was written:\n${text}`,
      );
    }
  }

  private failed(args: string[], what: string): Error {
    return new Error(`chromium-bridge ${args.join(" ")} ${what}`);
  }

  private rel(path: string): string {
    return relative(this.root, path);
  }
}

export function freshMachine(m: Machine): void {
  m.ok("--help");
  // No browser detected: --fix refuses rather than guess a browser.
  m.refused("doctor", "--fix");
  m.install("chrome");
  m.ok("doctor", "--list");
  m.ok("doctor", "--fix");
  const manifest = m.manifest("chrome");
  m.contains(manifest, allowedOrigin, `"${NATIVE_HOST_ID}"`);
  const wrapper = m.wrapper("chrome");
  m.executable(wrapper);
  m.contains(wrapper, "--native-host", "--label 'chrome'");
  m.outputMatches(/chrome\s+detected\s+ok/, "doctor", "--list");
  rmSync(wrapper);
  m.outputMatches(/stale/, "doctor", "--list");
  m.ok("doctor", "--fix");
  m.executable(wrapper);
  m.ok("doctor", "--fix", "--browser", "brave");
  m.file(m.manifest("brave"));
  // --manifest-dir is the escape hatch for a browser the table does not name.
  const custom = join(m.root, "custom/NativeMessagingHosts");
  m.ok("doctor", "--fix", "--manifest-dir", custom);
  m.file(join(custom, manifestFile));
  const foreignDir = join(m.root, "foreign/NativeMessagingHosts");
  const foreign = join(foreignDir, manifestFile);
  const foreignBytes = '{"name":"com.other.host","description":"not ours"}\n';
  mkdirSync(foreignDir, { recursive: true });
  writeFileSync(foreign, foreignBytes);
  m.refused("doctor", "--fix", "--manifest-dir", foreignDir);
  m.refused("uninstall", "--manifest-dir", foreignDir);
  m.fileIs(foreign, foreignBytes);
  // uninstall clears every row it wrote, the refused foreign file notwithstanding.
  m.ok("uninstall", "--manifest-dir", custom);
  for (const path of [
    manifest,
    join(custom, manifestFile),
    wrapper,
    m.manifest("brave"),
    m.wrapper("brave"),
  ]) {
    m.absent(path);
  }
}

export function multiBrowser(m: Machine): void {
  const selected: Browser[] = ["chrome", "chromium", "brave", "edge"];
  m.ok("doctor", "--fix", "--browser", selected.join(","));
  for (const browser of browsers) {
    if (selected.includes(browser)) m.contains(m.manifest(browser), allowedOrigin);
    else m.absent(m.manifest(browser));
  }
  m.ok("doctor", "--fix", "--all");
  for (const browser of browsers) m.file(m.manifest(browser));
  m.ok("uninstall");
  for (const browser of browsers) {
    m.absent(m.manifest(browser));
    m.absent(m.wrapper(browser));
  }
}

export const scenarios: Record<string, (m: Machine) => void> = {
  "fresh-machine": freshMachine,
  "multi-browser": multiBrowser,
};

if (import.meta.main) {
  const scenario = selectMode(scenarios, process.argv.slice(2), "scripts/linux-registration.ts");
  const name = process.argv[2] as string;
  const bin = join(repoRoot, "target/release/chromium-bridge");
  const binary: RunBinary = (args, env) => {
    const run = Bun.spawnSync([bin, ...args], { env, stdout: "pipe", stderr: "pipe" });
    return { exitCode: run.exitCode, stdout: run.stdout.toString(), stderr: run.stderr.toString() };
  };
  const root = mkdtempSync(join(tmpdir(), "linux-registration-"));
  let failure: string | undefined;
  try {
    scenario(new Machine(root, binary));
  } catch (error) {
    failure = (error as Error).message;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  if (failure !== undefined) die(`${name}: ${failure}`);
  console.log(`${name}: every check passed`);
}
