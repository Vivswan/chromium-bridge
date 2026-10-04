// Shared helpers for the chromium-bridge TypeScript tooling scripts.
//
// scripts/build-repro.ts and scripts/fuzz-smoke.ts deliberately do NOT import this file: they stay
// self-contained on node builtins so they run before `bun install` (the release workflow builds the binary
// first, and the nightly fuzz job never installs the workspace).

import {
  appendFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Repo root, derived from this file's location (scripts/ is a direct child).
export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

// The JSON manifests that carry a copy of the crate version (Cargo.toml is the source of truth). The
// release PR bumps each one through release-please-config.json's extra-files; scripts/check-version.ts
// requires that coverage and verifies the copies agree. Add new version copies here, nowhere else.
export const versionedJsonFiles = ["src/apps/extension/package.json"] as const;

// Print an error to stderr and exit.
export function die(message: string, exitCode = 1): never {
  console.error(`error: ${message}`);
  process.exit(exitCode);
}

// The crate version from the workspace Cargo.toml: `[workspace.package] version`.
export function cargoVersion(): string {
  const toml = Bun.TOML.parse(readFileSync(join(repoRoot, "Cargo.toml"), "utf8")) as {
    workspace?: { package?: { version?: unknown } };
  };
  const version = toml.workspace?.package?.version;
  if (typeof version !== "string") die("no version found under [workspace.package] in Cargo.toml");
  return version;
}

// The "version" string from a JSON file. ("manifest_version" is a distinct
// key; JSON.parse reads the real field, not a textual match.)
export function jsonVersion(path: string): string {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as { version?: unknown };
  if (typeof parsed.version !== "string") die(`no "version" string in ${path}`);
  return parsed.version;
}

// The environment for a git spawned in a scratch repository by a test: `base` minus every GIT_* variable. A
// pre-commit hook exports GIT_DIR and GIT_INDEX_FILE, so an inheriting child acts on the repository under
// commit: a scratch `git init` re-initialised the shared .git (core.bare flipped to true) and a scratch
// `git add` rewrote the worktree index. The real gates keep the inherited env on purpose: a partial commit
// (`git commit --only`) is judged on the hook's temporary index, not the ordinary one.
/** The environment a child git is spawned with: process.env, or a test's scrubbed copy. */
export type Env = Record<string, string | undefined>;

export function gitEnv(base: Env = process.env): Record<string, string> {
  return Object.fromEntries(
    Object.entries(base).filter(
      (entry): entry is [string, string] => !entry[0].startsWith("GIT_") && entry[1] !== undefined,
    ),
  );
}

// A step output is one `name=value` line appended to the file GITHUB_OUTPUT names, and GitHub keeps the
// LAST line for a repeated name: a value with a line break would be read as a second record, so it is
// refused here rather than written as a different value.
export function githubOutput(name: string, value: string, env: Env = process.env): void {
  const file = env.GITHUB_OUTPUT;
  if (!file) throw new Error("GITHUB_OUTPUT is not set (not running as a GitHub Actions step)");
  if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(name)) throw new Error(`not a step output name: ${name}`);
  if (/[\r\n]/.test(value)) {
    throw new Error(`step output ${name} would span lines: ${JSON.stringify(value)}`);
  }
  appendFileSync(file, `${name}=${value}\n`);
}

/** A value the calling step must set in `env:`; an absent one is a miswired step, never a default. */
export function requiredEnv(name: string, env: Env = process.env): string {
  return env[name] ?? die(`${name} is not set`);
}

export function selectMode<T>(modes: Record<string, T>, argv: string[], script: string): T {
  const [mode, ...extra] = argv;
  // Object.hasOwn: `toString` is not a mode.
  const selected =
    mode === undefined || extra.length > 0 || !Object.hasOwn(modes, mode) ? undefined : modes[mode];
  if (selected === undefined) {
    console.error(`usage: bun ${script} ${Object.keys(modes).join(" | ")}`);
    process.exit(2);
  }
  return selected;
}

export function runGit(cwd: string, env: Env, ...args: string[]): string {
  const run = Bun.spawnSync(["git", ...args], { cwd, env, stdout: "pipe", stderr: "pipe" });
  if (run.exitCode !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${run.stderr.toString().trim()}`);
  }
  return run.stdout.toString();
}

export function writeTree(root: string, files: Record<string, string>): void {
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
}

/** The creator removes every scratch directory it minted, in the test file's afterEach or afterAll. */
export class Scratch {
  private readonly dirs: string[] = [];

  dir(tag: string): string {
    const dir = mkdtempSync(join(tmpdir(), `${tag}-`));
    this.dirs.push(dir);
    return dir;
  }

  remove(): void {
    for (const dir of this.dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  }
}

/** A finished command: its exit status and both streams. */
export interface Finished {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type Presence = "present" | "absent";

/**
 * Whether a directory entry exists, by lstat, so a dangling symlink counts as present. Only ENOENT is
 * absence: a path that could not be looked at throws, so a check never reads a failed look as "gone".
 */
export function presenceOf(path: string): Presence {
  try {
    lstatSync(path);
    return "present";
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "absent";
    throw new Error(`could not check ${path}: ${(error as Error).message}`);
  }
}

/**
 * The command checks the scenario drivers share (linux-registration.ts, installer-smoke.ts), so every driver
 * fails a step the same way: the command as the reader would type it, what was expected, and what it printed.
 * A command that exits 0 is the vacuous pass `refused` exists to catch; silence from one that exits 0 is the
 * one `outputMatches` catches.
 */
export class CommandChecks {
  constructor(
    private readonly spawn: (argv: string[]) => Finished,
    protected readonly log: (line: string) => void,
    /** How a command reads in logs and failures; the Linux driver prefixes the binary's name. */
    private readonly describe: (argv: string[]) => string = (argv) => argv.join(" "),
    private readonly presence: (path: string) => Presence = presenceOf,
  ) {}

  run(...argv: string[]): Finished {
    this.log(`$ ${this.describe(argv)}`);
    const finished = this.spawn(argv);
    for (const text of [finished.stdout, finished.stderr]) if (text) this.log(text.trimEnd());
    return finished;
  }

  ok(...argv: string[]): string {
    const finished = this.run(...argv);
    if (finished.exitCode !== 0) {
      throw this.failed(argv, `exited ${finished.exitCode}, expected 0:\n${finished.stderr}`);
    }
    return finished.stdout;
  }

  refused(...argv: string[]): void {
    if (this.run(...argv).exitCode === 0) throw this.failed(argv, "exited 0, expected a refusal");
  }

  outputMatches(pattern: RegExp, ...argv: string[]): void {
    const stdout = this.ok(...argv);
    if (!pattern.test(stdout)) {
      throw this.failed(argv, `printed nothing matching ${pattern}:\n${stdout}`);
    }
  }

  absent(path: string): void {
    if (this.presence(path) === "present") {
      throw new Error(`expected ${this.shown(path)} to be gone`);
    }
  }

  /** How a path reads in a failure; a driver with a root shows paths relative to it. */
  protected shown(path: string): string {
    return path;
  }

  protected failed(argv: string[], what: string): Error {
    return new Error(`${this.describe(argv)} ${what}`);
  }
}
