#!/usr/bin/env bun
// The readiness checks the root moon.yml header's rules hang on, one mode per task; each judges offline, installs
// and fetches nothing, and names `moon run setup`:
//   bun scripts/check-deps.ts bun [checkout]     -> root:check-deps
//   bun scripts/check-deps.ts cargo [checkout]   -> root:check-crates
// Self-contained on node builtins and Bun globals (no lib.ts import): it runs before any install by contract.
//
//   a checkout under another checkout  -> node's walk would climb into the parent's node_modules; this one stops at the root
//   cargo                              -> its own read-only verdicts: `cargo --version` under RUSTUP_AUTO_INSTALL=0 (rustup
//                                         would otherwise download a missing pin) and `cargo fetch --locked --offline`

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const setupCommand = "moon run setup";
// Every re-lock finding carries this prefix, so report() can route drift to the re-lock before setup.
const relockWith = (command: string): string => `(re-lock with \`${command}\`)`;
const relock = relockWith("bun install");

// bun.lock writes member paths and workspace links with forward slashes on every platform.
const posix = (path: string): string => path.split(sep).join("/");

type PackageEntry = [
  resolution: string,
  registry?: string,
  manifest?: { dependencies?: Record<string, string> },
  integrity?: string,
];

const declarationKinds = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;
type Declarations = Partial<Record<(typeof declarationKinds)[number], Record<string, string>>>;

/** The bun text lockfile, the fields read here. Workspace keys are member paths relative to the root ("" is the root). */
interface Lockfile {
  workspaces: Record<string, { name: string } & Declarations>;
  overrides?: Record<string, string>;
  packages: Record<string, PackageEntry>;
}

type Manifest = {
  name?: unknown;
  version?: unknown;
  workspaces?: unknown;
  overrides?: Record<string, string>;
} & Declarations;

function readManifest(dir: string): Manifest | undefined {
  try {
    return JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  } catch {
    return undefined;
  }
}

// bun's frozen-lockfile rule: what a manifest declares is what the lockfile recorded, name and spec alike.
function disagreements(
  where: string,
  declared: Record<string, string>,
  recorded: Record<string, string>,
): string[] {
  return [...new Set([...Object.keys(declared), ...Object.keys(recorded)])]
    .sort()
    .filter((name) => declared[name] !== recorded[name])
    .map(
      (name) =>
        `${where}: ${name} is ${declared[name] ?? "absent"} in package.json, ${recorded[name] ?? "absent"} in bun.lock ${relock}`,
    );
}

function declaredMembers(root: string, manifest: Manifest): Record<string, string> {
  const patterns = Array.isArray(manifest.workspaces) ? manifest.workspaces : [];
  const members: Record<string, string> = {};
  for (const pattern of patterns) {
    if (typeof pattern !== "string") continue;
    for (const match of new Bun.Glob(pattern).scanSync({ cwd: root, onlyFiles: false })) {
      // A glob such as `./src/*` yields `./`-prefixed matches; the lockfile key has neither prefix nor backslash.
      if (existsSync(join(root, match, "package.json")))
        members[posix(normalize(match))] = "a member";
    }
  }
  return members;
}

// Walk up from the dependent like node's resolution, but stop at the repo root.
function locate(root: string, from: string, dep: string): string | undefined {
  for (let dir = from; ; dir = dirname(dir)) {
    const candidate = join(dir, "node_modules", dep);
    if (existsSync(candidate)) return candidate;
    if (dir === root || dirname(dir) === dir) return undefined;
  }
}

function outsideRoot(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel);
}

// bun keys a package by the hoisting path that leads to it: `<dependent names>/<name>`, shortened as far as
// hoisting allowed. The entry a dependent sees is the deepest key under its own path.
function locked(
  packages: Lockfile["packages"],
  path: string[],
  dep: string,
): { entry: PackageEntry; path: string[] } | undefined {
  for (let depth = path.length; depth >= 0; depth--) {
    const prefix = path.slice(0, depth);
    const entry = packages[[...prefix, dep].join("/")];
    if (entry !== undefined) return { entry, path: [...prefix, dep] };
  }
  return undefined;
}

type Judged = { ok: true; real: string; workspace: boolean } | { ok: false; finding: string };

/** `name@version` as bun.lock resolves it; a workspace member resolves to `name@workspace:<path>`. */
function judge(root: string, from: string, dep: string, resolution: string): Judged {
  // The separator is the first `@` past a scope's; a git resolution carries `@` in its URL.
  const at = resolution.indexOf("@", 1);
  const name = resolution.slice(0, at);
  const version = resolution.slice(at + 1);
  const found = locate(root, from, dep);
  if (found === undefined) return { ok: false, finding: `is missing (bun.lock: ${resolution})` };
  const real = realpathSync(found);
  if (outsideRoot(root, real)) {
    return { ok: false, finding: `resolves outside the repository (${real})` };
  }
  const manifest = readManifest(real);
  if (manifest === undefined) {
    return { ok: false, finding: `has no readable package.json (bun.lock: ${resolution})` };
  }
  if (manifest.name !== name) {
    return { ok: false, finding: `is ${String(manifest.name)} (bun.lock: ${resolution})` };
  }
  if (version.startsWith("workspace:")) {
    const linked = posix(relative(root, real));
    const expected = version.slice("workspace:".length);
    if (linked !== expected) {
      return { ok: false, finding: `links to ${linked} (bun.lock: ${resolution})` };
    }
    return { ok: true, real, workspace: true };
  }
  // Only a registry resolution carries a comparable version; a git or tarball one is judged by name alone.
  if (/^\d/.test(version) && manifest.version !== version) {
    return { ok: false, finding: `is ${String(manifest.version)} (bun.lock: ${resolution})` };
  }
  return { ok: true, real, workspace: false };
}

/**
 * Every way the tree under `checkout` differs from its bun.lock, as the developer reads it. The manifests must
 * declare what the lockfile recorded (members, dependencies, overrides), so a change made without re-locking
 * is caught here and not at import time. Optional and peer dependencies are bun's call at install time
 * (platform bindings are optional), so they are not followed.
 */
export function auditWorkspace(checkout: string): string[] {
  // The inside-the-repository test compares real paths, so the root is one too (macOS puts tmp under a symlink).
  const root = realpathSync(checkout);
  const lock = Bun.JSONC.parse(readFileSync(join(root, "bun.lock"), "utf8")) as Lockfile;
  if (!existsSync(join(root, "node_modules"))) return ["node_modules/ is absent"];
  const rootManifest = readManifest(root);
  if (rootManifest === undefined) return [".: has no readable package.json"];
  const recordedMembers = Object.fromEntries(
    Object.keys(lock.workspaces)
      .filter((path) => path !== "")
      .map((path) => [path, "a member"]),
  );
  const findings = [
    ...disagreements("workspaces", declaredMembers(root, rootManifest), recordedMembers),
    ...disagreements("overrides", rootManifest.overrides ?? {}, lock.overrides ?? {}),
  ];
  const walked = new Set<string>();

  type Dependent = { label: string; dir: string; path: string[]; chain: string[] };
  const walk = (dep: string, from: Dependent): void => {
    const chain = [...from.chain, dep];
    const where = `${from.label}: ${chain.join(" > ")}`;
    const hit = locked(lock.packages, from.path, dep);
    if (hit === undefined) {
      findings.push(`${where} has no bun.lock entry`);
      return;
    }
    // Every dependent's own link is judged (a member can keep a stale one); the package's dependencies are
    // walked once, and a workspace member's from the member itself.
    const verdict = judge(root, from.dir, dep, hit.entry[0]);
    if (!verdict.ok) {
      findings.push(`${where} ${verdict.finding}`);
      return;
    }
    const key = hit.path.join("/");
    if (verdict.workspace || walked.has(key)) return;
    walked.add(key);
    const required = Object.keys(hit.entry[2]?.dependencies ?? {}).sort();
    const next = { label: from.label, dir: verdict.real, path: hit.path, chain };
    for (const name of required) walk(name, next);
  };

  for (const [memberPath, member] of Object.entries(lock.workspaces)) {
    const label = memberPath === "" ? "." : memberPath;
    const dir = join(root, memberPath);
    if (outsideRoot(root, dir)) {
      findings.push(`${label}: workspace member lies outside the repository`);
      continue;
    }
    const manifest = readManifest(dir);
    if (manifest === undefined) {
      findings.push(`${label}: has no readable package.json`);
      continue;
    }
    if (manifest.name !== member.name) {
      findings.push(
        `${label}: name is ${String(manifest.name)} in package.json, ${member.name} in bun.lock ${relock}`,
      );
    }
    for (const kind of declarationKinds) {
      findings.push(...disagreements(label, manifest[kind] ?? {}, member[kind] ?? {}));
    }
    const walkable = Object.keys({ ...member.dependencies, ...member.devDependencies }).sort();
    for (const dep of walkable) walk(dep, { label, dir, path: [member.name], chain: [] });
  }
  return findings;
}

function cargoManifests(root: string): string[] {
  const toml = Bun.TOML.parse(readFileSync(join(root, "Cargo.toml"), "utf8")) as {
    workspace?: { exclude?: unknown };
  };
  const excluded = Array.isArray(toml.workspace?.exclude) ? toml.workspace.exclude : [];
  const nested = excluded
    .filter((dir): dir is string => typeof dir === "string")
    .filter((dir) => existsSync(join(root, dir, "Cargo.toml")))
    .map((dir) => join(dir, "Cargo.toml"));
  return ["Cargo.toml", ...nested];
}

/**
 * Every way the checkout falls short of its pinned toolchain and lockfiles, by cargo's own offline verdicts:
 * the toolchain must already be installed, then every cargo workspace's crates must already be fetched.
 */
export function auditCrates(
  checkout: string,
  env: Record<string, string | undefined> = process.env,
): string[] {
  const root = realpathSync(checkout);
  let active = "";
  const cargo = (...args: string[]): string | undefined => {
    let run: ReturnType<typeof Bun.spawnSync>;
    try {
      run = Bun.spawnSync(["cargo", ...args], {
        cwd: root,
        env: { ...env, RUSTUP_AUTO_INSTALL: "0" },
        stdout: "pipe",
        stderr: "pipe",
      });
    } catch {
      return "cargo is not on PATH (rustup installs it: https://rustup.rs)";
    }
    if (run.success) {
      active = (run.stdout?.toString() ?? "").trim();
      return undefined;
    }
    const lines = (run.stderr?.toString() ?? "").trim().split("\n");
    return lines.find((line) => line.startsWith("error")) ?? lines[0] ?? `exit ${run.exitCode}`;
  };
  const toolchain = cargo("--version");
  if (toolchain !== undefined) return [`rust toolchain: ${toolchain}`];
  // An inherited RUSTUP_TOOLCHAIN overrides rust-toolchain.toml, so the active cargo is held to the pin when
  // the pin is a version (a channel name such as `stable` cannot be compared).
  const pin = (
    Bun.TOML.parse(readFileSync(join(root, "rust-toolchain.toml"), "utf8")) as {
      toolchain?: { channel?: unknown };
    }
  ).toolchain?.channel;
  if (typeof pin === "string" && /^\d/.test(pin) && !active.includes(` ${pin} `)) {
    return [`rust toolchain: ${active} is active, rust-toolchain.toml pins ${pin}`];
  }
  return cargoManifests(root).flatMap((manifest) => {
    const failure = cargo("fetch", "--locked", "--offline", "--manifest-path", manifest);
    if (failure === undefined) return [];
    // cargo's --locked refusal for a manifest edited without re-locking, which setup (also --locked) cannot fix;
    // the wording varies by version, the flag's name in it does not.
    if (failure.includes("--locked was passed")) {
      return [
        `${manifest}: its Cargo.lock is behind it ${relockWith(`cargo fetch --manifest-path ${manifest}`)}`,
      ];
    }
    return [`${manifest}: crates are not fetched to its Cargo.lock (${failure})`];
  });
}

export function report(findings: string[]): string {
  // setup runs with frozen lockfiles, so manifest drift is sent to the re-lock first.
  const remedy = findings.some((finding) => finding.includes("(re-lock with "))
    ? `a lockfile is behind its manifest: re-lock as its line says, then run \`${setupCommand}\` once`
    : `run \`${setupCommand}\` once`;
  return [
    `error: the checkout is missing what \`${setupCommand}\` installs:`,
    ...findings.map((finding) => `  ${finding}`),
    `${remedy}; this check installs and fetches nothing`,
  ].join("\n");
}

const audits = { bun: auditWorkspace, cargo: auditCrates };

if (import.meta.main) {
  const [mode, checkout, ...extra] = process.argv.slice(2);
  const audit =
    mode !== undefined && extra.length === 0 && Object.hasOwn(audits, mode)
      ? audits[mode as keyof typeof audits]
      : undefined;
  if (audit === undefined) {
    console.error("usage: bun scripts/check-deps.ts bun | cargo [checkout]");
    process.exit(2);
  }
  const findings = audit(checkout === undefined ? repoRoot : resolve(checkout));
  if (findings.length > 0) {
    console.error(report(findings));
    process.exit(1);
  }
}
