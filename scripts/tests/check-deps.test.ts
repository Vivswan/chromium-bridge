import { afterAll, expect, test } from "bun:test";
import { chmodSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { auditCrates, auditWorkspace } from "../check-deps.ts";
import { Scratch, writeTree } from "../lib.ts";

// Drift answer: bun's install state is not visible to moon's task graph, and bun's own read-only commands read only
// the lockfile, so this check alone fails a bun task on a tree that is missing or stale against bun.lock; on the
// cargo side, rustup downloads a missing pinned toolchain and cargo fetches missing crates unless told not to, so
// the check must hand cargo exactly the flags and environment that refuse. The trees are hand-authored in the
// shape bun 1.4 writes: a `.bun/<name>@<version>` store behind symlinks.

const scratch = new Scratch();
afterAll(() => scratch.remove());

const lockfile = `{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "fixture-root",
      "devDependencies": {
        "alpha": "1.0.0",
        "beta": "^1.0.0",
      },
    },
    "pkg": {
      "name": "fixture-pkg",
      "version": "0.0.0",
      "dependencies": {
        "@fixture/shared": "workspace:*",
        "alpha": "2.0.0",
        "beta": "^1.0.0",
      },
    },
    "shared": {
      "name": "@fixture/shared",
      "version": "0.0.0",
    },
  },
  "overrides": {
    "gamma": "^1.0.0",
  },
  "packages": {
    "@fixture/shared": ["@fixture/shared@workspace:shared"],

    "alpha": ["alpha@1.0.0", "", {}, "sha512-fixture-alpha-1"],

    "fixture-pkg/alpha": ["alpha@2.0.0", "", {}, "sha512-fixture-alpha-2"],

    "beta": ["beta@1.2.3", "", { "dependencies": { "gamma": "^1.0.0" }, "optionalDependencies": { "beta-linux-x64": "1.2.3" } }, "sha512-fixture-beta"],

    "beta-linux-x64": ["beta-linux-x64@1.2.3", "", { "os": "linux", "cpu": "x64" }, "sha512-fixture-beta-linux"],

    "gamma": ["gamma@1.0.0", "", {}, "sha512-fixture-gamma"],
  }
}
`;

const manifest = (name: string, version: string, declarations: Record<string, unknown> = {}) =>
  JSON.stringify({ name, version, ...declarations });
const rootManifest = (extra: Record<string, unknown> = {}) =>
  manifest("fixture-root", "0.0.0", {
    workspaces: ["pkg", "sha*"],
    devDependencies: { alpha: "1.0.0", beta: "^1.0.0" },
    overrides: { gamma: "^1.0.0" },
    ...extra,
  });
const pkgManifest = (
  dependencies: Record<string, string> = {
    "@fixture/shared": "workspace:*",
    alpha: "2.0.0",
    beta: "^1.0.0",
  },
) => manifest("fixture-pkg", "0.0.0", { dependencies });

const store = (name: string, version: string) =>
  `node_modules/.bun/${name}@${version}/node_modules/${name}`;

// A checkout installed exactly to the lockfile, one directory below `parent`; beta's optional binding for another
// platform is absent, as bun leaves it.
function installedRoot(parent = scratch.dir("check-deps")): string {
  const root = join(parent, "checkout");
  writeTree(root, {
    "bun.lock": lockfile,
    "package.json": rootManifest(),
    "pkg/package.json": pkgManifest(),
    "shared/package.json": manifest("@fixture/shared", "0.0.0"),
    [`${store("alpha", "1.0.0")}/package.json`]: manifest("alpha", "1.0.0"),
    [`${store("alpha", "2.0.0")}/package.json`]: manifest("alpha", "2.0.0"),
    [`${store("beta", "1.2.3")}/package.json`]: manifest("beta", "1.2.3"),
    [`${store("gamma", "1.0.0")}/package.json`]: manifest("gamma", "1.0.0"),
  });
  mkdirSync(join(root, "pkg/node_modules/@fixture"), { recursive: true });
  symlinkSync(`.bun/alpha@1.0.0/node_modules/alpha`, join(root, "node_modules/alpha"));
  symlinkSync(`.bun/beta@1.2.3/node_modules/beta`, join(root, "node_modules/beta"));
  symlinkSync(`../../${store("alpha", "2.0.0")}`, join(root, "pkg/node_modules/alpha"));
  symlinkSync(`../../${store("beta", "1.2.3")}`, join(root, "pkg/node_modules/beta"));
  symlinkSync(
    "../../gamma@1.0.0/node_modules/gamma",
    join(root, "node_modules/.bun/beta@1.2.3/node_modules/gamma"),
  );
  symlinkSync("../../../shared", join(root, "pkg/node_modules/@fixture/shared"));
  return root;
}

const cases: { name: string; drift: (root: string) => void; findings: (string | RegExp)[] }[] = [
  { name: "installed to the lockfile", drift: () => {}, findings: [] },
  {
    name: "fresh clone: no node_modules at the root, whatever a member still holds",
    drift: (root) => rmSync(join(root, "node_modules"), { recursive: true }),
    findings: ["node_modules/ is absent"],
  },
  {
    name: "a package's store entry deleted",
    drift: (root) => rmSync(join(root, "node_modules/.bun/beta@1.2.3"), { recursive: true }),
    findings: [
      ".: beta is missing (bun.lock: beta@1.2.3)",
      "pkg: beta is missing (bun.lock: beta@1.2.3)",
    ],
  },
  {
    name: "a required transitive dependency's store entry deleted (no member declares it); walked once",
    drift: (root) => rmSync(join(root, "node_modules/.bun/gamma@1.0.0"), { recursive: true }),
    findings: [".: beta > gamma is missing (bun.lock: gamma@1.0.0)"],
  },
  {
    name: "the lockfile moved past the installed version",
    drift: (root) =>
      writeFileSync(
        join(root, `${store("beta", "1.2.3")}/package.json`),
        manifest("beta", "1.2.2"),
      ),
    findings: [
      ".: beta is 1.2.2 (bun.lock: beta@1.2.3)",
      "pkg: beta is 1.2.2 (bun.lock: beta@1.2.3)",
    ],
  },
  {
    name: "one member's link left on a superseded store entry while the root's is current",
    drift: (root) => {
      writeTree(root, { [`${store("beta", "1.2.2")}/package.json`]: manifest("beta", "1.2.2") });
      rmSync(join(root, "pkg/node_modules/beta"));
      symlinkSync(`../../${store("beta", "1.2.2")}`, join(root, "pkg/node_modules/beta"));
    },
    findings: ["pkg: beta is 1.2.2 (bun.lock: beta@1.2.3)"],
  },
  {
    name: "a member's package.json changed without re-locking: one dependency added, one spec moved",
    drift: (root) =>
      writeFileSync(
        join(root, "pkg/package.json"),
        pkgManifest({
          "@fixture/shared": "workspace:*",
          alpha: "2.0.0",
          beta: "^2.0.0",
          delta: "^1.0.0",
        }),
      ),
    findings: [
      "pkg: beta is ^2.0.0 in package.json, ^1.0.0 in bun.lock (re-lock with `bun install`)",
      "pkg: delta is ^1.0.0 in package.json, absent in bun.lock (re-lock with `bun install`)",
    ],
  },
  {
    name: "the root's workspaces list and overrides changed without re-locking",
    drift: (root) => {
      writeTree(root, { "extra/package.json": manifest("fixture-extra", "0.0.0") });
      writeFileSync(
        join(root, "package.json"),
        rootManifest({ workspaces: ["pkg", "sha*", "extra"], overrides: { gamma: "1.0.0" } }),
      );
    },
    findings: [
      "workspaces: extra is a member in package.json, absent in bun.lock (re-lock with `bun install`)",
      "overrides: gamma is 1.0.0 in package.json, ^1.0.0 in bun.lock (re-lock with `bun install`)",
    ],
  },
  {
    name: "a package directory left without its package.json",
    drift: (root) => rmSync(join(root, `${store("alpha", "1.0.0")}/package.json`)),
    findings: [".: alpha has no readable package.json (bun.lock: alpha@1.0.0)"],
  },
  {
    name: "a member's own version gone: resolution falls through to the hoisted one, which the member's key refuses",
    drift: (root) => rmSync(join(root, "pkg/node_modules/alpha"), { recursive: true }),
    findings: ["pkg: alpha is 1.0.0 (bun.lock: alpha@2.0.0)"],
  },
  {
    name: "a package symlinked to a directory outside the repository",
    drift: (root) => {
      const elsewhere = scratch.dir("check-deps-elsewhere");
      writeTree(elsewhere, { "node_modules/beta/package.json": manifest("beta", "1.2.3") });
      rmSync(join(root, "node_modules/beta"));
      symlinkSync(join(elsewhere, "node_modules/beta"), join(root, "node_modules/beta"));
    },
    findings: [/^\.: beta resolves outside the repository \(.*check-deps-elsewhere.*\)$/],
  },
  {
    name: "a workspace link pointing at the wrong member",
    drift: (root) => {
      rmSync(join(root, "pkg/node_modules/@fixture/shared"));
      writeTree(root, { "other/package.json": manifest("@fixture/shared", "0.0.0") });
      symlinkSync("../../../other", join(root, "pkg/node_modules/@fixture/shared"));
    },
    findings: ["pkg: @fixture/shared links to other (bun.lock: @fixture/shared@workspace:shared)"],
  },
];

test.each(cases)("$name", ({ drift, findings }) => {
  const root = installedRoot();
  drift(root);
  const actual = auditWorkspace(root);
  expect(actual).toHaveLength(findings.length);
  findings.forEach((expected, i) => {
    if (typeof expected === "string") expect(actual[i]).toBe(expected);
    else expect(actual[i]).toMatch(expected);
  });
});

// The incident: a git worktree lives under its main checkout, whose node_modules node's walk reaches, so a
// worktree that was never installed ran every bun task on the parent's packages.
test("a checkout under another checkout: the parent's node_modules never stands in for a missing package", () => {
  const parent = scratch.dir("check-deps-parent");
  writeTree(parent, { "node_modules/beta/package.json": manifest("beta", "1.2.3") });
  const root = installedRoot(parent);
  rmSync(join(root, "node_modules/.bun/beta@1.2.3"), { recursive: true });
  expect(auditWorkspace(root)).toEqual([
    ".: beta is missing (bun.lock: beta@1.2.3)",
    "pkg: beta is missing (bun.lock: beta@1.2.3)",
  ]);
});

// moon sees only the exit status, and the developer only stderr: a drift that exited 0, or a verdict on stdout,
// would let the dependent task run or hide the command to run.
test("as a process: an installed root is silent and exits 0, a fresh clone exits 1 naming the setup command on stderr", () => {
  const installed = installedRoot();
  const cold = installedRoot();
  rmSync(join(cold, "node_modules"), { recursive: true });
  const run = (root: string) => {
    const proc = Bun.spawnSync(
      [process.execPath, join(import.meta.dir, "..", "check-deps.ts"), "bun", root],
      { stdout: "pipe", stderr: "pipe" },
    );
    return {
      status: proc.exitCode,
      stdout: proc.stdout.toString(),
      stderr: proc.stderr.toString(),
    };
  };
  expect({ installed: run(installed), cold: run(cold) }).toEqual({
    installed: { status: 0, stdout: "", stderr: "" },
    cold: {
      status: 1,
      stdout: "",
      stderr: [
        "error: the checkout is missing what `moon run setup` installs:",
        "  node_modules/ is absent",
        "run `moon run setup` once; this check installs and fetches nothing",
        "",
      ].join("\n"),
    },
  });
});

// The cargo verdicts come from cargo itself, so a fake cargo on PATH records what it was asked and answers as
// scripted; the cargo workspaces are the root and the excluded `fuzz` (the excluded `docs` holds no Cargo.toml).
function cargoRoot(
  fail: string,
  message: string,
  active = "1.96.1",
): { root: string; log: string } {
  const root = scratch.dir("check-crates");
  const log = join(root, "cargo.log");
  writeTree(root, {
    "Cargo.toml": '[workspace]\nmembers = ["core"]\nexclude = ["fuzz", "docs"]\n',
    "rust-toolchain.toml": '[toolchain]\nchannel = "1.96.1"\n',
    "Cargo.lock": "",
    "fuzz/Cargo.toml": "",
    "fuzz/Cargo.lock": "",
    "docs/README.md": "",
    "cargo.err": `warning: scripted\nerror: ${message}\n`,
    "bin/cargo": [
      "#!/bin/sh",
      `printf '%s\\n' "RUSTUP_AUTO_INSTALL=$RUSTUP_AUTO_INSTALL cargo $*" >> "${log}"`,
      `if [ "$*" = "${fail}" ]; then /bin/cat "${join(root, "cargo.err")}" >&2; exit 101; fi`,
      `if [ "$*" = "--version" ]; then echo "cargo ${active} (fixture 2026-01-01)"; fi`,
      "exit 0",
      "",
    ].join("\n"),
  });
  chmodSync(join(root, "bin/cargo"), 0o755);
  return { root, log };
}

const cargoCases: {
  name: string;
  fail: string;
  message: string;
  active?: string;
  findings: string[];
  asked: string[];
}[] = [
  {
    name: "toolchain installed and both workspaces fetched: silent, three offline questions asked",
    fail: "",
    message: "",
    findings: [],
    asked: [
      "cargo --version",
      "cargo fetch --locked --offline --manifest-path Cargo.toml",
      "cargo fetch --locked --offline --manifest-path fuzz/Cargo.toml",
    ],
  },
  {
    name: "the pinned toolchain is not installed: rustup's refusal is the finding and nothing else is asked",
    fail: "--version",
    message: "toolchain '1.96.1-aarch64-apple-darwin' is not installed",
    findings: ["rust toolchain: error: toolchain '1.96.1-aarch64-apple-darwin' is not installed"],
    asked: ["cargo --version"],
  },
  {
    name: "another toolchain is active than the pin (an inherited RUSTUP_TOOLCHAIN): named, nothing fetched is asked",
    fail: "",
    message: "",
    active: "1.97.0",
    findings: [
      "rust toolchain: cargo 1.97.0 (fixture 2026-01-01) is active, rust-toolchain.toml pins 1.96.1",
    ],
    asked: ["cargo --version"],
  },
  {
    name: "the fuzz workspace's crates are not fetched: the manifest is named with cargo's error line",
    fail: "fetch --locked --offline --manifest-path fuzz/Cargo.toml",
    message: "no matching package named `arbitrary` found (--offline)",
    findings: [
      "fuzz/Cargo.toml: crates are not fetched to its Cargo.lock (error: no matching package named `arbitrary` found (--offline))",
    ],
    asked: [
      "cargo --version",
      "cargo fetch --locked --offline --manifest-path Cargo.toml",
      "cargo fetch --locked --offline --manifest-path fuzz/Cargo.toml",
    ],
  },
];

test.each(cargoCases)("$name", ({ fail, message, active, findings, asked }) => {
  const { root, log } = cargoRoot(fail, message, active);
  const env = { ...process.env, PATH: join(root, "bin") };
  expect(auditCrates(root, env)).toEqual(findings);
  expect(readFileSync(log, "utf8")).toBe(
    asked.map((command) => `RUSTUP_AUTO_INSTALL=0 ${command}\n`).join(""),
  );
});

test("no cargo on PATH is a finding pointing at rustup, not a crash", () => {
  const { root } = cargoRoot("", "");
  expect(auditCrates(root, { ...process.env, PATH: scratch.dir("empty-path") })).toEqual([
    "rust toolchain: cargo is not on PATH (rustup installs it: https://rustup.rs)",
  ]);
});
