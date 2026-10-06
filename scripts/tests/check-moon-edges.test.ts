import { describe, expect, test } from "bun:test";
import { auditGraph, GATE, type TaskGraph } from "../check-moon-edges";

// Drift answer: moon cannot express "no task runs bunx", "the pre-commit gate runs only the repository's own
// toolchain", or "a task that names a build/ path depends on its writer", and a task added without them fails on
// its first cold run, inside a commit, or against a stale artifact. The graph is hand-written in the shape
// `moon query tasks` returns.
const graph: TaskGraph = {
  root: {
    gate: {
      command: "noop",
      deps: [
        { target: "core:lint" },
        { target: "core:fmt-check" },
        { target: "root:typecheck" },
        { target: "root:hygiene" },
        { target: "root:machete" },
        { target: "root:gen-shared" },
        { target: "root:unfetched" },
        { target: "root:vanished" },
        { target: "root:sneaky-install" },
        { target: "root:sneaky-alias" },
        { target: "root:sneaky-x" },
        { target: "root:sneaky-cwd-x" },
        { target: "root:sneaky-cwd" },
        { target: "root:sneaky-config" },
        { target: "root:frozen-after-dashes" },
        { target: "root:auto-install" },
      ],
    },
    ci: { command: "noop", deps: [{ target: "root:gate" }, { target: "root:check-yaml" }] },
    hygiene: {
      command: "noop",
      deps: [{ target: "root:check-pins" }, { target: "root:check-yaml" }],
    },
    typecheck: {
      command: "set",
      script: "set -e\nbun run tsc -p scripts\nbun run tsc -p src/packages/shared\n",
      deps: [],
    },
    "gen-shared": {
      command: "set",
      script:
        "set -e\nbun scripts/gen-ops.ts\nbun run biome format --write \\\n  src/a.gen.ts \\\n  src/b.gen.ts\n",
      deps: [],
    },
    "check-pins": {
      command: "bun",
      script: "bun test scripts/tests/pin.test.ts && bun scripts/pin.ts",
      deps: [],
    },
    "check-yaml": { command: "uvx", args: ["yamllint@1.38.0", "-s", "."], deps: [] },
    machete: { command: "cargo", args: ["machete"], deps: [], env: { RUSTUP_AUTO_INSTALL: "0" } },
    unfetched: {
      command: "cargo",
      args: ["doc", "--workspace"],
      deps: [],
      env: { RUSTUP_AUTO_INSTALL: "0" },
    },
    "sneaky-cwd": { command: "bun", args: ["--cwd=.", "install"], deps: [] },
    "sneaky-config": { command: "bun", args: ["--config", "install"], deps: [] },
    "frozen-after-dashes": {
      command: "cargo",
      args: ["clippy", "--all-targets", "--", "--frozen"],
      deps: [],
      env: { RUSTUP_AUTO_INSTALL: "0" },
    },
    "auto-install": { command: "cargo", args: ["doc", "--frozen"], deps: [] },
    "sneaky-install": { command: "bun", args: ["install", "--frozen-lockfile"], deps: [] },
    "sneaky-alias": { command: "bun", args: ["i"], deps: [] },
    "sneaky-x": { command: "bun", args: ["x", "fixture-tool"], deps: [] },
    "sneaky-cwd-x": { command: "bun", args: ["--cwd", ".", "x", "fixture-tool"], deps: [] },
    "lint-ts": { command: "bun", args: ["run", "biome", "lint", "."], deps: [] },
    "fmt-ts": {
      command: "bunx",
      args: ["--no-install", "biome", "format", "--write", "."],
      deps: [],
    },
    typos: { command: "typos", deps: [] },
    "build-repro": { command: "bun" },
    setup: {
      command: "set",
      script: "set -e\nbun install --frozen-lockfile\ncargo fetch --locked\n",
      deps: [],
    },
    "build-release": { command: "cargo", args: ["build", "--release"], script: null, deps: [] },
    install: {
      command: "./target/release/chromium-bridge",
      deps: [{ target: "root:build-release" }],
    },
    "quoted-runner": { command: "set", script: 'set -e; "bunx" tsc -p scripts' },
    "reads-built-without-dependency": {
      command: "bun",
      args: ["scripts/check-built.ts"],
      deps: [],
      inputFiles: { "build/extension/chrome-mv3/manifest.json": {} },
    },
    "reads-built-through-aggregate": {
      command: "bun",
      args: ["scripts/pack.ts", "build/extension/chrome-mv3"],
      deps: [{ target: "root:build-all" }],
    },
    "build-all": { command: "noop", deps: [{ target: "extension:build" }] },
    "reads-glob-build": {
      command: "bun",
      args: ["scripts/x.ts"],
      deps: [],
      inputGlobs: { "build/web-pdf/**/*": { cache: true } },
    },
    "writes-and-names-own-output": {
      command: "bun",
      args: ["scripts/zip.ts", "build/bundle"],
      deps: [],
      outputFiles: { "build/bundle": { optional: false } },
    },
    "reads-under-glob-writer": {
      command: "bun",
      args: ["scripts/y.ts"],
      deps: [{ target: "root:writes-glob" }],
      inputFiles: { "build/report-html/index.html": {} },
    },
    "writes-glob": { command: "bun", deps: [], outputGlobs: { "build/report-*/**/*": {} } },
    "names-filesystem-path": {
      command: "bun",
      args: ["scripts/q.ts", "/build/extension"],
      deps: [],
    },
    "reads-dotted-path": {
      command: "bun",
      args: ["scripts/r.ts", "././build/./web/../extension/chrome-mv3/manifest.json"],
      deps: [],
    },
    "mentions-bun": {
      command: "set",
      script: "set -e\n# bun test would be wrong here\necho bun test",
    },
  },
  extension: {
    build: {
      command: "bun",
      args: ["run", "build"],
      deps: [],
      outputFiles: { "build/extension": { optional: false } },
    },
    // Runs in src/apps/extension, so this word is src/apps/extension/build/extension, not the workspace artifact.
    pack: { command: "bun", args: ["scripts/pack.ts", "build/extension"], deps: [] },
  },
  core: {
    lint: {
      command: "cargo",
      args: ["clippy", "--frozen", "--all-targets", "--", "-D", "warnings"],
      deps: [],
      env: { RUSTUP_AUTO_INSTALL: "0" },
    },
    "fmt-check": {
      command: "cargo",
      args: ["fmt", "--check"],
      deps: [],
      env: { RUSTUP_AUTO_INSTALL: "0" },
    },
  },
  web: { build: { command: "bun" } },
};

describe("auditGraph", () => {
  test("names every rule a task breaks, sorted: no bunx anywhere, own-toolchain commands with --frozen and RUSTUP_AUTO_INSTALL=0 and no bun install inside the gate's closure only, and every named build/ path ordered after its writer", () => {
    expect(auditGraph(graph)).toEqual(
      [
        "root:reads-built-without-dependency: names build/extension/chrome-mv3/manifest.json without depending on extension:build, which writes build/extension",
        "root:reads-dotted-path: names build/extension/chrome-mv3/manifest.json without depending on extension:build, which writes build/extension",
        "root:reads-glob-build: declares the glob input build/web-pdf/**/*; a reader under build/ declares the file or directory it reads",
        "root:writes-glob: declares the glob output build/report-*/**/*; a writer under build/ declares the directory it writes",
        "root:reads-under-glob-writer: names build/report-html/index.html, which no task's outputs write",
        "root:check-yaml: runs uvx inside root:gate (not bun or a cargo toolchain verb)",
        "root:machete: runs cargo machete inside root:gate (not a toolchain verb)",
        "root:machete: cargo machete inside root:gate without --frozen",
        "root:fmt-ts: runs bunx (bun's global cache stands in for a missing package)",
        "root:quoted-runner: runs bunx (bun's global cache stands in for a missing package)",
        "root:auto-install: cargo doc inside root:gate without RUSTUP_AUTO_INSTALL=0 in env",
        "root:frozen-after-dashes: cargo clippy inside root:gate without --frozen",
        "root:sneaky-config: bun install inside root:gate (installs)",
        "root:sneaky-cwd: bun install inside root:gate (installs)",
        "root:sneaky-install: bun install inside root:gate (installs)",
        "root:sneaky-alias: bun i inside root:gate (installs)",
        "root:sneaky-cwd-x: runs bunx (bun's global cache stands in for a missing package)",
        "root:sneaky-cwd-x: runs bunx inside root:gate (not bun or a cargo toolchain verb)",
        "root:sneaky-x: runs bunx (bun's global cache stands in for a missing package)",
        "root:sneaky-x: runs bunx inside root:gate (not bun or a cargo toolchain verb)",
        "root:unfetched: cargo doc inside root:gate without --frozen",
        "root:vanished: reachable from root:gate but not in the graph",
      ].sort(),
    );
  });

  test("a writer of the whole build directory covers every path under it, and a reader of a directory follows every writer inside it", () => {
    const whole: TaskGraph = {
      root: {
        gate: { command: "noop", deps: [{ target: "root:reads-anywhere" }] },
        "writes-build": { command: "bun", deps: [], outputFiles: { build: { optional: false } } },
        "writes-part": {
          command: "bun",
          deps: [],
          outputFiles: { "build/part": { optional: false } },
        },
        "reads-anywhere": {
          command: "bun",
          args: ["scripts/z.ts", "build/anything/at/all"],
          deps: [{ target: "root:writes-build" }],
        },
        "lists-build": { command: "bun", args: ["scripts/ls.ts", "build/"], deps: [] },
      },
    };
    expect(auditGraph(whole)).toEqual([
      "root:lists-build: names build without depending on root:writes-build, which writes build",
      "root:lists-build: names build without depending on root:writes-part, which writes build/part",
    ]);
  });

  test("a graph without the gate reports the gate itself, not a clean census", () => {
    const { gate: _gate, ...rootWithoutGate } = graph.root ?? {};
    expect(auditGraph({ ...graph, root: rootWithoutGate })).toContain(
      `${GATE}: reachable from ${GATE} but not in the graph`,
    );
  });
});
