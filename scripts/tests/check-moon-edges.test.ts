import { describe, expect, test } from "bun:test";
import { auditGraph, CRATES_CHECK, DEPS_CHECK, GATE, type TaskGraph } from "../check-moon-edges";

// Drift answer: a task's command and its deps sit on different lines of moon.yml, and moon cannot express "every
// task that runs bun depends on check-deps" or "the pre-commit gate runs only the repository's own toolchain".
// The graph is hand-written in the shape `moon query tasks` returns.
const edge = [{ target: DEPS_CHECK }];
const crates = [{ target: CRATES_CHECK }];
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
      ],
    },
    ci: { command: "noop", deps: [{ target: "root:gate" }, { target: "root:check-yaml" }] },
    "check-deps": { command: "bun", args: ["scripts/check-deps.ts", "bun"], deps: [] },
    "check-crates": { command: "bun", args: ["scripts/check-deps.ts", "cargo"], deps: [] },
    hygiene: {
      command: "noop",
      deps: [{ target: "root:check-pins" }, { target: "root:check-yaml" }],
    },
    typecheck: {
      command: "set",
      script:
        "set -e\nbunx --no-install tsc -p scripts\nbunx --no-install tsc -p src/packages/shared\n",
      deps: edge,
    },
    "gen-shared": {
      command: "set",
      script:
        "set -e\nbun scripts/gen-ops.ts\nbunx --no-install biome format --write \\\n  src/a.gen.ts \\\n  src/b.gen.ts\n",
      deps: edge,
    },
    "check-pins": {
      command: "bun",
      script: "bun test scripts/tests/pin.test.ts && bun scripts/pin.ts",
      deps: [],
    },
    "check-yaml": { command: "uvx", args: ["yamllint@1.38.0", "-s", "."], deps: [] },
    machete: { command: "cargo", args: ["machete"], deps: crates },
    unfetched: { command: "cargo", args: ["doc", "--workspace"], deps: [] },
    "sneaky-install": { command: "bun", args: ["install", "--frozen-lockfile"], deps: edge },
    "sneaky-alias": { command: "bun", args: ["i"], deps: edge },
    "sneaky-x": { command: "bun", args: ["x", "fixture-tool"], deps: edge },
    "lint-ts": { command: "bunx", args: ["--no-install", "biome", "lint", "."], deps: edge },
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
    "mentions-bun": {
      command: "set",
      script: "set -e\n# bun test would be wrong here\necho bun test",
    },
  },
  core: {
    lint: {
      command: "cargo",
      args: ["clippy", "--frozen", "--all-targets", "--", "-D", "warnings"],
      deps: crates,
    },
    "fmt-check": { command: "cargo", args: ["fmt", "--check"], deps: crates },
  },
  web: { build: { command: "bun" } },
};

describe("auditGraph", () => {
  test("names every rule a task breaks, sorted: the bun edge and --no-install everywhere, own-toolchain commands with the crates edge and --frozen inside the gate's closure only", () => {
    expect(auditGraph(graph)).toEqual(
      [
        "root:check-pins: runs bun without depending on root:check-deps",
        "root:check-yaml: runs uvx inside root:gate (not bun, bunx, or a cargo toolchain verb)",
        "root:machete: runs cargo machete inside root:gate (not a toolchain verb)",
        "root:machete: cargo machete inside root:gate without --frozen",
        "root:quoted-runner: bunx without --no-install",
        "root:quoted-runner: runs bun without depending on root:check-deps",
        "root:sneaky-install: bun install inside root:gate (installs)",
        "root:sneaky-alias: bun i inside root:gate (installs)",
        "root:sneaky-x: bunx without --no-install",
        "root:unfetched: cargo doc inside root:gate without --frozen",
        "root:unfetched: runs cargo inside root:gate without depending on root:check-crates",
        "root:vanished: reachable from root:gate but not in the graph",
        "web:build: runs bun without depending on root:check-deps",
      ].sort(),
    );
  });

  test("the exemption set is the only way a bun task passes without the edge", () => {
    expect(auditGraph(graph, new Set()).filter((f) => f.includes(DEPS_CHECK))).toEqual([
      "root:build-repro: runs bun without depending on root:check-deps",
      "root:check-crates: runs bun without depending on root:check-deps",
      "root:check-deps: runs bun without depending on root:check-deps",
      "root:check-pins: runs bun without depending on root:check-deps",
      "root:quoted-runner: runs bun without depending on root:check-deps",
      "root:setup: runs bun without depending on root:check-deps",
      "web:build: runs bun without depending on root:check-deps",
    ]);
  });

  test("a graph without the gate reports the gate itself, not a clean census", () => {
    const { gate: _gate, ...rootWithoutGate } = graph.root ?? {};
    expect(auditGraph({ ...graph, root: rootWithoutGate })).toContain(
      `${GATE}: reachable from ${GATE} but not in the graph`,
    );
  });
});
