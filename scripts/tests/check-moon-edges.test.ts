import { describe, expect, test } from "bun:test";
import { auditGraph, GATE, type TaskGraph } from "../check-moon-edges";

// Drift answer: moon cannot express "bunx never installs" or "the pre-commit gate runs only the repository's own
// toolchain", and a task added without them fails on its first cold run or inside a commit. The graph is
// hand-written in the shape `moon query tasks` returns.
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
    hygiene: {
      command: "noop",
      deps: [{ target: "root:check-pins" }, { target: "root:check-yaml" }],
    },
    typecheck: {
      command: "set",
      script:
        "set -e\nbunx --no-install tsc -p scripts\nbunx --no-install tsc -p src/packages/shared\n",
      deps: [],
    },
    "gen-shared": {
      command: "set",
      script:
        "set -e\nbun scripts/gen-ops.ts\nbunx --no-install biome format --write \\\n  src/a.gen.ts \\\n  src/b.gen.ts\n",
      deps: [],
    },
    "check-pins": {
      command: "bun",
      script: "bun test scripts/tests/pin.test.ts && bun scripts/pin.ts",
      deps: [],
    },
    "check-yaml": { command: "uvx", args: ["yamllint@1.38.0", "-s", "."], deps: [] },
    machete: { command: "cargo", args: ["machete"], deps: [] },
    unfetched: { command: "cargo", args: ["doc", "--workspace"], deps: [] },
    "sneaky-install": { command: "bun", args: ["install", "--frozen-lockfile"], deps: [] },
    "sneaky-alias": { command: "bun", args: ["i"], deps: [] },
    "sneaky-x": { command: "bun", args: ["x", "fixture-tool"], deps: [] },
    "lint-ts": { command: "bunx", args: ["--no-install", "biome", "lint", "."], deps: [] },
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
      deps: [],
    },
    "fmt-check": { command: "cargo", args: ["fmt", "--check"], deps: [] },
  },
  web: { build: { command: "bun" } },
};

describe("auditGraph", () => {
  test("names every rule a task breaks, sorted: --no-install everywhere, own-toolchain commands with --frozen and no bun install inside the gate's closure only", () => {
    expect(auditGraph(graph)).toEqual(
      [
        "root:check-yaml: runs uvx inside root:gate (not bun, bunx, or a cargo toolchain verb)",
        "root:machete: runs cargo machete inside root:gate (not a toolchain verb)",
        "root:machete: cargo machete inside root:gate without --frozen",
        "root:quoted-runner: bunx without --no-install",
        "root:sneaky-install: bun install inside root:gate (installs)",
        "root:sneaky-alias: bun i inside root:gate (installs)",
        "root:sneaky-x: bunx without --no-install",
        "root:unfetched: cargo doc inside root:gate without --frozen",
        "root:vanished: reachable from root:gate but not in the graph",
      ].sort(),
    );
  });

  test("a graph without the gate reports the gate itself, not a clean census", () => {
    const { gate: _gate, ...rootWithoutGate } = graph.root ?? {};
    expect(auditGraph({ ...graph, root: rootWithoutGate })).toContain(
      `${GATE}: reachable from ${GATE} but not in the graph`,
    );
  });
});
