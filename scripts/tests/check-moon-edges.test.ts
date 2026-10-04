import { describe, expect, test } from "bun:test";
import { missingInstallEdges, type TaskGraph } from "../check-moon-edges";

// Drift answer: a task's command and its deps sit on different lines of moon.yml, and moon cannot express "every
// task that runs bun depends on install-deps".
const install = [{ target: "root:install-deps" }];
const graph: TaskGraph = {
  root: {
    "lint-ts": { command: "bunx", deps: install },
    typos: { command: "typos", deps: [] },
    "check-pins": {
      command: "bun",
      script: "bun test scripts/tests/pin.test.ts && bun scripts/pin.ts",
      deps: [],
    },
    "build-repro": { command: "bun" },
    "gen-shared": { command: "set", script: "set -e\nbun scripts/gen-ops.ts\n", deps: [] },
    "build-release": { command: "cargo", script: null, deps: [] },
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
  web: { build: { command: "bun" } },
};

describe("missingInstallEdges", () => {
  test("names every task whose command or a script line starts with bun or bunx and lacks the edge, sorted, deps absent or empty alike", () => {
    expect(missingInstallEdges(graph)).toEqual([
      "root:check-pins",
      "root:gen-shared",
      "root:quoted-runner",
      "web:build",
    ]);
  });

  test("the exception set is the only way a bun task passes without the edge", () => {
    expect(missingInstallEdges(graph, new Set())).toEqual([
      "root:build-repro",
      "root:check-pins",
      "root:gen-shared",
      "root:quoted-runner",
      "web:build",
    ]);
  });
});
