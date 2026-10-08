// The runner's two CI switches are environment variables, and the shell's way of unsetting one is an empty
// value (`GENKAN_BROWSER_CANARY_DIR= bun run_all.ts`). The landing review found that an empty value was read
// as a caller-named dir "" on one line and as unset on another, so a fully passing run exited 1 with every
// marker "missing"; a second finding: a relative dir was written by the suites from the repo root but
// checked by the runner against its own cwd. This pins the one reading both sides share: empty is none,
// and a path is absolute before it reaches a suite.

import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import { callerCanaryDir } from "./run_all";

describe("callerCanaryDir", () => {
  test.each([
    { name: "unset means no caller dir", env: {}, dir: undefined },
    { name: "empty means no caller dir", env: { GENKAN_BROWSER_CANARY_DIR: "" }, dir: undefined },
    {
      name: "an absolute path is the caller dir",
      env: { GENKAN_BROWSER_CANARY_DIR: "/tmp/canary" },
      dir: "/tmp/canary",
    },
    {
      name: "a relative path is resolved against the runner's cwd before any suite sees it",
      env: { GENKAN_BROWSER_CANARY_DIR: "tmp/canary" },
      dir: resolve("tmp/canary"),
    },
  ])("$name", ({ env, dir }) => {
    expect(callerCanaryDir(env)).toBe(dir);
  });
});
