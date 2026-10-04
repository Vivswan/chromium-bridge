// The runner's two CI switches are environment variables, and the shell's way of unsetting one is an empty
// value (`BB_BROWSER_CANARY_DIR= bun run_all.ts`). The landing review found that an empty value was read
// as a caller-named dir "" on one line and as unset on another, so a fully passing run exited 1 with every
// marker "missing". This pins the one reading both lines share.

import { describe, expect, test } from "bun:test";
import { callerCanaryDir } from "./run_all";

describe("callerCanaryDir", () => {
  test.each([
    { name: "unset means no caller dir", env: {}, dir: undefined },
    { name: "empty means no caller dir", env: { BB_BROWSER_CANARY_DIR: "" }, dir: undefined },
    {
      name: "a path is the caller dir",
      env: { BB_BROWSER_CANARY_DIR: "/tmp/canary" },
      dir: "/tmp/canary",
    },
  ])("$name", ({ env, dir }) => {
    expect(callerCanaryDir(env)).toBe(dir);
  });
});
