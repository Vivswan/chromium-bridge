import { afterAll, expect, test } from "bun:test";
import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { missingMessage } from "../check-uv.ts";
import { Scratch } from "../lib.ts";

// moon sees only the exit status and stderr of this check, and the suites that depend on it run only when
// it exits 0: a refusal that exited 0, or a found uv that still printed the refusal, would misroute them.
// The PATH handed to the subprocess is a scratch directory with or without a uv in it.

const scratch = new Scratch();
afterAll(() => scratch.remove());

function checkWith(path: string) {
  // process.execPath: the PATH handed down holds no bun.
  const run = Bun.spawnSync([process.execPath, join(import.meta.dir, "..", "check-uv.ts")], {
    cwd: join(import.meta.dir, "../.."),
    env: { ...process.env, PATH: path },
    stdout: "pipe",
    stderr: "pipe",
  });
  return { status: run.exitCode, stdout: run.stdout.toString(), stderr: run.stderr.toString() };
}

test("uv on PATH exits 0 silently; no uv exits 1 with the pin file and the install routes on stderr", () => {
  const withUv = scratch.dir("check-uv-with");
  const without = scratch.dir("check-uv-without");
  writeFileSync(join(withUv, "uv"), "#!/bin/sh\nexit 0\n");
  chmodSync(join(withUv, "uv"), 0o755);

  expect({ found: checkWith(withUv), missing: checkWith(without) }).toEqual({
    found: { status: 0, stdout: "", stderr: "" },
    missing: { status: 1, stdout: "", stderr: `error: ${missingMessage}\n` },
  });
});
