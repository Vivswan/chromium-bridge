import { afterEach, describe, expect, test } from "bun:test";
import { checkGenerated, type GenReport } from "../check-gen.ts";
import { gitEnv, runGit, Scratch, writeTree } from "../lib.ts";

// `git diff` never sees an untracked file, so a generated module written for the first time would pass a
// diff-only gate, and the pathspec's scope (generated modules only, hand-written siblings out) is a claim
// no tool checks. Both are pinned on a scratch repository with one module of each kind committed.

const env = gitEnv();
const scratch = new Scratch();
afterEach(() => scratch.remove());

const shared = "src/packages/shared/src";
const write = (root: string, file: string, text: string) =>
  writeTree(root, { [`${shared}/${file}`]: text });

function repo(): string {
  const root = scratch.dir("check-gen");
  write(root, "ops.gen.ts", "export const ops = [];\n");
  write(root, "envelope.ts", "export const envelope = 1;\n");
  for (const args of [
    ["init", "--quiet"],
    ["config", "user.name", "example-user"],
    ["config", "user.email", "example-user@example.com"],
    ["add", "--all"],
    ["commit", "--quiet", "--message", "fixture"],
  ]) {
    runGit(root, env, ...args);
  }
  return root;
}

describe("checkGenerated", () => {
  test.each<[string, (root: string) => void, GenReport]>([
    [
      "a checkout matching what the generators wrote is clean",
      () => {},
      { stale: [], untracked: [] },
    ],
    [
      "a generated module rewritten differently is stale",
      (root) => write(root, "ops.gen.ts", "export const ops = [1];\n"),
      { stale: [`${shared}/ops.gen.ts`], untracked: [] },
    ],
    [
      "a generated module no commit tracks is reported as untracked, which a diff alone would miss",
      (root) => write(root, "policy.gen.ts", "export const policy = {};\n"),
      { stale: [], untracked: [`${shared}/policy.gen.ts`] },
    ],
    [
      "a hand-written sibling mid-edit is out of the gate's scope",
      (root) => write(root, "envelope.ts", "export const envelope = 2;\n"),
      { stale: [], untracked: [] },
    ],
  ])("%s", (_name, mutate, expected) => {
    const root = repo();
    mutate(root);
    expect(checkGenerated(root, env)).toEqual(expected);
  });
});
