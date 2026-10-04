import { afterEach, expect, test } from "bun:test";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { COMMIT_SUBJECT, commitFormatting } from "../auto-format-commit.ts";
import { gitEnv, runGit, Scratch } from "../lib.ts";

// The formatter's rewrite must reach the pull request's branch as one commit the Actions bot authored,
// and a clean checkout must leave the branch alone: a `git commit` on nothing fails the step, and an
// author address without the bot's id shows as an unknown user. Neither is enforced by anything else.

const env = gitEnv();
const scratch = new Scratch();
afterEach(() => scratch.remove());
const must = (cwd: string, ...args: string[]) => runGit(cwd, env, ...args);

function checkoutWithRemote(): { work: string; remote: string } {
  const dir = scratch.dir("auto-format-commit");
  const remote = join(dir, "remote.git");
  must(dir, "init", "--quiet", "--bare", remote);
  const work = join(dir, "work");
  mkdirSync(work);
  must(work, "init", "--quiet", "--initial-branch", "pr");
  must(work, "config", "user.name", "example-user");
  must(work, "config", "user.email", "example-user@example.com");
  writeFileSync(join(work, "a.ts"), "const  x=1\n");
  must(work, "add", "--all");
  must(work, "commit", "--quiet", "--message", "fixture");
  must(work, "push", "--quiet", remote, "HEAD:refs/heads/pr");
  return { work, remote };
}

test("a rewritten checkout is committed by the bot and pushed to the branch; a clean one is left alone", async () => {
  const { work, remote } = checkoutWithRemote();
  writeFileSync(join(work, "a.ts"), "const x = 1;\n");

  expect(await commitFormatting(work, env, remote, "pr")).toEqual({ committed: true });
  const head = must(work, "rev-parse", "HEAD");
  expect({
    remoteTip: must(work, "--git-dir", remote, "rev-parse", "refs/heads/pr"),
    commit: must(work, "log", "-1", "--format=%s%n%an <%ae>"),
    status: must(work, "status", "--porcelain"),
  }).toEqual({
    remoteTip: head,
    // GitHub links a commit to the Actions bot only under this id-prefixed address.
    commit: `${COMMIT_SUBJECT}\ngithub-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>\n`,
    status: "",
  });

  expect(await commitFormatting(work, env, remote, "pr")).toEqual({ committed: false });
  expect(must(work, "rev-parse", "HEAD")).toBe(head);
});
