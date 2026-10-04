#!/usr/bin/env bun
// Runs one compose.yaml service, supplying what only the host knows: the engine (podman adds its
// user-namespace override file), the caller's uid and gid, and the git common dir, which a linked
// worktree keeps outside the checkout. A worktree's .git file names that dir by a HOST path, and
// moon runs git with GIT_DIR cleared, so the container gets a pointer file bind-mounted over
// /work/.git that names the dir by its fixed mount point, /work-git, instead.
//
//   bun scripts/compose-run.ts ci|browser|shell [command [args...]]
//
// bash and zsh refuse `UID=...` in a shell, so the ids are set here, not in the moon task.

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { die, repoRoot } from "./lib.ts";
import { readPin } from "./pin.ts";

const [service, ...command] = process.argv.slice(2);
if (!service) die("usage: bun scripts/compose-run.ts ci|browser|shell [command [args...]]", 2);

const engine = process.env.CONTAINER_ENGINE ?? "docker";
const composeFiles = ["-f", "compose.yaml"];
if (engine === "podman") composeFiles.push("-f", "compose.podman.yaml");

const env: NodeJS.ProcessEnv = {
  ...process.env,
  UID: String(process.getuid?.() ?? 1000),
  GID: String(process.getgid?.() ?? 1000),
  COMPOSE_GIT_DIR: execFileSync(
    "git",
    ["rev-parse", "--path-format=absolute", "--git-common-dir"],
    { cwd: repoRoot, encoding: "utf8" },
  ).trim(),
};

// The Containerfile's one build arg: proto's pin is .prototools's and no script runs inside the build, so the
// launcher reads it, as container-image.yml does for the published image. A flag rather than compose.yaml
// build.args: the portable compose subset (check-compose) has no args key. Read before the scratch dir
// below exists, so a refused pin leaves nothing behind.
const protoPin = readPin("proto");

// The pointer's text is `gitdir: <path>`; git itself tolerates a CRLF ending, so trim() does too.
const dotGit = join(repoRoot, ".git");
const scratch = statSync(dotGit).isFile() ? mkdtempSync(join(tmpdir(), "compose-run-")) : null;
if (scratch) {
  const worktree = basename(
    readFileSync(dotGit, "utf8")
      .replace(/^gitdir:\s*/, "")
      .trim(),
  );
  const pointer = join(scratch, "git-pointer");
  writeFileSync(pointer, `gitdir: /work-git/worktrees/${worktree}\n`);
  env.COMPOSE_GIT_POINTER = pointer;
}

function compose(...args: string[]): number {
  const run = spawnSync(engine, ["compose", ...composeFiles, ...args], {
    cwd: repoRoot,
    stdio: "inherit",
    env,
  });
  if (run.error) {
    console.error(`error: could not start ${engine}: ${run.error.message}`);
    return 2;
  }
  return run.status ?? 1;
}

let status = compose("build", "--build-arg", `PROTO_VERSION=${protoPin}`, service);
if (status === 0) status = compose("run", "--rm", service, ...command);
if (scratch) rmSync(scratch, { recursive: true, force: true });
process.exit(status);
