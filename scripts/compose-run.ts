#!/usr/bin/env bun
// Runs one compose.yaml service, supplying what only the host knows: the engine (podman adds its
// user-namespace override file), the caller's uid and gid, and a linked worktree's git common dir,
// which must be mounted at its own absolute path for git inside the container to resolve the
// worktree's .git file.
//
//   bun scripts/compose-run.ts ci|browser|shell [command [args...]]
//
// bash and zsh refuse `UID=...` in a shell, so the ids are set here, not in the moon task.

import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { die, repoRoot } from "./lib.ts";

const [service, ...command] = process.argv.slice(2);
if (!service) die("usage: bun scripts/compose-run.ts ci|browser|shell [command [args...]]", 2);

const engine = process.env.CONTAINER_ENGINE ?? "docker";
const composeFiles = ["-f", "compose.yaml"];
if (engine === "podman") composeFiles.push("-f", "compose.podman.yaml");

const gitCommonDir = realpathSync(
  execFileSync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
    cwd: repoRoot,
    encoding: "utf8",
  }).trim(),
);
const env: NodeJS.ProcessEnv = {
  ...process.env,
  UID: String(process.getuid?.() ?? 1000),
  GID: String(process.getgid?.() ?? 1000),
};
// A plain checkout's .git is already inside the bind mount; only a linked worktree needs the common
// dir mounted separately, and only one whose .git file names it by absolute path resolves from /work
// (`git worktree add --relative-paths` writes a pointer that would resolve relative to /work instead).
const dotGit = join(repoRoot, ".git");
if (gitCommonDir !== realpathSync(dotGit)) {
  if (statSync(dotGit).isFile()) {
    const pointer = readFileSync(dotGit, "utf8")
      .replace(/^gitdir:\s*/, "")
      .trim();
    if (!isAbsolute(pointer)) {
      die(
        `this worktree's .git file points at '${pointer}', a relative path the container cannot resolve; use a worktree created without --relative-paths`,
      );
    }
  }
  env.COMPOSE_GIT_DIR = gitCommonDir;
}

function compose(...args: string[]): void {
  const run = spawnSync(engine, ["compose", ...composeFiles, ...args], {
    cwd: repoRoot,
    stdio: "inherit",
    env,
  });
  if (run.error) die(`could not start ${engine}: ${run.error.message}`, 2);
  if (run.status !== 0) process.exit(run.status ?? 1);
}

compose("build", service);
compose("run", "--rm", service, ...command);
