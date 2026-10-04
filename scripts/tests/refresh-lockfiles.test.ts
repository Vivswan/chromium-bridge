import { afterEach, expect, test } from "bun:test";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { gitEnv, repoRoot, Scratch, writeTree } from "../lib.ts";
import { COMMIT_SUBJECT, refreshLockfiles } from "../refresh-lockfiles.ts";

// release-please bumps the manifests and no lockfile, and `cargo --locked` refuses a lockfile whose member
// version lags its manifest (exit 101): the release PR failed every --locked step until the hook re-locked.
// The scratch workspace is hand-written and dependency-free, so cargo and bun need no registry.

const env = gitEnv();
const scratch = new Scratch();
afterEach(() => scratch.remove());

function run(cwd: string, ...cmd: string[]): { exitCode: number; stdout: string; stderr: string } {
  const child = Bun.spawnSync(cmd, { cwd, env, stdout: "pipe", stderr: "pipe" });
  return {
    exitCode: child.exitCode,
    stdout: child.stdout.toString(),
    stderr: child.stderr.toString(),
  };
}

function must(cwd: string, ...cmd: string[]): string {
  const result = run(cwd, ...cmd);
  if (result.exitCode !== 0) throw new Error(`${cmd.join(" ")} failed: ${result.stderr}`);
  return result.stdout;
}

/** A root cargo workspace, an excluded nested one depending on it by path, and a bun workspace. */
function manifests(version: string): Record<string, string> {
  return {
    "Cargo.toml": `[workspace]\nresolver = "2"\nmembers = ["core", "host"]\nexclude = ["core/fuzz"]\n\n[workspace.package]\nversion = "${version}"\nedition = "2021"\n`,
    "core/Cargo.toml":
      '[package]\nname = "probe-core"\nversion.workspace = true\nedition.workspace = true\n',
    "core/src/lib.rs": "",
    "host/Cargo.toml":
      '[package]\nname = "probe-host"\nversion.workspace = true\nedition.workspace = true\n\n[dependencies]\nprobe-core = { path = "../core" }\n',
    "host/src/main.rs": "fn main() {}\n",
    "core/fuzz/Cargo.toml":
      '[package]\nname = "probe-fuzz"\nversion = "0.0.0"\nedition = "2021"\n\n[workspace]\n\n[dependencies]\nprobe-core = { path = ".." }\n',
    "core/fuzz/src/lib.rs": "",
    "package.json": '{ "name": "probe", "private": true, "workspaces": ["ext"] }\n',
    "ext/package.json": `{ "name": "probe-ext", "version": "${version}", "private": true }\n`,
  };
}

const CARGO_MANIFESTS = ["Cargo.toml", "core/fuzz/Cargo.toml"];

/** Exit codes of `cargo metadata --locked` per manifest: 0 fresh, 101 when the lockfile lags. */
function lockedExits(dir: string): number[] {
  return CARGO_MANIFESTS.map(
    (manifest) =>
      run(
        dir,
        "cargo",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--manifest-path",
        manifest,
      ).exitCode,
  );
}

/** A committed scratch repository whose lockfiles match version 0.1.0. */
function lockedRepo(): string {
  const dir = scratch.dir("refresh-lockfiles");
  writeTree(dir, manifests("0.1.0"));
  // The CI image installs rustup with no default toolchain, so outside the repo tree cargo has nothing to
  // run ("rustup could not choose a version of cargo"); the scratch workspace carries the repo's pin.
  writeFileSync(
    join(dir, "rust-toolchain.toml"),
    readFileSync(join(repoRoot, "rust-toolchain.toml")),
  );
  for (const manifest of CARGO_MANIFESTS) {
    must(dir, "cargo", "generate-lockfile", "--offline", "--manifest-path", manifest);
  }
  must(dir, "bun", "install", "--lockfile-only");
  must(dir, "git", "init", "--quiet");
  must(dir, "git", "config", "user.name", "example-user");
  must(dir, "git", "config", "user.email", "example-user@example.com");
  must(dir, "git", "add", "--all");
  must(dir, "git", "commit", "--quiet", "--message", "fixture at 0.1.0");
  return dir;
}

test("a bumped workspace re-locks into one lockfile-only commit; a fresh one gets no commit", async () => {
  const dir = lockedRepo();
  writeTree(dir, manifests("0.2.0"));
  expect(lockedExits(dir), "the incident: the bump alone fails --locked on both manifests").toEqual(
    [101, 101],
  );

  expect(await refreshLockfiles(dir, env)).toEqual({
    changed: ["Cargo.lock", "bun.lock", "core/fuzz/Cargo.lock"],
    committed: true,
  });
  expect(lockedExits(dir)).toEqual([0, 0]);
  expect(readFileSync(join(dir, "bun.lock"), "utf8")).toContain('"version": "0.2.0"');
  expect(must(dir, "git", "show", "--format=%s", "--name-only", "HEAD")).toBe(
    `${COMMIT_SUBJECT}\n\nCargo.lock\nbun.lock\ncore/fuzz/Cargo.lock\n`,
  );
  expect(
    must(dir, "git", "status", "--porcelain"),
    "the bumped manifests stay for the release commit",
  ).toBe(" M Cargo.toml\n M ext/package.json\n");

  const head = must(dir, "git", "rev-parse", "HEAD");
  expect(await refreshLockfiles(dir, env)).toEqual({ changed: [], committed: false });
  expect(must(dir, "git", "rev-parse", "HEAD")).toBe(head);
});
