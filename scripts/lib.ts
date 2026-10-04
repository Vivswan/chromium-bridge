// Shared helpers for the chromium-bridge TypeScript tooling scripts.
//
// scripts/build-repro.ts and scripts/fuzz-smoke.ts deliberately do NOT import this file: they stay
// self-contained on node builtins so they run before `bun install` (the release workflow builds the binary
// first, and the nightly fuzz job never installs the workspace).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Repo root, derived from this file's location (scripts/ is a direct child).
export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

// The JSON manifests that carry a copy of the crate version (Cargo.toml is the source of truth). The
// release PR bumps each one through release-please-config.json's extra-files; scripts/check-version.ts
// requires that coverage and verifies the copies agree. Add new version copies here, nowhere else.
export const versionedJsonFiles = ["src/apps/extension/package.json"] as const;

// Print an error to stderr and exit.
export function die(message: string, exitCode = 1): never {
  console.error(`error: ${message}`);
  process.exit(exitCode);
}

// The crate version from the workspace Cargo.toml: `[workspace.package] version`.
export function cargoVersion(): string {
  const toml = Bun.TOML.parse(readFileSync(join(repoRoot, "Cargo.toml"), "utf8")) as {
    workspace?: { package?: { version?: unknown } };
  };
  const version = toml.workspace?.package?.version;
  if (typeof version !== "string") die("no version found under [workspace.package] in Cargo.toml");
  return version;
}

// The "version" string from a JSON file. ("manifest_version" is a distinct
// key; JSON.parse reads the real field, not a textual match.)
export function jsonVersion(path: string): string {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as { version?: unknown };
  if (typeof parsed.version !== "string") die(`no "version" string in ${path}`);
  return parsed.version;
}

// The environment for a git spawned in a scratch repository by a test: `base` minus every GIT_* variable. A
// pre-commit hook exports GIT_DIR and GIT_INDEX_FILE, so an inheriting child acts on the repository under
// commit: a scratch `git init` re-initialised the shared .git (core.bare flipped to true) and a scratch
// `git add` rewrote the worktree index. The real gates keep the inherited env on purpose: a partial commit
// (`git commit --only`) is judged on the hook's temporary index, not the ordinary one.
export function gitEnv(base: NodeJS.ProcessEnv = process.env): Record<string, string> {
  return Object.fromEntries(
    Object.entries(base).filter(
      (entry): entry is [string, string] => !entry[0].startsWith("GIT_") && entry[1] !== undefined,
    ),
  );
}
