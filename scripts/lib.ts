// Shared helpers for the chromium-bridge TypeScript tooling scripts.
// Import from scripts run via bun, e.g.:
//
//   import { repoRoot, cargoVersion } from "./lib.ts";
//
// (scripts/build-repro.ts and the CI-only .github/scripts/fuzz_smoke.ts
// deliberately do NOT import this file: they stay self-contained on node
// builtins so they run before `bun install` - the release workflow builds
// the binary first, and the nightly fuzz job never installs the workspace.)

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Repo root, derived from this file's location (scripts/ is a direct child).
export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

// Print an error to stderr and exit.
export function die(message: string, exitCode = 1): never {
  console.error(`error: ${message}`);
  process.exit(exitCode);
}

// The crate version from the workspace Cargo.toml (the single source of
// truth): the `version = "..."` entry inside the [workspace.package] section.
export function cargoVersion(): string {
  const toml = readFileSync(join(repoRoot, "Cargo.toml"), "utf8");
  let section = "";
  for (const line of toml.split("\n")) {
    const header = line.match(/^\[([^\]]+)\]/);
    if (header?.[1]) {
      section = header[1];
      continue;
    }
    if (section !== "workspace.package") continue;
    const version = line.match(/^version\s*=\s*"([^"]+)"/);
    if (version?.[1]) return version[1];
  }
  die("no version found under [workspace.package] in Cargo.toml");
}

// The "version" string from a JSON file. ("manifest_version" is a distinct
// key; JSON.parse reads the real field, not a textual match.)
export function jsonVersion(path: string): string {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as { version?: unknown };
  if (typeof parsed.version !== "string") die(`no "version" string in ${path}`);
  return parsed.version;
}
