#!/usr/bin/env bun

// update-release.yml's release legs. The tag arrives through RELEASE_TAG and is held to the release
// grammar (vMAJOR.MINOR.PATCH[-suffix]) before it names a file or reaches a gh argument.
//
//   verify-tag     the tag's core equals Cargo.toml's version                                  (binaries and sbom jobs)
//   archive        the release archive for this leg, RELEASE.txt, and the two checksum files      (binaries job)
//   extension-zip  the standalone extension bundle zip and its checksum; output name            (macos leg only)
//   prerelease     a suffixed tag flags the draft release as a prerelease                       (mark-prerelease job)

import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  cargoVersion,
  die,
  type Env,
  githubOutput,
  repoRoot,
  requiredEnv,
  selectMode,
} from "./lib.ts";

export interface ReleaseTag {
  tag: string;
  /** MAJOR.MINOR.PATCH, the part Cargo.toml carries. */
  core: string;
  /** A tag with a suffix (v0.1.0-dev, v1.0.0-rc.1) is a prerelease. */
  prerelease: boolean;
}

const grammar = /^v(\d+\.\d+\.\d+)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$/;

export function parseTag(tag: string): ReleaseTag {
  const match = grammar.exec(tag);
  if (!match) throw new Error(`refusing malformed release tag: ${tag}`);
  return { tag, core: match[1] as string, prerelease: match[2] !== undefined };
}

export function verifyTag(tag: string, cargo: string): ReleaseTag {
  const parsed = parseTag(tag);
  if (parsed.core !== cargo) throw new Error(`tag core ${parsed.core} != Cargo version ${cargo}`);
  return parsed;
}

/** The line `sha256sum -c` and `shasum -c` read: the hex digest, two spaces, the bare file name. */
export function checksumLine(bytes: Uint8Array, name: string): string {
  return `${createHash("sha256").update(bytes).digest("hex")}  ${name}\n`;
}

/**
 * RELEASE.txt records which release an archive came from, so a user verifying by hand picks the matching
 * published checksum and provenance attestation (SECURITY.md, "Release artifact integrity").
 */
export function releaseText(
  repository: string,
  tag: string,
  platform: string,
  arch: string,
): string {
  return `repo=${repository}\ntag=${tag}\nplatform=${platform}\narch=${arch}\n`;
}

export interface Plan {
  name: string;
  binaryFile: string;
  archive: string;
  /** The archiver, run from the repository root. */
  archiver: string[];
}

/** Windows ships a zip made by the runner's 7z; the other legs a tarball. */
export function packagingPlan(tag: string, platform: string, arch: string): Plan {
  const name = `chromium-bridge-${tag}-${platform}-${arch}`;
  if (platform === "windows") {
    const archive = `${name}.zip`;
    return {
      name,
      binaryFile: "chromium-bridge.exe",
      archive,
      archiver: ["7z", "a", "-tzip", archive, name],
    };
  }
  const archive = `${name}.tar.gz`;
  return { name, binaryFile: "chromium-bridge", archive, archiver: ["tar", "czf", archive, name] };
}

/** A tool run from `cwd`; a nonzero exit throws. Injected so a test can stand in for tar, 7z, and zip. */
export type RunTool = (argv: string[], cwd: string) => void;

export const archiveOutputs = ["name", "archive", "sha256file", "binary", "binsha256file"] as const;

export function packageArchive(
  root: string,
  env: Env,
  plan: Plan,
  releaseTxt: string,
  run: RunTool,
): void {
  const stage = join(root, plan.name);
  mkdirSync(join(stage, "extension"), { recursive: true });
  cpSync(join(root, "build/extension/chrome-mv3"), join(stage, "extension/dist"), {
    recursive: true,
  });
  for (const file of ["LICENSE.md", "README.md", `target/release/${plan.binaryFile}`]) {
    cpSync(join(root, file), join(stage, file.slice(file.lastIndexOf("/") + 1)));
  }
  writeFileSync(join(stage, "RELEASE.txt"), releaseTxt);
  run(plan.archiver, root);
  writeFileSync(
    join(root, `${plan.archive}.sha256`),
    checksumLine(readFileSync(join(root, plan.archive)), plan.archive),
  );
  // The per-binary checksum is published on its own so the binary can be verified after extraction, where
  // the archive's checksum no longer applies; its recorded name is the bare binary, as it sits on disk then.
  const binarySha256 = `${plan.name}.binary.sha256`;
  writeFileSync(
    join(root, binarySha256),
    checksumLine(readFileSync(join(stage, plan.binaryFile)), plan.binaryFile),
  );
  const records: Record<(typeof archiveOutputs)[number], string> = {
    name: plan.name,
    archive: plan.archive,
    sha256file: `${plan.archive}.sha256`,
    binary: `${plan.name}/${plan.binaryFile}`,
    binsha256file: binarySha256,
  };
  for (const output of archiveOutputs) githubOutput(output, records[output], env);
}

/** The built bundle under a top-level `dist/`, so "Load unpacked" takes the extracted directory as is. */
export function packageExtensionZip(root: string, env: Env, tag: string, run: RunTool): void {
  const name = `chromium-bridge-extension-${tag}`;
  const staging = join(root, "dist-zip");
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging);
  cpSync(join(root, "build/extension/chrome-mv3"), join(staging, "dist"), { recursive: true });
  run(["zip", "-r", join("..", `${name}.zip`), "dist"], staging);
  writeFileSync(
    join(root, `${name}.zip.sha256`),
    checksumLine(readFileSync(join(root, `${name}.zip`)), `${name}.zip`),
  );
  githubOutput("name", name, env);
}

export function flagPrerelease(release: ReleaseTag, cwd: string, run: RunTool): string {
  if (!release.prerelease) return "final release tag; nothing to flag";
  run(["gh", "release", "edit", release.tag, "--prerelease"], cwd);
  return `${release.tag} flagged as a prerelease`;
}

const runTool: RunTool = (argv, cwd) => {
  const run = Bun.spawnSync(argv, { cwd, stdout: "ignore", stderr: "inherit" });
  if (run.exitCode !== 0) throw new Error(`${argv.join(" ")} exited ${run.exitCode}`);
};

const modes: Record<string, () => void> = {
  "verify-tag"() {
    const cargo = cargoVersion();
    const release = verifyTag(requiredEnv("RELEASE_TAG"), cargo);
    console.log(`tag=${release.tag} core=${release.core} cargo=${cargo}`);
  },
  archive() {
    const release = verifyTag(requiredEnv("RELEASE_TAG"), cargoVersion());
    const [platform, arch] = [requiredEnv("PLATFORM"), requiredEnv("ARCH")];
    const plan = packagingPlan(release.tag, platform, arch);
    const text = releaseText(requiredEnv("GITHUB_REPOSITORY"), release.tag, platform, arch);
    packageArchive(repoRoot, process.env, plan, text, runTool);
  },
  "extension-zip"() {
    const release = verifyTag(requiredEnv("RELEASE_TAG"), cargoVersion());
    packageExtensionZip(repoRoot, process.env, release.tag, runTool);
  },
  prerelease() {
    console.log(flagPrerelease(parseTag(requiredEnv("RELEASE_TAG")), repoRoot, runTool));
  },
};

if (import.meta.main) {
  const run = selectMode(modes, process.argv.slice(2), "scripts/release-package.ts");
  try {
    run();
  } catch (error) {
    die((error as Error).message);
  }
}
