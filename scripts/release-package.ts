#!/usr/bin/env bun

// update-release.yml's release legs. The tag arrives through RELEASE_TAG and is held to the release
// grammar (vMAJOR.MINOR.PATCH[-suffix]) before it names a file or reaches a gh argument.
//
//   verify-tag           the tag's core equals Cargo.toml's version                            (binaries and sbom jobs)
//   archive              the release archive for this leg, RELEASE.txt, and the two checksum files (binaries job)
//   extension-zip        the standalone extension bundle zip and its checksum; output name      (macos leg only)
//   installer            this leg's .pkg, .deb, or .msi and its checksum; output installer     (binaries job)
//   installer-from-cargo the same installer for the version Cargo.toml carries, no tag needed  (installers.yml)
//   brew-formula         the tap formula from the two archive checksums, written to FORMULA_PATH; final tags
//                        alone, output bump                                                       (homebrew job)
//   prerelease           a suffixed tag flags the draft release as a prerelease                 (mark-prerelease job)

import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
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

export interface InstallerPlan {
  installer: string;
  /** Copied into place before the tools run: [source, destination], repo-relative. */
  staged: [string, string][];
  /** The packaging tools, in order, run from the repository root. */
  tools: string[][];
}

/**
 * The pkg's receipt identifier (`pkgutil --pkgs` lists it): the GitHub reverse-DNS form, since the project
 * has no domain and the `com.vivswan.*` family is the bridge's own identifiers (check-docs-literals).
 */
export const pkgIdentifier = "io.github.vivswan.chromium-bridge";

/**
 * Each installer wraps the already-built, attested binary unchanged: pkgbuild and WiX copy it, cargo-deb is
 * told not to build or strip. The .msi and .pkg versions take the tag's core: both formats refuse a
 * prerelease suffix.
 */
export function installerPlan(release: ReleaseTag, platform: string, arch: string): InstallerPlan {
  const name = `chromium-bridge-${release.tag}-${platform}-${arch}`;
  if (platform === "macos") {
    const installer = `${name}.pkg`;
    const root = "pkg-root";
    return {
      installer,
      staged: [["target/release/chromium-bridge", `${root}/usr/local/bin/chromium-bridge`]],
      tools: [
        [
          "pkgbuild",
          "--root",
          root,
          "--identifier",
          pkgIdentifier,
          "--version",
          release.core,
          "--install-location",
          "/",
          "--scripts",
          "packaging/pkg/scripts",
          installer,
        ],
      ],
    };
  }
  if (platform === "linux") {
    const installer = `${name}.deb`;
    return {
      installer,
      staged: [],
      tools: [
        [
          "cargo",
          "deb",
          "--no-build",
          "--no-strip",
          "--package",
          "chromium-bridge",
          "--output",
          installer,
        ],
      ],
    };
  }
  if (platform === "windows") {
    const installer = `${name}.msi`;
    const object = "chromium-bridge.wixobj";
    return {
      installer,
      staged: [],
      tools: [
        [
          "candle.exe",
          "-nologo",
          "-arch",
          "x64",
          `-dVersion=${release.core}`,
          "-dBinary=target/release/chromium-bridge.exe",
          "-out",
          object,
          "packaging/msi/chromium-bridge.wxs",
        ],
        ["light.exe", "-nologo", "-spdb", "-ext", "WixUtilExtension", "-out", installer, object],
      ],
    };
  }
  throw new Error(`no installer is defined for platform ${platform}`);
}

export const installerOutputs = ["installer", "installersha256file"] as const;

/** `true` when a formula was written. */
export const formulaOutputs = ["bump"] as const;

/**
 * Write the tap formula for a final release and report `bump`; a prerelease writes nothing. Homebrew's
 * Version ranks `1.2.3-rc.1` below `1.2.3` but `1.2.3-dev` above it, so a prerelease formula could pin the
 * tap at a version `brew upgrade` never leaves; the tap sees final releases alone.
 */
export function writeTapFormula(
  inputs: FormulaInputs,
  path: string,
  env: Env,
  write: (path: string, text: string) => void,
): boolean {
  if (inputs.release.prerelease) {
    githubOutput("bump", "false", env);
    return false;
  }
  mkdirSync(dirname(path), { recursive: true });
  write(path, brewFormula(inputs));
  githubOutput("bump", "true", env);
  return true;
}

export function packageInstaller(root: string, env: Env, plan: InstallerPlan, run: RunTool): void {
  for (const [source, destination] of plan.staged) {
    mkdirSync(dirname(join(root, destination)), { recursive: true });
    cpSync(join(root, source), join(root, destination));
  }
  for (const tool of plan.tools) run(tool, root);
  const sha256File = `${plan.installer}.sha256`;
  writeFileSync(
    join(root, sha256File),
    checksumLine(readFileSync(join(root, plan.installer)), plan.installer),
  );
  const records: Record<(typeof installerOutputs)[number], string> = {
    installer: plan.installer,
    installersha256file: sha256File,
  };
  for (const output of installerOutputs) githubOutput(output, records[output], env);
}

/** The digest of a checksum file written by `checksumLine`; anything else is refused, never guessed. */
export function checksumDigest(text: string): string {
  const match = /^([0-9a-f]{64}) {2}\S+\n$/.exec(text);
  if (!match) throw new Error(`not a checksum line: ${JSON.stringify(text)}`);
  return match[1] as string;
}

export interface FormulaInputs {
  repository: string;
  release: ReleaseTag;
  /** Digests of the two release archives the formula installs from. */
  macosArm64: string;
  linuxX64: string;
}

/**
 * The Homebrew formula over the release archives (brew strips the archive's single top-level directory, so
 * `bin.install` sees the binary by name). `post_install` is the binary's own registration: a failure there
 * leaves the install in place with brew's warning, and `brew postinstall` retries it.
 */
export function brewFormula(inputs: FormulaInputs): string {
  const base = `https://github.com/${inputs.repository}/releases/download/${inputs.release.tag}`;
  const archive = (platform: string, arch: string) =>
    `${base}/${packagingPlan(inputs.release.tag, platform, arch).archive}`;
  return `class ChromiumBridge < Formula
  desc "Authenticated MCP bridge to your real Chromium browsers"
  homepage "https://github.com/${inputs.repository}"
  version "${inputs.release.core}"
  license :cannot_represent

  on_macos do
    on_arm do
      url "${archive("macos", "arm64")}"
      sha256 "${inputs.macosArm64}"
    end
  end

  on_linux do
    on_intel do
      url "${archive("linux", "x64")}"
      sha256 "${inputs.linuxX64}"
    end
  end

  def install
    bin.install "chromium-bridge"
  end

  def post_install
    system bin/"chromium-bridge", "doctor", "--fix"
  end

  def caveats
    <<~EOS
      The post-install ran the registration for every detected Chromium browser. If it
      reported no browser, or refused one, fix the cause and run it again:
        chromium-bridge doctor --fix
    EOS
  end

  test do
    assert_equal "chromium-bridge ${inputs.release.core}", shell_output("#{bin}/chromium-bridge --version").strip
  end
end
`;
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
  installer() {
    const release = verifyTag(requiredEnv("RELEASE_TAG"), cargoVersion());
    const plan = installerPlan(release, requiredEnv("PLATFORM"), requiredEnv("ARCH"));
    packageInstaller(repoRoot, process.env, plan, runTool);
  },
  "installer-from-cargo"() {
    const release = parseTag(`v${cargoVersion()}`);
    const plan = installerPlan(release, requiredEnv("PLATFORM"), requiredEnv("ARCH"));
    packageInstaller(repoRoot, process.env, plan, runTool);
  },
  "brew-formula"() {
    const release = verifyTag(requiredEnv("RELEASE_TAG"), cargoVersion());
    const path = requiredEnv("FORMULA_PATH");
    if (release.prerelease) {
      writeTapFormula(
        { repository: "", release, macosArm64: "", linuxX64: "" },
        path,
        process.env,
        writeFileSync,
      );
      console.log(`${release.tag} is a prerelease; the tap receives final releases alone`);
      return;
    }
    const digest = (platform: string, arch: string) =>
      checksumDigest(
        readFileSync(
          join(repoRoot, `${packagingPlan(release.tag, platform, arch).archive}.sha256`),
          "utf8",
        ),
      );
    writeTapFormula(
      {
        repository: requiredEnv("GITHUB_REPOSITORY"),
        release,
        macosArm64: digest("macos", "arm64"),
        linuxX64: digest("linux", "x64"),
      },
      path,
      process.env,
      writeFileSync,
    );
    console.log(`formula written to ${path}`);
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
