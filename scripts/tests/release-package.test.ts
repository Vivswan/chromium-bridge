import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot, Scratch, writeTree } from "../lib.ts";
import {
  archiveOutputs,
  checksumDigest,
  checksumLine,
  flagPrerelease,
  formulaOutputs,
  installerOutputs,
  installerPlan,
  packageArchive,
  packageExtensionZip,
  packageInstaller,
  packagingPlan,
  parseTag,
  pkgIdentifier,
  type RunTool,
  releaseText,
  verifyTag,
  writeTapFormula,
} from "../release-package.ts";
import { stepOutputFile, stepOutputs } from "./step-outputs.ts";

// What would drift silently: the release grammar that keeps a tag safe as a file name and a gh argument,
// the checksum line `sha256sum -c` reads, the RELEASE.txt a user verifies by hand against SECURITY.md, and
// the step outputs update-release.yml reads from the pkg step. None of them is enforced by anything else.

const scratch = new Scratch();
afterAll(() => scratch.remove());
afterEach(() => {
  delete process.env.GITHUB_OUTPUT;
});

const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");

describe("the tag grammar: vMAJOR.MINOR.PATCH with an optional dotted suffix", () => {
  test.each<[string, { core: string; prerelease: boolean } | "malformed"]>([
    ["v1.2.3", { core: "1.2.3", prerelease: false }],
    ["v0.1.0-dev", { core: "0.1.0", prerelease: true }],
    ["v1.0.0-rc.1", { core: "1.0.0", prerelease: true }],
    ["1.2.3", "malformed"],
    ["v1.2", "malformed"],
    ["v1.2.3-", "malformed"],
    ["v1.2.3-rc_1", "malformed"],
    ["v1.2.3 ", "malformed"],
    ["v1.2.3/../x", "malformed"],
    ["", "malformed"],
  ])("%s", (tag, outcome) => {
    if (outcome === "malformed") {
      expect(() => parseTag(tag)).toThrow(`refusing malformed release tag: ${tag}`);
    } else {
      expect(parseTag(tag)).toEqual({ tag, ...outcome });
    }
  });

  test("the core must equal Cargo.toml's version, suffix aside", () => {
    expect(verifyTag("v1.2.3-rc.1", "1.2.3")).toEqual({
      tag: "v1.2.3-rc.1",
      core: "1.2.3",
      prerelease: true,
    });
    expect(() => verifyTag("v1.2.4", "1.2.3")).toThrow("tag core 1.2.4 != Cargo version 1.2.3");
  });
});

test("a suffixed tag reaches gh as one argument of `release edit --prerelease`; a final tag runs no gh", () => {
  const calls: { argv: string[]; cwd: string }[] = [];
  const run: RunTool = (argv, cwd) => {
    calls.push({ argv, cwd });
  };
  expect({
    suffixed: flagPrerelease(parseTag("v1.0.0-rc.1"), "/repo", run),
    final: flagPrerelease(parseTag("v1.0.0"), "/repo", run),
    calls,
  }).toEqual({
    suffixed: "v1.0.0-rc.1 flagged as a prerelease",
    final: "final release tag; nothing to flag",
    calls: [{ argv: ["gh", "release", "edit", "v1.0.0-rc.1", "--prerelease"], cwd: "/repo" }],
  });
});

function builtCheckout(binaryFile: string): string {
  const root = scratch.dir("release-package");
  writeTree(root, {
    [`target/release/${binaryFile}`]: "binary bytes",
    "build/extension/chrome-mv3/manifest.json": '{"manifest_version":3}\n',
    "LICENSE.md": "license\n",
    "README.md": "readme\n",
  });
  return root;
}

function fakeArchiver(calls: { argv: string[]; cwd: string }[]): RunTool {
  return (argv, cwd) => {
    calls.push({ argv, cwd });
    const archive =
      argv[0] === "zip" ? (argv[2] as string) : (argv[argv[0] === "7z" ? 3 : 2] as string);
    writeFileSync(join(cwd, archive), `archive of ${argv.at(-1)}`);
  };
}

describe("packageArchive", () => {
  test.each<[string, string, string, string[]]>([
    ["linux", "x64", "genkan", ["tar", "czf"]],
    ["macos", "arm64", "genkan", ["tar", "czf"]],
    ["windows", "x64", "genkan.exe", ["7z", "a", "-tzip"]],
  ])(
    "%s-%s: the staged tree, RELEASE.txt, both checksum files, and the step outputs",
    (platform, arch, binaryFile, archiverHead) => {
      const root = builtCheckout(binaryFile);
      const output = stepOutputFile(root);
      const calls: { argv: string[]; cwd: string }[] = [];
      const plan = packagingPlan("v1.2.3", platform, arch);
      const text = releaseText("example-user/repo", "v1.2.3", platform, arch);

      packageArchive(root, plan, text, fakeArchiver(calls));

      const name = `genkan-v1.2.3-${platform}-${arch}`;
      const archive = platform === "windows" ? `${name}.zip` : `${name}.tar.gz`;
      const read = (file: string) => readFileSync(join(root, file), "utf8");
      expect({
        staged: [
          `${name}/extension/dist/manifest.json`,
          `${name}/LICENSE.md`,
          `${name}/README.md`,
          `${name}/${binaryFile}`,
        ].map((file) => existsSync(join(root, file))),
        releaseTxt: read(`${name}/RELEASE.txt`),
        archiver: calls,
        archiveSha256: read(`${archive}.sha256`),
        binarySha256: read(`${name}.binary.sha256`),
        outputs: stepOutputs(output),
      }).toEqual({
        staged: [true, true, true, true],
        releaseTxt: `repo=example-user/repo\ntag=v1.2.3\nplatform=${platform}\narch=${arch}\n`,
        archiver: [{ argv: [...archiverHead, archive, name], cwd: root }],
        archiveSha256: `${sha256(`archive of ${name}`)}  ${archive}\n`,
        binarySha256: `${sha256("binary bytes")}  ${binaryFile}\n`,
        outputs: {
          name,
          archive,
          sha256file: `${archive}.sha256`,
          binary: `${name}/${binaryFile}`,
          binsha256file: `${name}.binary.sha256`,
        },
      });
    },
  );

  test("every `steps.pkg.outputs.<x>` update-release.yml reads is a record the archive mode writes", () => {
    const workflow = readFileSync(join(repoRoot, ".github/workflows/update-release.yml"), "utf8");
    const read = new Set(
      [...workflow.matchAll(/steps\.pkg\.outputs\.([a-z0-9_-]+)/g)].map((m) => m[1]),
    );
    expect(read.size).toBeGreaterThan(0);
    expect([...read].sort()).toEqual([...new Set(archiveOutputs)].sort());
  });
});

describe("packageInstaller", () => {
  // pkgbuild and the MSI ProductVersion refuse a prerelease suffix, so the tools get the tag's core while
  // the file names keep the full tag. A fake tool stands in for pkgbuild, cargo-deb, candle and light,
  // which exist only on their own runners.
  //   the binary inside each installer  -> the attested one, copied unchanged (never rebuilt or stripped)
  //   the checksum                       -> names the installer as it sits on disk
  const release = parseTag("v1.2.3-rc.1");
  const fakeTool = (calls: { argv: string[]; cwd: string }[]): RunTool => {
    return (argv, cwd) => {
      calls.push({ argv, cwd });
      const out = argv.indexOf("-out") === -1 ? argv.indexOf("--output") : argv.indexOf("-out");
      const produced = argv[0] === "pkgbuild" ? (argv.at(-1) as string) : (argv[out + 1] as string);
      writeFileSync(join(cwd, produced), `installer from ${argv[0]}`);
    };
  };

  test.each<[string, string, string, string[][]]>([
    [
      "macos",
      "arm64",
      "pkg",
      [
        [
          "pkgbuild",
          "--root",
          "pkg-root",
          "--identifier",
          pkgIdentifier,
          "--version",
          "1.2.3",
          "--install-location",
          "/",
          "--scripts",
          "packaging/pkg/scripts",
          "genkan-v1.2.3-rc.1-macos-arm64.pkg",
        ],
      ],
    ],
    [
      "linux",
      "x64",
      "deb",
      [
        [
          "cargo",
          "deb",
          "--no-build",
          "--no-strip",
          "--package",
          "genkan",
          "--output",
          "genkan-v1.2.3-rc.1-linux-x64.deb",
        ],
      ],
    ],
    [
      "windows",
      "x64",
      "msi",
      [
        [
          "candle.exe",
          "-nologo",
          "-arch",
          "x64",
          "-dVersion=1.2.3",
          "-dBinary=target/release/genkan.exe",
          "-out",
          "genkan.wixobj",
          "packaging/msi/genkan.wxs",
        ],
        [
          "light.exe",
          "-nologo",
          "-spdb",
          "-ext",
          "WixUtilExtension",
          "-out",
          "genkan-v1.2.3-rc.1-windows-x64.msi",
          "genkan.wixobj",
        ],
      ],
    ],
  ])(
    "%s-%s: the staged binary, the tool calls, the checksum, and the outputs",
    (platform, arch, ext, tools) => {
      const root = builtCheckout(platform === "windows" ? "genkan.exe" : "genkan");
      const output = stepOutputFile(root);
      const calls: { argv: string[]; cwd: string }[] = [];
      const plan = installerPlan(release, platform, arch);

      packageInstaller(root, plan, fakeTool(calls));

      const installer = `genkan-v1.2.3-rc.1-${platform}-${arch}.${ext}`;
      const stagedBinary = join(root, "pkg-root/usr/local/bin/genkan");
      expect({
        staged:
          platform === "macos" ? readFileSync(stagedBinary, "utf8") : existsSync(stagedBinary),
        tools: calls,
        sha256: readFileSync(join(root, `${installer}.sha256`), "utf8"),
        outputs: stepOutputs(output),
      }).toEqual({
        staged: platform === "macos" ? "binary bytes" : false,
        tools: tools.map((argv) => ({ argv, cwd: root })),
        sha256: `${sha256(`installer from ${(tools.at(-1) as string[])[0]}`)}  ${installer}\n`,
        outputs: { installer, installersha256file: `${installer}.sha256` },
      });
    },
  );

  test("every `steps.installer.outputs.<x>` the two workflows read is a record the installer modes write", () => {
    const read = new Set<string>();
    for (const file of ["update-release.yml", "installers.yml"]) {
      const workflow = readFileSync(join(repoRoot, ".github/workflows", file), "utf8");
      for (const m of workflow.matchAll(/steps\.installer\.outputs\.([a-z0-9_-]+)/g)) {
        read.add(m[1] as string);
      }
    }
    expect(read.size).toBeGreaterThan(0);
    expect([...read].sort()).toEqual([...new Set(installerOutputs)].sort());
  });
});

describe("the Homebrew formula", () => {
  const linuxX64 = "b".repeat(64);
  const macosArm64 = "a".repeat(64);

  // Homebrew's Version ranks "1.2.3-rc.1" below "1.2.3" and "1.2.3-dev" above it (a dev formula would
  // pin the tap past the final release), so the tap sees final releases alone, at the core version.
  test.each<[string, boolean]>([
    ["v1.2.3-dev", false],
    ["v1.2.3-rc.1", false],
    ["v1.2.3", true],
  ])("%s -> bump %p", (tag, bump) => {
    const root = scratch.dir("tap-formula");
    const output = stepOutputFile(root);
    const path = join(root, "Formula", "genkan.rb");
    // The tap excludes prereleases, so the digest reader must not run for one.
    const written = writeTapFormula(
      parseTag(tag),
      () => {
        if (!bump) throw new Error("digests read for a prerelease");
        return { repository: "example-user/repo", macosArm64, linuxX64 };
      },
      path,
      writeFileSync,
    );
    expect({
      written,
      formula: existsSync(path) ? readFileSync(path, "utf8").includes('version "1.2.3"') : "none",
      output: stepOutputs(output),
    }).toEqual({ written: bump, formula: bump ? true : "none", output: { bump: String(bump) } });
  });

  test("every `steps.formula.outputs.<x>` update-release.yml reads is a record the brew-formula mode writes", () => {
    const workflow = readFileSync(join(repoRoot, ".github/workflows/update-release.yml"), "utf8");
    const read = new Set(
      [...workflow.matchAll(/steps\.formula\.outputs\.([a-z0-9_-]+)/g)].map((m) => m[1]),
    );
    expect(read.size).toBeGreaterThan(0);
    expect([...read].sort()).toEqual([...new Set(formulaOutputs)].sort());
  });

  test.each<[string, string | "refused"]>([
    [`${linuxX64}  genkan-v1.2.3-linux-x64.tar.gz\n`, linuxX64],
    [`${linuxX64.toUpperCase()}  file\n`, "refused"],
    [`${"b".repeat(63)}  file\n`, "refused"],
    [`${linuxX64} file\n`, "refused"],
    [`${linuxX64}  file\n${macosArm64}  other\n`, "refused"],
    ["", "refused"],
  ])("checksumDigest(%j)", (text, outcome) => {
    if (outcome === "refused") {
      expect(() => checksumDigest(text)).toThrow("not a checksum line");
    } else {
      expect(checksumDigest(text)).toBe(outcome);
    }
  });
});

test("the extension zip stages the bundle under dist/, zips from the staging dir, and writes its checksum", () => {
  const root = builtCheckout("genkan");
  const output = stepOutputFile(root);
  const calls: { argv: string[]; cwd: string }[] = [];

  packageExtensionZip(root, "v1.2.3", fakeArchiver(calls));

  const name = "genkan-extension-v1.2.3";
  expect({
    staged: existsSync(join(root, "dist-zip/dist/manifest.json")),
    zip: calls,
    sha256: readFileSync(join(root, `${name}.zip.sha256`), "utf8"),
    outputs: stepOutputs(output),
  }).toEqual({
    staged: true,
    zip: [{ argv: ["zip", "-r", `../${name}.zip`, "dist"], cwd: join(root, "dist-zip") }],
    sha256: `${sha256("archive of dist")}  ${name}.zip\n`,
    outputs: { name },
  });
});

test("checksumLine is the two-space form both sha256sum -c and shasum -c accept", () => {
  expect(checksumLine(Buffer.from("abc"), "file.tar.gz")).toBe(`${sha256("abc")}  file.tar.gz\n`);
});
