#!/usr/bin/env bun

// Assert the signing/entitlement chain of the built desktop bundle (Phase 6
// signing spike, ADR-0026). The bundled host binary is the Secure Enclave
// toucher, so its signature is a security surface, not a packaging detail:
//
//   - the .app passes `codesign --verify --deep --strict`, and the app
//     binary, the helper bundle, and the host binary verify individually
//   - everything is signed by the expected Team ID
//   - the host (helper bundle main executable) carries EXACTLY its own
//     entitlements (application-identifier + keychain-access-groups) and the
//     app binary exactly its own (application-identifier only)
//   - `com.apple.security.get-task-allow` is absent from EVERY Mach-O in the
//     bundle (all executables are swept, not just the two known ones): it
//     would let any same-user process attach a debugger to the
//     Enclave-holding process, a zero-trust regression (fails the build if
//     it ever appears)
//   - both embedded provisioning profiles authorize the full chain on this
//     machine (identifier, team, keychain group, device) and have not
//     expired (free-tier profiles die after 7 days; without a live one macOS
//     SIGKILLs the entitled binaries at exec)
//
// Exits non-zero on any mismatch. Run standalone or via `moon run check-app-signing`.
// An optional argument points at a different .app to verify (scripts/
// desktop-bundle.ts re-runs this against the copy inside the mounted .dmg); the default is the
// deliverable copy in build/app/.

import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { profileProblems, provisioningUdid, readProvisioningProfile } from "./provisioning.ts";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

// The signing identity anchors. TEAM_ID is the certificate's OU
// ("Apple Development: vivswanshah@icloud.com", Team 3ZMH96L4V9); BUNDLE_ID
// must equal tauri.conf.json's `identifier` (asserted below).
const TEAM_ID = "3ZMH96L4V9";
const BUNDLE_ID = "com.vivswan.chromium-bridge";
const APP_IDENTIFIER = `${TEAM_ID}.${BUNDLE_ID}`;

const appPath = process.argv[2]
  ? resolve(process.argv[2])
  : resolve(root, "build/app/Chromium Bridge.app");
const appBinary = resolve(appPath, "Contents/MacOS/chromium-bridge-desktop");
const helperBundle = resolve(appPath, "Contents/Helpers/chromium-bridge.app");
const hostBinary = resolve(helperBundle, "Contents/MacOS/chromium-bridge");

const expectedHostEntitlements = {
  "com.apple.application-identifier": APP_IDENTIFIER,
  "keychain-access-groups": [APP_IDENTIFIER],
};
const expectedAppEntitlements = {
  "com.apple.application-identifier": APP_IDENTIFIER,
};

let failed = false;
function problem(message: string): void {
  console.error(`error: ${message}`);
  failed = true;
}

function run(cmd: string[], stdin?: string): { ok: boolean; stdout: string; stderr: string } {
  const proc = Bun.spawnSync(cmd, {
    stdin: stdin === undefined ? "ignore" : new TextEncoder().encode(stdin),
  });
  return {
    ok: proc.exitCode === 0,
    stdout: proc.stdout.toString(),
    stderr: proc.stderr.toString(),
  };
}

// Entitlements of a signed binary, as parsed JSON (codesign emits an XML
// plist; plutil converts it). An unsigned or entitlement-free binary yields
// empty output, reported as {}.
function entitlementsOf(path: string): Record<string, unknown> {
  const dump = run(["codesign", "-d", "--entitlements", "-", "--xml", path]);
  if (!dump.ok) {
    problem(`codesign --entitlements failed for ${path}: ${dump.stderr.trim()}`);
    return {};
  }
  if (dump.stdout.trim() === "") return {};
  const json = run(["plutil", "-convert", "json", "-o", "-", "--", "-"], dump.stdout);
  if (!json.ok) {
    problem(`plutil could not parse the entitlements of ${path}: ${json.stderr.trim()}`);
    return {};
  }
  return JSON.parse(json.stdout) as Record<string, unknown>;
}

function teamIdOf(path: string): string | undefined {
  // codesign -dv prints details to stderr.
  return run(["codesign", "-dv", path]).stderr.match(/^TeamIdentifier=(.+)$/m)?.[1];
}

// sha256 of the leaf certificate that signed a binary. codesign writes the
// chain as codesign0 (leaf) .. codesignN into the working directory, so run
// it in a throwaway temp dir.
function leafCertSha256(path: string): string | undefined {
  const dir = mkdtempSync(join(tmpdir(), "cb-signing-check-"));
  try {
    const proc = Bun.spawnSync(["codesign", "-d", "--extract-certificates", path], { cwd: dir });
    if (proc.exitCode !== 0) return undefined;
    return createHash("sha256")
      .update(readFileSync(join(dir, "codesign0")))
      .digest("hex");
  } catch {
    return undefined;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// AMFI only honors a profile for binaries signed by a certificate the
// profile lists in DeveloperCertificates. Team, identifier, and entitlements
// agreeing is not enough: a renewed free-tier certificate with the same name
// fails at exec until a profile minted for it exists. Catch that here
// instead of shipping it.
function assertProfileCoversSigner(label: string, profilePath: string, binary: string): void {
  const profile = readProvisioningProfile(profilePath);
  if (profile === undefined) return; // assertProfile already reported it
  const leaf = leafCertSha256(binary);
  if (leaf === undefined) {
    problem(`could not extract the signing certificate of ${binary}`);
    return;
  }
  const authorized = profile.developerCertificates.map((b64) =>
    createHash("sha256").update(Buffer.from(b64, "base64")).digest("hex"),
  );
  if (!authorized.includes(leaf)) {
    problem(
      `${label} does not authorize the certificate that signed ${binary}\n` +
        `  signer leaf sha256 ${leaf}\n` +
        `  profile authorizes ${authorized.join(", ") || "none"}\n` +
        "  (re-mint the profile for the current certificate via Xcode, see ADR-0026)",
    );
  }
}

function assertEntitlements(label: string, path: string, expected: Record<string, unknown>): void {
  const actual = entitlementsOf(path);
  if ("com.apple.security.get-task-allow" in actual) {
    problem(`${label} carries com.apple.security.get-task-allow (debugger-attach regression)`);
  }
  const want = JSON.stringify(Object.entries(expected).sort());
  const got = JSON.stringify(Object.entries(actual).sort());
  if (want !== got) {
    problem(
      `${label} entitlements drifted:\n  expected ${JSON.stringify(expected)}\n  actual   ${JSON.stringify(actual)}`,
    );
  }
}

// A provisioning profile must authorize the full entitlement chain;
// anything less means AMFI kills the entitled process at exec. deviceUdid
// is undefined when PROVISION_PROFILE_PATH supplied the profile (a CI
// runner is never in the device list; AMFI still enforces coverage on the
// machine that runs the app).
function assertProfile(label: string, path: string, deviceUdid: string | undefined): void {
  if (!existsSync(path)) {
    problem(`${label} is missing (${path})`);
    return;
  }
  const profile = readProvisioningProfile(path);
  if (profile === undefined) {
    problem(`${label} could not be decoded (${path})`);
    return;
  }
  for (const p of profileProblems(profile, {
    appIdentifier: APP_IDENTIFIER,
    teamId: TEAM_ID,
    keychainGroup: APP_IDENTIFIER,
    deviceUdid,
  })) {
    problem(`${label}: ${p}`);
  }
  if (profile.expires.getTime() - Date.now() < 24 * 60 * 60 * 1000) {
    console.warn(`warning: ${label} expires within 24h (${profile.expires.toISOString()})`);
  }
}

// Every Mach-O in the bundle, by magic number (thin or fat, either
// endianness). The named binaries get exact-entitlement asserts; this sweep
// backs the "no get-task-allow anywhere" claim.
const MACH_O_MAGICS = new Set([
  0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca,
]);
function isMachO(path: string): boolean {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return false;
  }
  try {
    const head = Buffer.alloc(4);
    if (readSync(fd, head, 0, 4, 0) < 4) return false;
    return MACH_O_MAGICS.has(head.readUInt32BE(0));
  } finally {
    closeSync(fd);
  }
}

function machOFilesUnder(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const stat = statSync(path, { throwIfNoEntry: false });
    if (stat === undefined) continue;
    if (stat.isDirectory()) found.push(...machOFilesUnder(path));
    else if (stat.isFile() && isMachO(path)) found.push(path);
  }
  return found;
}

// The config's identifier is what becomes CFBundleIdentifier; keep this
// script and tauri.conf.json agreeing on one value.
const tauriConf = JSON.parse(
  await Bun.file(resolve(root, "src/apps/desktop/tauri.conf.json")).text(),
) as { identifier?: unknown };
if (tauriConf.identifier !== BUNDLE_ID) {
  problem(`tauri.conf.json identifier ${String(tauriConf.identifier)} != ${BUNDLE_ID}`);
}

if (!existsSync(appPath)) {
  console.error(`error: ${appPath} not found; build it first with \`moon run bundle-app\``);
  process.exit(1);
}
if (!existsSync(hostBinary)) {
  problem("the bundled host binary is missing from Contents/Helpers/chromium-bridge.app");
}

const deepVerify = run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", appPath]);
if (!deepVerify.ok) {
  problem(`codesign --verify --deep --strict failed for the .app:\n${deepVerify.stderr.trim()}`);
}
for (const [label, path] of [
  ["app binary", appBinary],
  ["helper bundle", helperBundle],
  ["bundled host", hostBinary],
] as const) {
  const verify = run(["codesign", "--verify", "--strict", path]);
  if (!verify.ok) problem(`codesign --verify failed for the ${label}: ${verify.stderr.trim()}`);
  const team = teamIdOf(path);
  if (team !== TEAM_ID) problem(`${label} TeamIdentifier=${team ?? "none"}, expected ${TEAM_ID}`);
}

assertEntitlements("bundled host", hostBinary, expectedHostEntitlements);
assertEntitlements("app binary", appBinary, expectedAppEntitlements);

// The sweep behind "no get-task-allow anywhere": every Mach-O in the bundle,
// including any the bundler or a future change might add.
for (const path of machOFilesUnder(appPath)) {
  if ("com.apple.security.get-task-allow" in entitlementsOf(path)) {
    problem(`${path} carries com.apple.security.get-task-allow (debugger-attach regression)`);
  }
}

const helperProfile = resolve(helperBundle, "Contents/embedded.provisionprofile");
const appProfile = resolve(appPath, "Contents/embedded.provisionprofile");

const suppliedProfilePath = process.env.PROVISION_PROFILE_PATH;
if (suppliedProfilePath) {
  // The env var is not a bare bypass: the embedded profiles must be byte-
  // identical to the supplied file, and only then is the this-device check
  // skipped (a CI runner is never in the device list; AMFI still enforces
  // coverage on whatever Mac runs the app).
  console.log(
    "PROVISION_PROFILE_PATH set: this-device check skipped; the app runs only on Macs the embedded profile provisions",
  );
  let supplied: Buffer | undefined;
  try {
    supplied = readFileSync(suppliedProfilePath);
  } catch {
    problem(`PROVISION_PROFILE_PATH is not readable (${suppliedProfilePath})`);
  }
  if (supplied !== undefined) {
    for (const [label, path] of [
      ["helper embedded.provisionprofile", helperProfile],
      ["app embedded.provisionprofile", appProfile],
    ] as const) {
      if (!existsSync(path) || !supplied.equals(readFileSync(path))) {
        problem(`${label} is not the profile PROVISION_PROFILE_PATH supplied`);
      }
    }
  }
  assertProfile("helper embedded.provisionprofile", helperProfile, undefined);
  assertProfile("app embedded.provisionprofile", appProfile, undefined);
} else {
  const udid = provisioningUdid();
  if (udid === undefined) {
    problem("could not determine this Mac's provisioning UDID (system_profiler)");
  } else {
    assertProfile("helper embedded.provisionprofile", helperProfile, udid);
    assertProfile("app embedded.provisionprofile", appProfile, udid);
  }
}

assertProfileCoversSigner("helper embedded.provisionprofile", helperProfile, hostBinary);
assertProfileCoversSigner("app embedded.provisionprofile", appProfile, appBinary);

// Gatekeeper status is informational for a local dev build (no notarization;
// publishing is on hold): record what spctl says without gating on it.
const spctl = run(["spctl", "--assess", "--type", "execute", "--verbose=2", appPath]);
console.log(`spctl (informational): ${(spctl.stderr || spctl.stdout).trim() || "no output"}`);

if (failed) process.exit(1);
console.log(`desktop bundle signing verified (${appPath})`);
console.log(`  host: own entitlements exact, no get-task-allow, Team ${TEAM_ID}, live profile`);
console.log(`  app:  entitlements exact, no get-task-allow, Team ${TEAM_ID}, live profile`);
