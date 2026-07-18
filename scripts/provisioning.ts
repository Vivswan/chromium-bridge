// Provisioning-profile parsing and validation shared by the desktop signing
// scripts (scripts/desktop-bundle.ts stages a profile, scripts/
// check-desktop-signing.ts re-asserts the shipped one; ADR-0026).
//
// macOS only honors restricted entitlements (application-identifier,
// keychain-access-groups) when a provisioning profile authorizes the exact
// combination of team, identifier, entitlements, and device - anything less
// and AMFI SIGKILLs the process at exec. So validation here is fail-closed:
// a profile is usable only when every check passes.

import { readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface ProvisioningProfile {
  path: string;
  appIdentifier: string;
  keychainAccessGroups: string[];
  teamIds: string[];
  // base64 DER of each certificate the profile authorizes to sign; AMFI
  // rejects a binary signed by any other certificate, even same-team.
  developerCertificates: string[];
  hasGetTaskAllow: boolean;
  provisionsAllDevices: boolean;
  provisionedDevices: string[];
  expires: Date;
}

export interface ProfileExpectation {
  appIdentifier: string;
  teamId: string;
  keychainGroup: string;
  // undefined skips the this-device check: a CI runner signing for the
  // user's Mac is never in the profile's device list. AMFI still enforces
  // device coverage at exec on whatever machine runs the app, so skipping
  // the build-time check cannot widen what the profile authorizes.
  deviceUdid: string | undefined;
}

function capture(cmd: string[], stdin?: string): string | undefined {
  const proc = Bun.spawnSync(cmd, {
    stdin: stdin === undefined ? "ignore" : new TextEncoder().encode(stdin),
  });
  return proc.exitCode === 0 ? proc.stdout.toString() : undefined;
}

// One field out of a decoded profile plist, via plutil reading stdin (no
// temp files). `json` mode parses arrays/objects; `raw` mode returns scalars.
function extract(plist: string, keypath: string, mode: "raw" | "json"): string | undefined {
  return capture(["plutil", "-extract", keypath, mode, "-o", "-", "--", "-"], plist)?.trim();
}

function extractStringArray(plist: string, keypath: string): string[] {
  const json = extract(plist, keypath, "json");
  if (json === undefined) return [];
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === "string") : [];
  } catch {
    return [];
  }
}

// An array of <data> values, as base64 strings. plutil cannot render data in
// json mode, but raw mode prints an array's element count and a data
// element's base64, so index through the array.
function extractDataArray(plist: string, keypath: string): string[] {
  const count = Number(extract(plist, keypath, "raw"));
  if (!Number.isInteger(count) || count <= 0) return [];
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    const b64 = extract(plist, `${keypath}.${i}`, "raw");
    if (b64 !== undefined) out.push(b64);
  }
  return out;
}

/// Decode and parse one .provisionprofile. Returns undefined when the file
/// cannot be decoded (not a CMS blob, unreadable).
export function readProvisioningProfile(path: string): ProvisioningProfile | undefined {
  const plist = capture(["security", "cms", "-D", "-i", path]);
  if (plist === undefined) return undefined;
  const appIdentifier = extract(plist, "Entitlements.com\\.apple\\.application-identifier", "raw");
  const expiresRaw = extract(plist, "ExpirationDate", "raw");
  if (appIdentifier === undefined || expiresRaw === undefined) return undefined;
  const expires = new Date(expiresRaw);
  if (Number.isNaN(expires.getTime())) return undefined;
  return {
    path,
    appIdentifier,
    keychainAccessGroups: extractStringArray(plist, "Entitlements.keychain-access-groups"),
    teamIds: extractStringArray(plist, "TeamIdentifier"),
    developerCertificates: extractDataArray(plist, "DeveloperCertificates"),
    hasGetTaskAllow:
      extract(plist, "Entitlements.com\\.apple\\.security\\.get-task-allow", "raw") !== undefined,
    provisionsAllDevices: extract(plist, "ProvisionsAllDevices", "raw") === "true",
    provisionedDevices: extractStringArray(plist, "ProvisionedDevices"),
    expires,
  };
}

// Whether a profile keychain-access-groups entry covers a concrete group:
// either an exact match or a team-prefix wildcard ("3ZMH96L4V9.*").
function groupCovers(pattern: string, group: string): boolean {
  if (pattern === group) return true;
  return pattern.endsWith(".*") && group.startsWith(pattern.slice(0, -1));
}

/// Every reason a profile cannot back our entitlement chain; an empty array
/// means the profile is usable. Callers fail closed on any entry.
export function profileProblems(p: ProvisioningProfile, want: ProfileExpectation): string[] {
  const problems: string[] = [];
  if (p.appIdentifier !== want.appIdentifier) {
    problems.push(`authorizes ${p.appIdentifier}, expected ${want.appIdentifier}`);
  }
  if (!p.teamIds.includes(want.teamId)) {
    problems.push(`team ${p.teamIds.join(",") || "none"}, expected ${want.teamId}`);
  }
  if (!p.keychainAccessGroups.some((pattern) => groupCovers(pattern, want.keychainGroup))) {
    problems.push(`keychain-access-groups do not cover ${want.keychainGroup}`);
  }
  if (p.hasGetTaskAllow) {
    problems.push("authorizes com.apple.security.get-task-allow (debugger-attach regression)");
  }
  if (
    want.deviceUdid !== undefined &&
    !p.provisionsAllDevices &&
    !p.provisionedDevices.includes(want.deviceUdid)
  ) {
    problems.push(`does not provision this device (${want.deviceUdid})`);
  }
  if (p.expires.getTime() <= Date.now()) {
    problems.push(`expired at ${p.expires.toISOString()} (re-mint via Xcode, see ADR-0026)`);
  }
  return problems;
}

/// This Mac's provisioning UDID (what profiles list under
/// ProvisionedDevices). Undefined when it cannot be determined; callers must
/// treat that as a failure, not as a pass.
export function provisioningUdid(): string | undefined {
  const report = capture(["system_profiler", "SPHardwareDataType"]);
  return report?.match(/Provisioning UDID:\s*(\S+)/)?.[1];
}

/// Xcode's per-user profile cache, where automatic signing puts the
/// Mac Team profiles this build relies on.
export function xcodeProfileDir(): string {
  return join(homedir(), "Library/Developer/Xcode/UserData/Provisioning Profiles");
}

/// The newest usable profile in Xcode's cache for the expected identity, or
/// undefined with the reasons logged to stderr.
export function findUsableProfile(want: ProfileExpectation): ProvisioningProfile | undefined {
  let candidates: string[] = [];
  try {
    candidates = readdirSync(xcodeProfileDir()).filter((f) => f.endsWith(".provisionprofile"));
  } catch {
    return undefined;
  }
  let best: ProvisioningProfile | undefined;
  for (const file of candidates) {
    const profile = readProvisioningProfile(join(xcodeProfileDir(), file));
    if (profile === undefined) continue;
    const problems = profileProblems(profile, want);
    if (problems.length > 0) {
      console.error(`skipping profile ${file}: ${problems.join("; ")}`);
      continue;
    }
    if (best === undefined || profile.expires > best.expires) best = profile;
  }
  return best;
}
