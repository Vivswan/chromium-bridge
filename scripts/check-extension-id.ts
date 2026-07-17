#!/usr/bin/env bun

// Verify the bridge's identity constants against their sources of truth:
//
//   - extension id: DERIVED from contracts/identity.json's
//     `extensionManifestKey` (Chrome's id derivation; src/apps/extension/wxt.config.ts
//     injects the same key into the generated manifest). The generated
//     src/packages/shared/src/identity.gen.ts and both installers must carry
//     exactly that id.
//   - native-messaging host id: DECLARED in contracts/identity.json. The
//     generated TS, the Rust host, and both installers must agree, and the id
//     must satisfy Chrome's charset. Any disagreement makes native messaging
//     fail silently, so it is asserted here as a CI gate.

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const identityContract = JSON.parse(
  readFileSync(resolve(root, "contracts/identity.json"), "utf8"),
) as { nativeMessagingHostId?: unknown; extensionManifestKey?: unknown };
if (
  typeof identityContract.extensionManifestKey !== "string" ||
  identityContract.extensionManifestKey.length === 0
) {
  throw new Error("contracts/identity.json has no extensionManifestKey");
}

const hex = createHash("sha256")
  .update(Buffer.from(identityContract.extensionManifestKey, "base64"))
  .digest("hex")
  .slice(0, 32);
const derivedId = [...hex]
  .map((digit) => String.fromCharCode(97 + Number.parseInt(digit, 16)))
  .join("");

const sources: Array<[string, RegExp]> = [
  ["install/install.sh", /PINNED_EXTENSION_ID="([a-p]{32})"/],
  ["install/install.ps1", /\$ExtensionId\s*=\s*'([a-p]{32})'/],
  ["src/packages/shared/src/identity.gen.ts", /PINNED_EXTENSION_ID = "([a-p]{32})"/],
];

let failed = false;
for (const [relativePath, pattern] of sources) {
  const source = readFileSync(resolve(root, relativePath), "utf8");
  const configuredId = source.match(pattern)?.[1];
  if (configuredId !== derivedId) {
    console.error(`${relativePath}: configured=${configuredId || "missing"} derived=${derivedId}`);
    failed = true;
  }
}

// The native-messaging host id must be one value everywhere: the id the
// extension passes to connectNative (via the generated identity.gen.ts), the
// id the Rust host expects, and the id the installers write as both the
// manifest "name" and the manifest filename stem (`$HOST_NAME.json`).
const hostId = identityContract.nativeMessagingHostId;
// Chrome's charset for host names: dot-separated segments of [a-z0-9_], so
// no leading/trailing dots and no empty segments.
if (typeof hostId !== "string" || !/^[a-z0-9_]+(\.[a-z0-9_]+)*$/.test(hostId)) {
  console.error(`contracts/identity.json host id ${String(hostId)} violates Chrome's charset`);
  process.exit(1);
}
const hostSources: Array<[string, RegExp]> = [
  ["src/packages/shared/src/identity.gen.ts", /NATIVE_HOST_ID = "([a-z0-9._]+)"/],
  ["src/packages/core/src/doctor.rs", /const HOST_NAME: &str = "([a-z0-9._]+)"/],
  ["install/install.sh", /HOST_NAME="([a-z0-9._]+)"/],
  ["install/install.ps1", /\$HostName = '([a-z0-9._]+)'/],
];
for (const [relativePath, pattern] of hostSources) {
  const source = readFileSync(resolve(root, relativePath), "utf8");
  const configured = source.match(pattern)?.[1];
  if (configured !== hostId) {
    console.error(`${relativePath}: host id=${configured || "missing"} expected=${hostId}`);
    failed = true;
  }
}

// When the extension has been built, re-assert the SECURITY SURFACE on the
// shipped artifact: the pinned key, the exact permission set, no install-time
// host access, and no manifest-declared content scripts. This catches drift
// between wxt.config.ts and what the build actually emits (the config-level
// assertions live in src/apps/extension/tests/shared/manifest.test.ts). `just ci`
// builds before this check runs; a standalone run without dist/ skips it
// loudly rather than failing a build-free environment.
const builtManifestPath = resolve(root, "src/apps/extension/dist/chrome-mv3/manifest.json");
if (existsSync(builtManifestPath)) {
  const built = JSON.parse(readFileSync(builtManifestPath, "utf8")) as {
    key?: unknown;
    permissions?: unknown;
    host_permissions?: unknown;
    optional_host_permissions?: unknown;
    content_scripts?: unknown;
  };
  const expectPermissions = [
    "tabs",
    "tabGroups",
    "scripting",
    "storage",
    "nativeMessaging",
    "debugger",
    "cookies",
  ];
  const problems: string[] = [];
  if (built.key !== identityContract.extensionManifestKey) {
    problems.push("built manifest key differs from contracts/identity.json");
  }
  if (JSON.stringify(built.permissions) !== JSON.stringify(expectPermissions)) {
    problems.push(`built permissions drifted: ${JSON.stringify(built.permissions)}`);
  }
  if (JSON.stringify(built.host_permissions) !== "[]") {
    problems.push(
      `built host_permissions must be empty: ${JSON.stringify(built.host_permissions)}`,
    );
  }
  if (JSON.stringify(built.optional_host_permissions) !== '["<all_urls>"]') {
    problems.push(
      `built optional_host_permissions drifted: ${JSON.stringify(built.optional_host_permissions)}`,
    );
  }
  if (JSON.stringify(built.content_scripts ?? []) !== "[]") {
    problems.push("built manifest declares content_scripts; injection must stay runtime-only");
  }
  if (problems.length > 0) {
    for (const p of problems) console.error(`src/apps/extension/dist manifest: ${p}`);
    process.exit(1);
  }
  console.log("built manifest security surface verified (key, permissions, host access)");
} else {
  console.log(
    "note: src/apps/extension/dist/chrome-mv3 not built; skipped built-manifest verification",
  );
}

if (failed) process.exit(1);
console.log(`extension id: ${derivedId} (contract key + generated TS + installers consistent)`);
console.log(`host id: ${hostId} (contract + generated TS + host + installers consistent)`);
