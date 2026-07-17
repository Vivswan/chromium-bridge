#!/usr/bin/env bun

// Verify the bridge's identity constants against their sources of truth:
//
//   - extension id: DERIVED from extension/manifest.json's `key` (Chrome's id
//     derivation). The generated packages/shared/src/identity.gen.ts and both
//     installers must carry exactly that id.
//   - native-messaging host id: DECLARED in contracts/identity.json. The
//     generated TS, the Rust host, and both installers must agree, and the id
//     must satisfy Chrome's charset. Any disagreement makes native messaging
//     fail silently, so it is asserted here as a CI gate.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifest = JSON.parse(readFileSync(resolve(root, "extension/manifest.json"), "utf8")) as {
  key?: unknown;
};
if (typeof manifest.key !== "string" || manifest.key.length === 0) {
  throw new Error("extension/manifest.json has no public key");
}

const hex = createHash("sha256")
  .update(Buffer.from(manifest.key, "base64"))
  .digest("hex")
  .slice(0, 32);
const derivedId = [...hex]
  .map((digit) => String.fromCharCode(97 + Number.parseInt(digit, 16)))
  .join("");

const sources: Array<[string, RegExp]> = [
  ["install/install.sh", /PINNED_EXTENSION_ID="([a-p]{32})"/],
  ["install/install.ps1", /\$ExtensionId\s*=\s*'([a-p]{32})'/],
  ["packages/shared/src/identity.gen.ts", /PINNED_EXTENSION_ID = "([a-p]{32})"/],
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
const identity = JSON.parse(readFileSync(resolve(root, "contracts/identity.json"), "utf8")) as {
  nativeMessagingHostId?: unknown;
};
const hostId = identity.nativeMessagingHostId;
// Chrome's charset for host names: dot-separated segments of [a-z0-9_], so
// no leading/trailing dots and no empty segments.
if (typeof hostId !== "string" || !/^[a-z0-9_]+(\.[a-z0-9_]+)*$/.test(hostId)) {
  console.error(`contracts/identity.json host id ${String(hostId)} violates Chrome's charset`);
  process.exit(1);
}
const hostSources: Array<[string, RegExp]> = [
  ["packages/shared/src/identity.gen.ts", /NATIVE_HOST_ID = "([a-z0-9._]+)"/],
  ["crates/core/src/doctor.rs", /const HOST_NAME: &str = "([a-z0-9._]+)"/],
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

if (failed) process.exit(1);
console.log(`extension id: ${derivedId} (manifest key + generated TS + installers consistent)`);
console.log(`host id: ${hostId} (contract + generated TS + host + installers consistent)`);
