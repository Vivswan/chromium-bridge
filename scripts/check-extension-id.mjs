#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifest = JSON.parse(readFileSync(resolve(root, "extension/manifest.json"), "utf8"));
if (typeof manifest.key !== "string" || manifest.key.length === 0) {
  throw new Error("extension/manifest.json has no public key");
}

const hex = createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest("hex").slice(0, 32);
const derivedId = [...hex].map((digit) => String.fromCharCode(97 + Number.parseInt(digit, 16))).join("");

const sources = [
  ["install/install.sh", /PINNED_EXTENSION_ID="([a-p]{32})"/],
  ["install/install.ps1", /\$ExtensionId\s*=\s*'([a-p]{32})'/],
  ["extension/src/shared/extension-id.ts", /PINNED_EXTENSION_ID\s*=\s*"([a-p]{32})"/],
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
// extension passes to connectNative, the id the Rust host expects, and the id
// the installers write as both the manifest "name" and the manifest filename
// stem (`$HOST_NAME.json`). Any disagreement makes native messaging fail
// silently, so it is asserted here alongside the extension id.
const HOST_ID = "com.vivswan.chromium_bridge.host";
if (!/^[a-z0-9._]+$/.test(HOST_ID) || HOST_ID.includes("..")) {
  console.error(`host id ${HOST_ID} violates Chrome's allowed charset`);
  failed = true;
}
const hostSources = [
  ["extension/src/background/port.ts", /const NATIVE_HOST = "([a-z0-9._]+)"/],
  ["crates/core/src/doctor.rs", /const HOST_NAME: &str = "([a-z0-9._]+)"/],
  ["install/install.sh", /HOST_NAME="([a-z0-9._]+)"/],
  ["install/install.ps1", /\$HostName = '([a-z0-9._]+)'/],
];
for (const [relativePath, pattern] of hostSources) {
  const source = readFileSync(resolve(root, relativePath), "utf8");
  const configured = source.match(pattern)?.[1];
  if (configured !== HOST_ID) {
    console.error(`${relativePath}: host id=${configured || "missing"} expected=${HOST_ID}`);
    failed = true;
  }
}

if (failed) process.exit(1);
console.log(`extension id: ${derivedId} (manifest key + installers consistent)`);
console.log(`host id: ${HOST_ID} (extension + host + installers consistent)`);
