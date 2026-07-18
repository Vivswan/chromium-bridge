#!/usr/bin/env bun

// Verify the bridge's identity constants against their source of truth, the
// Rust core (src/packages/core/src/identity.rs, ADR-0028):
//
//   - extension id: DERIVED from the pinned manifest key (Chrome's id
//     derivation; extension/wxt.config.ts injects the same key into the
//     generated manifest). The generated src/packages/shared/src/identity.gen.ts
//     must carry exactly that id.
//   - native-messaging host id: the generated TS must agree with the Rust
//     constant, and the id must satisfy Chrome's charset. Any disagreement
//     makes native messaging fail silently, so it is asserted here as a CI
//     gate. The registration engine (registration.rs) consumes the constants
//     directly from identity.rs, so it has no textual copy to verify.
//
// This script runs without cargo, so the Rust constants are read from the
// source text; `just gen` idempotency (CI) separately proves the generated
// TS is fresh, and the two checks together pin every copy to identity.rs.

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  EXTENSION_MANIFEST_KEY,
  NATIVE_HOST_ID,
  PINNED_EXTENSION_ID,
} from "../src/packages/shared/src/identity.gen";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

let failed = false;

// The Rust source is canonical: the generated TS constants must match its
// literals exactly.
const identityRs = readFileSync(resolve(root, "src/packages/core/src/identity.rs"), "utf8");
const rustKey = identityRs.match(/EXTENSION_MANIFEST_KEY: &str = "([A-Za-z0-9+/=]+)"/)?.[1];
const rustHostId = identityRs.match(/NATIVE_HOST_ID: &str = "([a-z0-9._]+)"/)?.[1];
if (rustKey !== EXTENSION_MANIFEST_KEY) {
  console.error(
    "identity.gen.ts EXTENSION_MANIFEST_KEY differs from src/packages/core/src/identity.rs",
  );
  failed = true;
}
if (rustHostId !== NATIVE_HOST_ID) {
  console.error("identity.gen.ts NATIVE_HOST_ID differs from src/packages/core/src/identity.rs");
  failed = true;
}

// Chrome's id derivation: sha256 of the DER key, first 16 bytes, hex mapped
// onto a-p. Same computation as scripts/gen-ops.ts.
const hex = createHash("sha256")
  .update(Buffer.from(EXTENSION_MANIFEST_KEY, "base64"))
  .digest("hex")
  .slice(0, 32);
const derivedId = [...hex]
  .map((digit) => String.fromCharCode(97 + Number.parseInt(digit, 16)))
  .join("");
if (PINNED_EXTENSION_ID !== derivedId) {
  console.error(
    `identity.gen.ts PINNED_EXTENSION_ID=${PINNED_EXTENSION_ID} but the key derives ${derivedId}`,
  );
  failed = true;
}

// identity.rs also pins the derived id as a Rust constant (the registration
// engine stamps it into every manifest's allowed_origins); the literal must
// be exactly what the key derives.
const rustPinnedId = identityRs.match(/PINNED_EXTENSION_ID: &str = "([a-p]{32})"/)?.[1];
if (rustPinnedId !== derivedId) {
  console.error(
    `identity.rs PINNED_EXTENSION_ID=${rustPinnedId || "missing"} but the key derives ${derivedId}`,
  );
  failed = true;
}

// The native-messaging host id must be one value everywhere: the id the
// extension passes to connectNative (via the generated identity.gen.ts), the
// id the Rust host expects, and the id the registration engine writes as both
// the manifest "name" and the manifest filename stem (`<host id>.json`).
// Chrome's charset for host names: dot-separated segments of [a-z0-9_], so
// no leading/trailing dots and no empty segments.
if (!/^[a-z0-9_]+(\.[a-z0-9_]+)*$/.test(NATIVE_HOST_ID)) {
  console.error(`host id ${NATIVE_HOST_ID} violates Chrome's charset`);
  process.exit(1);
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
  if (built.key !== EXTENSION_MANIFEST_KEY) {
    problems.push("built manifest key differs from src/packages/core/src/identity.rs");
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
    for (const p of problems) console.error(`extension/dist manifest: ${p}`);
    process.exit(1);
  }
  console.log("built manifest security surface verified (key, permissions, host access)");
} else {
  console.log(
    "note: src/apps/extension/dist/chrome-mv3 not built; skipped built-manifest verification",
  );
}

// SINGLE SOURCE: identity.rs is the only Rust file allowed to DEFINE the
// identity values; everything else (browsers.rs re-exports them for the
// registration engine) must reference that one site. Test fixtures may spell
// the literals out to pin derivations, so only const/static string
// definitions are flagged.
const browsersRs = readFileSync(resolve(root, "src/packages/core/src/browsers.rs"), "utf8");
if (
  !browsersRs.includes("pub use crate::identity::{NATIVE_HOST_ID as HOST_ID, PINNED_EXTENSION_ID};")
) {
  console.error(
    "browsers.rs no longer re-exports the identity constants from identity.rs - " +
      "restore the re-export rather than redefining them",
  );
  failed = true;
}
const coreSrc = resolve(root, "src/packages/core/src");
const duplicateConst = new RegExp(
  `(?:const|static)\\s+\\w+\\s*:\\s*&str\\s*=\\s*"(?:${NATIVE_HOST_ID.replaceAll(".", "\\.")}|${derivedId})"`,
);
for (const entry of readdirSync(coreSrc, { recursive: true }) as string[]) {
  if (!entry.endsWith(".rs") || entry === "identity.rs") continue;
  if (duplicateConst.test(readFileSync(resolve(coreSrc, entry), "utf8"))) {
    console.error(
      `src/packages/core/src/${entry}: defines a duplicate identity constant (the single source is identity.rs)`,
    );
    failed = true;
  }
}

if (failed) process.exit(1);
console.log(`extension id: ${derivedId} (Rust key + generated TS consistent)`);
console.log(`host id: ${NATIVE_HOST_ID} (Rust + generated TS consistent)`);
