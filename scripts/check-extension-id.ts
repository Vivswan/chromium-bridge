#!/usr/bin/env bun

// Two identity facts no other gate reaches. gen-ops.ts re-derives the extension id from the key and checks the
// host id's charset while generating the TS side, and src/apps/extension/tests/shared/manifest.test.ts asserts
// the manifest SOURCE (wxt.config.ts).
//
//   built manifest   -> the shipped artifact keeps the pinned key, the exact permission set, the Chrome floor,
//                       no install-time host access, and no manifest-declared content scripts; the task depends
//                       on extension:build, so a missing manifest is an error, not a skip
//   core/src         -> identity.rs is the only file that DEFINES an identity constant, by name (a shadowing
//                       PINNED_EXTENSION_ID in browsers.rs would feed registration a different allowed_origins
//                       while the generated TS, emitted from identity.rs, stayed green) or by value. Only a
//                       line that starts as a declaration counts, so a `//` comment never trips it; a
//                       declaration-shaped line inside a block comment or a raw string still does, fail closed

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MANIFEST_PERMISSIONS,
  MINIMUM_CHROME_VERSION,
} from "../src/apps/extension/src/lib/shared/manifest-surface";
import {
  EXTENSION_MANIFEST_KEY,
  NATIVE_HOST_ID,
  PINNED_EXTENSION_ID,
} from "../src/packages/shared/generated/identity";

const BUILT_MANIFEST = "build/extension/chrome-mv3/manifest.json";

export function builtManifestProblems(root: string): string[] {
  const problems: string[] = [];
  const builtManifestPath = resolve(root, BUILT_MANIFEST);
  if (!existsSync(builtManifestPath)) {
    return [`built manifest missing at ${BUILT_MANIFEST}`];
  }
  const built = JSON.parse(readFileSync(builtManifestPath, "utf8")) as {
    key?: unknown;
    permissions?: unknown;
    minimum_chrome_version?: unknown;
    host_permissions?: unknown;
    optional_host_permissions?: unknown;
    content_scripts?: unknown;
  };
  if (built.key !== EXTENSION_MANIFEST_KEY) {
    problems.push("built manifest key differs from src/packages/core/src/identity.rs");
  }
  if (JSON.stringify(built.permissions) !== JSON.stringify(MANIFEST_PERMISSIONS)) {
    problems.push(`built permissions drifted: ${JSON.stringify(built.permissions)}`);
  }
  if (built.minimum_chrome_version !== MINIMUM_CHROME_VERSION) {
    problems.push(
      `built minimum_chrome_version drifted: ${JSON.stringify(built.minimum_chrome_version)}`,
    );
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
  return problems;
}

export function identityDefiners(root: string): string[] {
  const coreSrc = resolve(root, "src/packages/core/src");
  const identityNames = ["NATIVE_HOST_ID", "PINNED_EXTENSION_ID", "EXTENSION_MANIFEST_KEY"];
  const identityValues = [NATIVE_HOST_ID, PINNED_EXTENSION_ID, EXTENSION_MANIFEST_KEY].map(
    RegExp.escape,
  );
  const definesIdentity = new RegExp(
    `^\\s*(?:pub(?:\\([^)]*\\))?\\s+)?(?:const|static)\\s+(?:r#)?(?:(?:${identityNames.join("|")})\\s*:|\\w+\\s*:\\s*&str\\s*=\\s*"(?:${identityValues.join("|")})")`,
    "m",
  );
  return (readdirSync(coreSrc, { recursive: true }) as string[])
    .filter((entry) => entry.endsWith(".rs") && entry !== "identity.rs")
    .filter((entry) => definesIdentity.test(readFileSync(resolve(coreSrc, entry), "utf8")))
    .map(
      (entry) =>
        `src/packages/core/src/${entry} defines an identity constant (the single source is identity.rs; re-export it instead)`,
    );
}

if (import.meta.main) {
  const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
  const problems = [...builtManifestProblems(root), ...identityDefiners(root)];
  if (problems.length > 0) {
    for (const p of problems) console.error(`check-extension-id: ${p}`);
    process.exit(1);
  }
  console.log(
    `check-extension-id: identity.rs is the only definition site for ${NATIVE_HOST_ID} and ${PINNED_EXTENSION_ID}; the built manifest keeps the pinned security surface`,
  );
}
