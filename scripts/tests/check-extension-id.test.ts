import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  MANIFEST_PERMISSIONS,
  MINIMUM_CHROME_VERSION,
} from "../../src/apps/extension/src/lib/shared/manifest-surface";
import { EXTENSION_MANIFEST_KEY } from "../../src/packages/shared/generated/identity";
import { builtManifestProblems } from "../check-extension-id";
import { Scratch } from "../lib";

const scratch = new Scratch();
afterEach(() => scratch.remove());

function built(manifest: Record<string, unknown> | undefined): string {
  const root = scratch.dir("check-extension-id");
  mkdirSync(join(root, "build/extension/chrome-mv3"), { recursive: true });
  if (manifest) {
    writeFileSync(join(root, "build/extension/chrome-mv3/manifest.json"), JSON.stringify(manifest));
  }
  return root;
}

const pinned = {
  key: EXTENSION_MANIFEST_KEY,
  permissions: MANIFEST_PERMISSIONS,
  minimum_chrome_version: MINIMUM_CHROME_VERSION,
  host_permissions: [],
  optional_host_permissions: ["<all_urls>"],
};

// The CI run shows the pinned surface passing; only a drifted manifest shows each rule firing by name, and
// the task depends on extension:build, so a manifest absent after the build is a defect, never a skip.
describe("builtManifestProblems", () => {
  test.each<[name: string, manifest: Record<string, unknown> | undefined, problems: string[]]>([
    ["the pinned surface has no problem", pinned, []],
    [
      "a build directory without a manifest is an error naming the expected path, not a skip",
      undefined,
      ["built manifest missing at build/extension/chrome-mv3/manifest.json"],
    ],
    [
      "every drifted field is named: key, permissions, Chrome floor, host access, content scripts",
      {
        key: "another key",
        permissions: ["tabs"],
        minimum_chrome_version: "100",
        host_permissions: ["<all_urls>"],
        optional_host_permissions: [],
        content_scripts: [{ matches: ["<all_urls>"], js: ["x.js"] }],
      },
      [
        "built manifest key differs from src/packages/core/src/identity.rs",
        'built permissions drifted: ["tabs"]',
        'built minimum_chrome_version drifted: "100"',
        'built host_permissions must be empty: ["<all_urls>"]',
        "built optional_host_permissions drifted: []",
        "built manifest declares content_scripts; injection must stay runtime-only",
      ],
    ],
  ])("%s", (_name, manifest, problems) => {
    expect(builtManifestProblems(built(manifest))).toEqual(problems);
  });
});
