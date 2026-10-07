import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MANIFEST_PERMISSIONS,
  MINIMUM_CHROME_VERSION,
} from "../../src/apps/extension/src/lib/shared/manifest-surface";
import { EXTENSION_MANIFEST_KEY } from "../../src/packages/shared/src/identity.gen";
import { builtManifestProblems } from "../check-extension-id";

const scratchDirs: string[] = [];

afterEach(() => {
  for (const dir of scratchDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "check-extension-id-"));
  scratchDirs.push(dir);
  return dir;
}

// Drift answer: the task depends on extension:build, so a manifest absent after the build is a defect, and a skip
// there would pass a surface no one checked.
describe("builtManifestProblems", () => {
  test("a build directory without a manifest is an error naming the expected path, not a skip", () => {
    const root = scratch();
    mkdirSync(join(root, "build/extension/chrome-mv3"), { recursive: true });
    expect(builtManifestProblems(root)).toEqual([
      "built manifest missing at build/extension/chrome-mv3/manifest.json",
    ]);
  });

  test("a manifest with the pinned surface has no problem", () => {
    const root = scratch();
    mkdirSync(join(root, "build/extension/chrome-mv3"), { recursive: true });
    writeFileSync(
      join(root, "build/extension/chrome-mv3/manifest.json"),
      JSON.stringify({
        key: EXTENSION_MANIFEST_KEY,
        permissions: MANIFEST_PERMISSIONS,
        minimum_chrome_version: MINIMUM_CHROME_VERSION,
        host_permissions: [],
        optional_host_permissions: ["<all_urls>"],
      }),
    );
    expect(builtManifestProblems(root)).toEqual([]);
  });
});
