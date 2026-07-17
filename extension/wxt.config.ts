import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "wxt";
import { MANIFEST_PERMISSIONS } from "./src/lib/shared/manifest-permissions";

// contracts/identity.json is the single source of truth for the pinned
// manifest `key`. The extension ID Chrome derives from it is what the native-
// messaging host manifest pins in `allowed_origins`, so the key ships in
// EVERY build (this extension is distributed as load-unpacked, not through a
// store): a build without it would get a path-derived ID and be rejected by
// the host. scripts/check-extension-id.ts verifies every copy of the derived
// ID against this same contract.
const identity = JSON.parse(
  readFileSync(resolve(__dirname, "../contracts/identity.json"), "utf8"),
) as { extensionManifestKey: string };

export default defineConfig({
  srcDir: "src",
  outDir: "dist",
  publicDir: "src/public",
  // No magic: every import is written out, so grep and tsc see the truth.
  imports: false,
  manifest: {
    name: "Chromium Bridge",
    description:
      "Let an MCP client (Claude Code, Codex, ...) operate your real Chrome - your tabs and logins. You approve new sites and risky actions.",
    key: identity.extensionManifestKey,
    // storage.local.setAccessLevel (the #32 trust-state isolation) needs a
    // current Chrome; the API throws on older versions and the enrollment
    // gate then fails closed (see lib/background/trusted-storage.ts).
    minimum_chrome_version: "130",
    permissions: [...MANIFEST_PERMISSIONS],
    host_permissions: [],
    optional_host_permissions: ["<all_urls>"],
    action: {
      default_title: "Chromium Bridge",
    },
    icons: {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png",
    },
  },
});
