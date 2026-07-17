import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
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
  readFileSync(resolve(__dirname, "../../../contracts/identity.json"), "utf8"),
) as { extensionManifestKey: string };

export default defineConfig({
  srcDir: "src",
  outDir: "dist",
  publicDir: "src/public",
  // No magic: every import is written out, so grep and tsc see the truth.
  imports: false,
  // Compiles src/locales/*.yml -> _locales/<locale>/messages.json and
  // generates the #i18n key structure the runtime types against.
  modules: ["@wxt-dev/i18n/module"],
  vite: () => ({
    plugins: [react(), tailwindcss()],
  }),
  manifest: {
    name: "Chromium Bridge",
    // The Chrome-resolved description reads from _locales; the in-extension
    // UI additionally honors the user's chosen display language (lib/i18n).
    default_locale: "en",
    description: "__MSG_extDescription__",
    key: identity.extensionManifestKey,
    // The extension relies on modern MV3 storage + scripting behavior; 116 is
    // the floor the pre-rehaul build targeted and remains the supported
    // minimum. The #32 trust-state isolation uses storage.local.setAccessLevel
    // (available since Chrome 102); if a browser somehow lacks it the call
    // throws and the enrollment gate fails closed rather than degrading (see
    // lib/background/trusted-storage.ts), so the floor need not encode it.
    minimum_chrome_version: "116",
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
