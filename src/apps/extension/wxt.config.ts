import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "wxt";
import { EXTENSION_MANIFEST_KEY } from "../../packages/shared/src/identity.gen";
import { MANIFEST_PERMISSIONS } from "./src/lib/shared/manifest-permissions";

// The pinned manifest `key` comes from the Rust core's identity constants
// (src/packages/core/src/identity.rs, via the generated identity.gen.ts). The
// extension ID Chrome derives from it is what the native-messaging host
// manifest pins in `allowed_origins`, so the key ships in EVERY build (this
// extension is distributed as load-unpacked, not through a store): a build
// without it would get a path-derived ID and be rejected by the host.
// scripts/check-extension-id.ts verifies every copy of the derived ID
// against the same source.

export default defineConfig({
  srcDir: "src",
  // All build deliverables land in the repo-root build/ folder; WXT appends
  // the browser target, so the loadable extension is build/extension/chrome-mv3.
  outDir: "../../../build/extension",
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
    key: EXTENSION_MANIFEST_KEY,
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
