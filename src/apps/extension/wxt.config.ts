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
  // DEV BROWSER ONLY: webExt configures how `wxt` (serve mode) would launch a throwaway browser; nothing here
  // reaches a build artifact. WXT's own launcher is DISABLED because scripts/dev-browser.ts owns the dev
  // browser (it drives web-ext-run directly so it can relaunch from the cleanup callback); WXT still builds,
  // serves, and reloads the extension over its dev-server websocket regardless of who launched Chrome.
  // This block is only the DEFAULTS layer: an rc file (web-ext.config.ts, .webextrc, ~/.webextrc) overrides
  // it, so the `config:resolved` hook below re-checks the RESOLVED config.
  webExt: {
    disabled: true,
  },
  hooks: {
    // FAIL CLOSED on dev-profile reuse: rc files can override the `webExt` defaults above, and two override
    // shapes would hand the dev browser a real, logged-in profile, which the browser-safety red line forbids.
    //   chromiumProfile / firefoxProfile (+ keepProfileChanges)  -> reuses or writes back a profile
    //   chromiumArgs / firefoxArgs                               -> smuggle the same as raw flags (--user-data-dir=...)
    // This config sets no args, so ANY resolved arg is an rc override; refusing the arrays wholesale is stricter
    // than deny-listing flag spellings. Serve mode only: only `wxt` (dev) launches a browser.
    // Residual: an rc `binaries.chrome` entry or CHROME_PATH can still swap WHICH binary launches; it cannot
    // reach a real session because web-ext-run always passes its fresh temp profile as --user-data-dir.
    "config:resolved": (wxt) => {
      if (wxt.config.command !== "serve") return;
      const resolved = wxt.config.webExt.config ?? {};
      const problems: string[] = [];
      if (resolved.disabled !== true) {
        problems.push(
          "disabled was overridden off: WXT would launch a second dev browser; " +
            "scripts/dev-browser.ts owns the dev browser",
        );
      }
      if (resolved.chromiumProfile || resolved.firefoxProfile || resolved.keepProfileChanges) {
        problems.push(
          "chromiumProfile/firefoxProfile/keepProfileChanges reuse or persist a browser profile",
        );
      }
      if (resolved.chromiumArgs?.length || resolved.firefoxArgs?.length) {
        problems.push("chromiumArgs/firefoxArgs can smuggle profile flags (e.g. --user-data-dir)");
      }
      if (problems.length > 0) {
        throw new Error(
          "refusing to start the dev browser: the resolved web-ext config is unsafe: " +
            `${problems.join("; ")}. The dev browser must run in a fresh temporary ` +
            "profile with no extra flags; remove the override " +
            "(web-ext.config.ts, .webextrc, or ~/.webextrc).",
        );
      }
    },
  },
  manifest: {
    name: "Chromium Bridge",
    // The Chrome-resolved description reads from _locales; the in-extension
    // UI additionally honors the user's chosen display language (lib/i18n).
    default_locale: "en",
    description: "__MSG_extDescription__",
    key: EXTENSION_MANIFEST_KEY,
    // 116 is the supported minimum. storage.local.setAccessLevel (Chrome 102+) need not be encoded in the
    // floor: if a browser lacks it the call throws and the enrollment gate fails closed rather than degrading
    // (lib/background/trusted-storage.ts).
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
