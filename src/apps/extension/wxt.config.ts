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
  // DEV BROWSER ONLY: webExt configures how `wxt` (serve mode) would launch a
  // throwaway browser; nothing here reaches a build artifact. We DISABLE WXT's
  // own launcher and hand browser ownership to the dev orchestrator
  // (scripts/dev-browser.ts), which drives web-ext-run directly so it can
  // relaunch the browser from web-ext-run's cleanup callback instead of the
  // old ps-poll watchdog. The launch config (fresh temp profile, startUrl docs
  // tab, pinned-extension pref, CDP unpacked-load path) lives there now. WXT
  // still builds, serves, and reloads the extension over its dev-server
  // websocket - reload does not depend on who launched Chrome.
  //
  // The `config:resolved` hook below stays as defense-in-depth: it fail-closes
  // if an rc file (web-ext.config.ts, .webextrc, ~/.webextrc) ever hands
  // WXT's runner a real profile - even though, with `disabled`, that runner no
  // longer launches anything.
  webExt: {
    disabled: true,
  },
  hooks: {
    // FAIL CLOSED on dev-profile reuse. WXT resolves the final web-ext
    // config from rc files too (web-ext.config.ts, .webextrc, including a
    // global one in $HOME), any of which can override the `webExt` defaults
    // above. Two override shapes would hand the dev browser a real,
    // logged-in profile - which the repo's browser-safety red line forbids:
    //   - chromiumProfile/firefoxProfile (+ keepProfileChanges writes back)
    //   - chromiumArgs/firefoxArgs smuggling the same thing as raw flags
    //     (--user-data-dir=..., --profile-directory=..., -profile ...).
    // This config sets no args, so ANY resolved arg is an rc override;
    // rejecting the arrays wholesale is simpler and stricter than
    // deny-listing flag spellings. Refuse to start instead of proceeding
    // degraded. Scoped to serve mode: only `wxt` (dev) launches a browser.
    // Named residual: an rc `binaries.chrome` entry or the CHROME_PATH env
    // var can still swap WHICH browser binary launches. That cannot reach a
    // real session - web-ext-run always passes its fresh temp profile as an
    // explicit --user-data-dir - so this hook guards profile reuse only.
    "config:resolved": (wxt) => {
      if (wxt.config.command !== "serve") return;
      const resolved = wxt.config.runnerConfig.config ?? {};
      const problems: string[] = [];
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
