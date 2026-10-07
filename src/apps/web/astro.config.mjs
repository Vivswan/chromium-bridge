// The public site: the landing page (src/pages/index.astro). The docs are the
// fleet's site leg's: it renders docs/ and its locale trees under /docs/ beside
// this build, so this app renders no markdown. Served as a GitHub Pages
// project page under /chromium-bridge/, so every internal link and asset must
// go through import.meta.env.BASE_URL - never a root-absolute path.
import { defineConfig } from "astro/config";
// Origin + base come from ASTRO_SITE / ASTRO_BASE (defaults: the GitHub Pages
// project page) so the deploy hook (.github/actions/site-build) can retarget the
// site, custom domain included, without touching source. See site-identity.ts.
import { SITE_BASE, SITE_ORIGIN } from "./src/lib/site-identity";

export default defineConfig({
  site: SITE_ORIGIN,
  base: SITE_BASE,
  outDir: "../../../build/web",
  // Keep authored whitespace: the default HTML compression eats the space
  // between text and an adjacent inline link ("the<a>source code</a>").
  compressHTML: false,
  // Each page builds to <route>/index.html so Pages serves clean URLs.
  build: {
    format: "directory",
  },
  vite: {
    // Let the dev server read the root Cargo.toml the landing page imports.
    server: { fs: { allow: ["../../.."] } },
  },
});
