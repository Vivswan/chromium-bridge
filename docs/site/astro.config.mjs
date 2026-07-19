// The public site: a landing page (src/pages/index.astro) plus the
// repository's own markdown docs rendered under /docs/ (see
// src/pages/docs/[...slug].astro). Served as a GitHub Pages project page
// under /chromium-bridge/, so every internal link and asset must go through
// import.meta.env.BASE_URL - never a root-absolute path.
import { satteri } from "@astrojs/markdown-satteri";
import { defineConfig } from "astro/config";
import { mdLinksPlugin } from "./src/lib/satteri-md-links";
// Origin + base come from ASTRO_SITE / ASTRO_BASE (defaults: the GitHub Pages
// project page) so deploy-site.yml can build the staging path and the
// custom-domain cutover without touching source. See site-identity.ts.
import { SITE_BASE, SITE_ORIGIN } from "./src/lib/site-identity";

export default defineConfig({
  site: SITE_ORIGIN,
  base: SITE_BASE,
  outDir: "dist",
  // Keep authored whitespace: the default HTML compression eats the space
  // between text and an adjacent inline link ("the<a>source code</a>").
  compressHTML: false,
  // Each page builds to <route>/index.html so Pages serves clean URLs.
  build: {
    format: "directory",
  },
  markdown: {
    // The default processor plus one plugin: repo-relative .md links become
    // their rendered /docs/ routes (see satteri-md-links.ts).
    processor: satteri({ hastPlugins: [mdLinksPlugin(SITE_BASE)] }),
  },
  vite: {
    // Let the dev server read the repo's markdown above the site root.
    server: { fs: { allow: ["../.."] } },
  },
});
