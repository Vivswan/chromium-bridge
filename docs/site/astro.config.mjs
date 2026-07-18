// The public site: a landing page (src/pages/index.astro) plus the
// repository's own markdown docs rendered under /docs/ (see
// src/pages/docs/[...slug].astro). Served as a GitHub Pages project page
// under /chromium-bridge/, so every internal link and asset must go through
// import.meta.env.BASE_URL - never a root-absolute path.
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://vivswan.github.io",
  base: "/chromium-bridge",
  outDir: "dist",
  // Keep authored whitespace: the default HTML compression eats the space
  // between text and an adjacent inline link ("the<a>source code</a>").
  compressHTML: false,
  // Each page builds to <route>/index.html so Pages serves clean URLs.
  build: {
    format: "directory",
  },
  vite: {
    // Let the dev server read the repo's markdown above the site root.
    server: { fs: { allow: ["../.."] } },
  },
});
