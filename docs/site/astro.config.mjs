// Minimal config: the site renders the repository's own markdown docs (see
// src/pages/[...slug].astro), so the only non-default setting is letting
// Vite's dev server read files above the site root.
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://vivswan.github.io",
  base: "/chromium-bridge",
  vite: {
    server: { fs: { allow: ["../.."] } },
  },
});
