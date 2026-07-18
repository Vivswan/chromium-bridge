// The Control Tower token layer exists as three hand-synchronized copies:
// the extension stylesheet, the desktop stylesheet (same tokens, different
// dark-mode wrapper), and the TypeScript mirror for CSS-less contexts
// (theme-colors.ts). Comments ask editors to keep them in sync; this test
// makes drift fail CI instead.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import {
  BADGE_DANGER_COLOR,
  BADGE_PENDING_COLOR,
  TOAST_DARK,
  TOAST_LIGHT,
} from "@/lib/shared/theme-colors";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const extensionCss = readFileSync(
  join(repoRoot, "src/apps/extension/src/assets/styles.css"),
  "utf8",
);
const desktopCss = readFileSync(join(repoRoot, "src/apps/desktop/ui/src/styles.css"), "utf8");

function stripComments(css: string): string {
  return css.replace(/\/\*[\s\S]*?\*\//g, "");
}

/** Every custom-property declaration, in source order, whitespace normalized. */
function tokenDeclarations(css: string): string[] {
  return Array.from(stripComments(css).matchAll(/--[\w-]+\s*:\s*[^;]+;/g), (m) =>
    m[0].replace(/\s+/g, " "),
  );
}

/** The name -> value map of one mode's palette block, located by its
 * `color-scheme: <scheme>` declaration and ending at the block's closing
 * brace (the palette rules contain no nested braces). This keeps the scope
 * check honest: a dark token declared outside the .dark class / media query
 * would vanish from this map, not still match a whole-file search. */
function paletteOf(css: string, scheme: "light" | "dark"): Record<string, string> {
  const flat = stripComments(css);
  const start = flat.indexOf(`color-scheme: ${scheme};`);
  expect(start).toBeGreaterThan(-1);
  const body = flat.slice(start, flat.indexOf("}", start));
  const palette: Record<string, string> = {};
  for (const [, name, value] of body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
    if (name && value) palette[name] = value.replace(/\s+/g, " ").trim();
  }
  return palette;
}

describe("Control Tower token parity", () => {
  test("extension and desktop stylesheets declare identical tokens, in order", () => {
    const ext = tokenDeclarations(extensionCss);
    expect(ext.length).toBeGreaterThan(50); // guard against a regex gone blind
    expect(tokenDeclarations(desktopCss)).toEqual(ext);
  });

  test("each mode's palette block matches between the two stylesheets", () => {
    for (const scheme of ["light", "dark"] as const) {
      expect(paletteOf(desktopCss, scheme)).toEqual(paletteOf(extensionCss, scheme));
    }
  });

  test("badge constants mirror the dark-scheme signal tokens", () => {
    const dark = paletteOf(extensionCss, "dark");
    expect(BADGE_PENDING_COLOR).toBe(dark["--pending"]);
    expect(BADGE_DANGER_COLOR).toBe(dark["--danger"]);
  });

  test("toast palettes mirror their named tokens per mode", () => {
    const light = paletteOf(extensionCss, "light");
    const dark = paletteOf(extensionCss, "dark");
    expect(TOAST_LIGHT).toEqual({
      surface: light["--surface-3"],
      text: light["--text-1"],
      textSecondary: light["--text-2"],
      edgeStrong: light["--edge-strong"],
      control: light["--surface-0"],
    });
    expect(TOAST_DARK).toEqual({
      surface: dark["--surface-3"],
      text: dark["--text-1"],
      textSecondary: dark["--text-2"],
      edgeStrong: dark["--edge-strong"],
      control: dark["--surface-4"],
    });
  });
});
