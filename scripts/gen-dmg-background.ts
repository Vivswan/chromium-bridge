#!/usr/bin/env bun

// Render the DMG window background (assets/dmg/background.svg is the source
// of truth; nothing rasterized is committed) into the hidpi TIFF Finder
// expects: a 1x page (660x400 @72dpi) and a 2x page (1320x800 @144dpi)
// combined by macOS `tiffutil -cathidpicheck`.
//
//   bun scripts/gen-dmg-background.ts <out.tiff>
//
// SVG -> PNG uses @resvg/resvg-js (napi bindings to the resvg Rust crate),
// the same rasterizer the icon pipeline is adopting; if a shared gen-icons
// script lands, this can fold into it. macOS-only because of tiffutil (the
// only DMG consumer is the macOS bundle script).

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Resvg } from "@resvg/resvg-js";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const src = resolve(root, "assets/dmg/background.svg");

const out = process.argv[2];
if (out === undefined || out === "") {
  console.error("usage: bun scripts/gen-dmg-background.ts <out.tiff>");
  process.exit(1);
}
if (process.platform !== "darwin") {
  console.error("error: gen-dmg-background is macOS-only (it uses tiffutil)");
  process.exit(1);
}

function run(cmd: string[]): void {
  const proc = Bun.spawnSync(cmd, { stdout: "inherit", stderr: "inherit" });
  if (proc.exitCode !== 0) {
    throw new Error(`${cmd[0]} exited with ${proc.exitCode}`);
  }
}

const svg = await Bun.file(src).text();
const tmp = mkdtempSync(join(tmpdir(), "dmg-bg-"));
let status = 0;
try {
  const pages: string[] = [];
  for (const zoom of [1, 2]) {
    const png = new Resvg(svg, { fitTo: { mode: "zoom", value: zoom } }).render().asPng();
    const page = join(tmp, zoom === 2 ? "background@2x.png" : "background.png");
    writeFileSync(page, png);
    pages.push(page);
  }
  // resvg writes no density metadata, and tiffutil copies each page's DPI
  // from the source PNG - without this stamp the 2x page lands at 72dpi and
  // Finder shows it as an oversized 1x image instead of a Retina variant.
  run(["sips", "-s", "dpiWidth", "144", "-s", "dpiHeight", "144", pages[1] as string]);
  run(["tiffutil", "-cathidpicheck", ...pages, "-out", out]);
  console.log(`dmg background: ${out}`);
} catch (err) {
  console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
  status = 1;
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
process.exit(status);
