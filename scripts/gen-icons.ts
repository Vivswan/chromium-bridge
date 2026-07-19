#!/usr/bin/env bun
// Render the Gatedeck icon rasters from the committed SVG sources
// (assets/icon/). The PNG and .icns rasters are build artifacts: they are
// generated here, gitignored, and never committed (the SVGs are the single
// source of truth).
//
//   bun scripts/gen-icons.ts             # extension + desktop
//   bun scripts/gen-icons.ts extension   # extension toolbar/store icons only
//   bun scripts/gen-icons.ts desktop     # desktop app icon (.png + .icns) only
//
// Rendering uses @resvg/resvg-js (resvg compiled to a native module): pure
// build tooling, no runtime or security surface. The .icns is assembled with
// macOS iconutil and is skipped, with a log line, on other platforms - only
// the macOS bundle (just bundle-app, CI's desktop job) needs it.

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Resvg } from "@resvg/resvg-js";
import { die, repoRoot } from "./lib.ts";

const svgDir = join(repoRoot, "assets/icon");
const extensionIconDir = join(repoRoot, "src/apps/extension/src/public/icons");
const desktopIconDir = join(repoRoot, "src/apps/desktop/icons");

function renderPng(svgFile: string, size: number): Buffer {
  const svg = readFileSync(join(svgDir, svgFile), "utf8");
  const rendered = new Resvg(svg, { fitTo: { mode: "width", value: size } }).render();
  if (rendered.width !== size || rendered.height !== size) {
    die(`${svgFile} rendered ${rendered.width}x${rendered.height}, expected ${size}x${size}`);
  }
  return rendered.asPng();
}

function emit(outDir: string, name: string, png: Buffer) {
  writeFileSync(join(outDir, name), png);
  console.log(`gen-icons: wrote ${join(outDir, name)} (${png.length} bytes)`);
}

// The output dirs hold only generated files: recreate them from scratch so a
// renamed or dropped raster cannot linger from an older run.
function resetDir(dir: string) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
}

function generateExtensionIcons() {
  resetDir(extensionIconDir);
  // 16px comes from the hand-cut toolbar art (pixel-grid snapped); the larger
  // sizes render the full mark, which has room to breathe at 48+.
  emit(extensionIconDir, "icon16.png", renderPng("gatedeck-toolbar-16.svg", 16));
  emit(extensionIconDir, "icon48.png", renderPng("gatedeck.svg", 48));
  emit(extensionIconDir, "icon128.png", renderPng("gatedeck.svg", 128));
}

// The Apple iconset ladder: file name in the .iconset -> pixel size.
const ICONSET_LADDER: ReadonlyArray<[string, number]> = [
  ["icon_16x16.png", 16],
  ["icon_16x16@2x.png", 32],
  ["icon_32x32.png", 32],
  ["icon_32x32@2x.png", 64],
  ["icon_128x128.png", 128],
  ["icon_128x128@2x.png", 256],
  ["icon_256x256.png", 256],
  ["icon_256x256@2x.png", 512],
  ["icon_512x512.png", 512],
  ["icon_512x512@2x.png", 1024],
];

function generateDesktopIcons() {
  resetDir(desktopIconDir);
  const bySize = new Map<number, Buffer>();
  for (const size of new Set(ICONSET_LADDER.map(([, s]) => s))) {
    bySize.set(size, renderPng("gatedeck-app-icon.svg", size));
  }
  emit(desktopIconDir, "icon.png", bySize.get(1024) as Buffer);

  if (process.platform !== "darwin") {
    console.log("gen-icons: skipping icon.icns (iconutil is macOS-only; nothing else needs it)");
    return;
  }
  const iconset = mkdtempSync(join(tmpdir(), "gatedeck-iconset-"));
  const iconsetDir = join(iconset, "icon.iconset");
  mkdirSync(iconsetDir);
  try {
    for (const [name, size] of ICONSET_LADDER) {
      writeFileSync(join(iconsetDir, name), bySize.get(size) as Buffer);
    }
    const icnsPath = join(desktopIconDir, "icon.icns");
    const result = spawnSync("iconutil", ["-c", "icns", iconsetDir, "-o", icnsPath], {
      stdio: ["ignore", "inherit", "inherit"],
    });
    // Thrown (not die(): process.exit would skip the finally cleanup below).
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`iconutil failed (exit ${result.status})`);
    console.log(`gen-icons: wrote ${icnsPath}`);
  } finally {
    rmSync(iconset, { recursive: true, force: true });
  }
}

const scopes = process.argv.slice(2);
for (const scope of scopes) {
  if (scope !== "extension" && scope !== "desktop") {
    die(`unknown scope "${scope}" (expected "extension" or "desktop")`);
  }
}
if (scopes.length === 0 || scopes.includes("extension")) generateExtensionIcons();
if (scopes.length === 0 || scopes.includes("desktop")) generateDesktopIcons();
