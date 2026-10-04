#!/usr/bin/env bun
// Render the Gatedeck extension icon rasters from the committed SVG sources
// (assets/icon/). The PNG rasters are build artifacts: they are generated
// here, gitignored, and never committed (the SVGs are the single source of
// truth).
//
//   bun scripts/gen-icons.ts   # extension toolbar/store icons
//
// Rendering uses @resvg/resvg-js (resvg compiled to a native module): pure
// build tooling, no runtime or security surface.

import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Resvg } from "@resvg/resvg-js";
import { die, repoRoot } from "./lib.ts";

const svgDir = join(repoRoot, "assets/icon");
const extensionIconDir = join(repoRoot, "src/apps/extension/src/public/icons");

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

generateExtensionIcons();
