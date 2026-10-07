#!/usr/bin/env bun

// `bun install` runs a package's install lifecycle scripts, so one that reads a build output (the extension's
// former postinstall `wxt prepare`, which loaded a generated contract module) breaks every fresh checkout
// before the first task can build it. Installing dependencies therefore stays plain: no workspace package
// declares a script bun runs at install time; what a package needs built is a moon task that depends on the
// task that builds it.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { die, repoRoot } from "./lib.ts";

/** The lifecycle scripts bun runs during `bun install`. */
export const INSTALL_HOOKS = [
  "preinstall",
  "install",
  "postinstall",
  "preprepare",
  "prepare",
  "postprepare",
] as const;

export interface InstallHook {
  file: string;
  script: (typeof INSTALL_HOOKS)[number];
}

function manifestScripts(root: string, file: string): Record<string, unknown> {
  const parsed = JSON.parse(readFileSync(join(root, file), "utf8")) as { scripts?: unknown };
  const scripts = parsed.scripts ?? {};
  if (typeof scripts !== "object" || scripts === null || Array.isArray(scripts)) {
    throw new Error(`${file}: "scripts" is not an object`);
  }
  return scripts as Record<string, unknown>;
}

export function workspaceManifests(root: string): string[] {
  const parsed = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
    workspaces?: unknown;
  };
  const patterns = Array.isArray(parsed.workspaces) ? parsed.workspaces : [];
  const files = new Set<string>(["package.json"]);
  for (const pattern of patterns) {
    if (typeof pattern !== "string")
      throw new Error(`package.json: workspaces entry ${JSON.stringify(pattern)} is not a string`);
    for (const match of new Bun.Glob(`${pattern}/package.json`).scanSync({ cwd: root })) {
      files.add(match);
    }
  }
  return [...files].sort();
}

export function installHooks(root: string): InstallHook[] {
  const hooks: InstallHook[] = [];
  for (const file of workspaceManifests(root)) {
    const scripts = manifestScripts(root, file);
    for (const script of INSTALL_HOOKS) {
      if (script in scripts) hooks.push({ file, script });
    }
  }
  return hooks;
}

if (import.meta.main) {
  const hooks = installHooks(repoRoot);
  if (hooks.length > 0) {
    die(
      "install-time scripts in the bun workspace (bun install runs them before any task can build what they read; " +
        "a package that needs a build output declares a moon task depending on its builder instead):\n" +
        hooks.map(({ file, script }) => `  ${file}: scripts.${script}`).join("\n"),
    );
  }
  console.log(
    `check-install-hooks: no workspace package declares ${INSTALL_HOOKS.join(", ")}; bun install depends on no build output`,
  );
}
