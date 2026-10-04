#!/usr/bin/env bun

// moon.yml's check-uv task says why the interpreter pinned in .python-version must come from uv.

import { die } from "./lib.ts";

export const missingMessage = [
  "uv not found - it provisions the Python pinned in .python-version for the protocol suites",
  "install it via proto (proto install uv), or: curl -LsSf https://astral.sh/uv/install.sh | sh   (or: brew install uv)",
].join("\n");

if (import.meta.main) {
  if (Bun.which("uv") === null) die(missingMessage);
}
