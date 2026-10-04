#!/usr/bin/env bun
// The second reader of architecture.yml: the module map, spliced between the
// page's `<!-- BEGIN GENERATED: <name> (hint) -->` and `<!-- END GENERATED: <name> -->`
// markers. The ci gate runs it with --check so a stale map fails; `moon run
// gen-architecture-map` rewrites it.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  DEFAULT_CONFIG,
  pathLabel,
  readArchitecture,
  renderArchitectureMermaid,
} from "./arch-lint";
import { readPage } from "./markdown-page";
import { realpath } from "./repo-paths";

export const DEFAULT_REGION = "architecture-map";

// The name is spliced into a regex unescaped, so only regex-literal characters are admitted.
const REGION_NAME = /^[a-z0-9-]+$/;

/** A marker is a line of its own (up to three spaces in); one quoted mid-line or under `> ` is page text. */
function markerPattern(kind: "BEGIN" | "END", name: string): RegExp {
  const hint = kind === "BEGIN" ? String.raw`(?: \([^)\n]*\))?` : "";
  return new RegExp(`^ {0,3}<!-- ${kind} GENERATED: ${name}${hint} -->[ \\t]*\\r?$`, "gm");
}

/** Exactly one BEGIN then one END for `name`, else a throw naming the counts: a second marker pair would splice into the wrong one silently. */
export function regionBounds(text: string, name: string): { bodyStart: number; bodyEnd: number } {
  if (!REGION_NAME.test(name)) {
    throw new Error(`a region name is lowercase letters, digits, and dashes; got "${name}"`);
  }
  // A marker quoted inside a fence is page text about markers, not a region;
  // line counting on the raw text keeps the offsets the splice needs.
  const page = readPage(text);
  const live = (match: RegExpExecArray): boolean =>
    page.text[text.slice(0, match.index).split("\n").length - 1] !== undefined;
  const begins = [...text.matchAll(markerPattern("BEGIN", name))].filter(live);
  const ends = [...text.matchAll(markerPattern("END", name))].filter(live);
  const [begin] = begins;
  const [end] = ends;
  if (begin === undefined || end === undefined || begins.length !== 1 || ends.length !== 1) {
    throw new Error(
      `region "${name}" needs exactly one BEGIN and one END marker, found ${begins.length} and ${ends.length}`,
    );
  }
  if (end.index < begin.index + begin[0].length) {
    throw new Error(`region "${name}" has its END marker before its BEGIN marker`);
  }
  return { bodyStart: begin.index + begin[0].length, bodyEnd: end.index };
}

export function spliceMap(text: string, name: string, map: string): string {
  const { bodyStart, bodyEnd } = regionBounds(text, name);
  return `${text.slice(0, bodyStart)}\n\`\`\`mermaid\n${map}\n\`\`\`\n${text.slice(bodyEnd)}`;
}

const USAGE = [
  "usage: render-architecture-map.ts --page <path> [--config <architecture.yml>] [--root <dir>] [--region <name>] [--check]",
  "  --page     the markdown page carrying the generated region",
  "  --config   the layering declaration (default: <root>/architecture.yml)",
  "  --root     the repository root (default: cwd)",
  `  --region   the generated region's name (default: ${DEFAULT_REGION})`,
  "  --check    exit 1 when the committed region differs, instead of rewriting it",
  "exit 0: written or already current; 1: drift under --check; 2: usage, no region, or an unreadable declaration",
].join("\n");

interface CliOptions {
  page: string;
  root: string;
  config: string;
  region: string;
  check: boolean;
}

function parseArgs(argv: readonly string[]): CliOptions {
  let root = realpath(process.cwd());
  let page: string | undefined;
  let config: string | undefined;
  let region = DEFAULT_REGION;
  let check = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = (): string => {
      const next = argv[++i];
      if (next === undefined) throw new Error(`${arg} needs a value\n${USAGE}`);
      return next;
    };
    if (arg === "--root") root = realpath(value());
    else if (arg === "--page") page = realpath(value());
    else if (arg === "--config") config = realpath(value());
    else if (arg === "--region") region = value();
    else if (arg === "--check") check = true;
    else throw new Error(`unknown argument: ${arg}\n${USAGE}`);
  }
  if (page === undefined) throw new Error(`--page is required\n${USAGE}`);
  return { page, root, config: config ?? join(root, DEFAULT_CONFIG), region, check };
}

if (import.meta.main) {
  let options: CliOptions;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(2);
  }
  const pageLabel = pathLabel(options.root, options.page);
  const configLabel = pathLabel(options.root, options.config);
  if (!existsSync(options.page)) {
    console.error(`render-architecture-map: ${pageLabel} does not exist`);
    process.exit(2);
  }
  try {
    const current = readFileSync(options.page, "utf8");
    const map = renderArchitectureMermaid(readArchitecture(options.config, configLabel));
    const next = spliceMap(current, options.region, map);
    if (next === current) {
      console.log(`render-architecture-map: ${pageLabel} region ${options.region} is current`);
    } else if (options.check) {
      console.error(
        `render-architecture-map: ${pageLabel} region ${options.region} differs from ${configLabel}; run \`moon run gen-architecture-map\` to rewrite it`,
      );
      process.exit(1);
    } else {
      writeFileSync(options.page, next);
      console.log(`render-architecture-map: wrote ${pageLabel} region ${options.region}`);
    }
  } catch (error) {
    console.error(
      `render-architecture-map: ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exit(2);
  }
}
