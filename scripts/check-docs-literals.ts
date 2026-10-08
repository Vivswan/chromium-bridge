#!/usr/bin/env bun

// Docs-literal parity gate: the living docs must state the canonical identifiers, paths, and protocol
// versions exactly as the code defines them, or a rename in the code leaves the troubleshooting and
// security docs quietly wrong. The values come from the generated contract modules (rebuilt from the Rust
// core by the gen-shared task this gate depends on), plus two the Rust core does not own: the
// fleet's release bundle name, which no file in this repository carries, and the extension manifest's
// Chrome floor.
//
//   FAMILY    every doc token shaped like an identifier must be a current canonical value  -> the stale copy a rename leaves
//   PRESENCE  a doc whose job is to state a value must contain the current one              -> the doc that never got the new value

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MINIMUM_CHROME_VERSION } from "../src/apps/extension/src/lib/shared/manifest-surface";
import { CHALLENGE_DOMAIN } from "../src/packages/shared/generated/enclave";
import {
  AUDIT_DEFAULT_LIMIT,
  BROWSER_KEYS,
  CLIENT_NAME_ENV,
  KEYCHAIN_LABEL,
  LOCK_FILENAME,
  LOG_FORMAT_ENV,
  LOG_FORMATS,
  LOG_LEVEL_ENV,
  LOG_LEVELS,
} from "../src/packages/shared/generated/host";
import { NATIVE_HOST_ID, PINNED_EXTENSION_ID } from "../src/packages/shared/generated/identity";
import {
  BRIDGE_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION,
} from "../src/packages/shared/generated/protocol";

export interface Violation {
  doc: string;
  line: number;
  message: string;
}

/** A bare release-level bundle filename in prose: `attestation.<ext...>`, not
 * preceded by another filename's characters (so the per-asset
 * `<asset>.attestation.jsonl` bundles, named by the repo-owned
 * update-release.yml, never match) and extended to the end of the token (so
 * `attestation.json.sig` is compared whole, never by its prefix). */
export const BUNDLE_TOKEN = /(?<![\w.-])attestation\.[\w.-]*\w/g;

/** Mirrors `BUNDLE_NAME` in the fleet's fleet-release-publish.yml, which no file here carries, so a fleet
 * rename is a manual update; SECURITY.md tells users to pass it to `gh attestation verify --bundle`. It must
 * match [`BUNDLE_TOKEN`], or no doc could satisfy the family check. */
export const RELEASE_BUNDLE_NAME = "attestation.json";

export const CHROME_VERSION_TOKEN = /\bChrom(?:e|ium) \d+\b/g;

export function familyViolations(
  doc: string,
  text: string,
  label: string,
  family: RegExp,
  allowed: ReadonlySet<string>,
): Violation[] {
  const out: Violation[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const m of lines[i]?.matchAll(family) ?? []) {
      if (!allowed.has(m[0])) {
        out.push({
          doc,
          line: i + 1,
          message: `stale ${label} "${m[0]}" (canonical: ${[...allowed].join(", ")})`,
        });
      }
    }
  }
  return out;
}

export function mcpLineViolations(doc: string, text: string, canonical: string): Violation[] {
  const out: Violation[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (!line.includes("MCP")) continue;
    for (const m of line.matchAll(/\b\d{4}-\d{2}-\d{2}\b/g)) {
      if (m[0] !== canonical) {
        out.push({
          doc,
          line: i + 1,
          message: `MCP protocol version "${m[0]}" differs from the code's "${canonical}"`,
        });
      }
    }
  }
  return out;
}

/** The docs name BRIDGE_PROTOCOL_VERSION beside its value (the compatibility table, the README version
 * rows), so the backticked integers on those lines are the copies. */
export function bridgeVersionLineViolations(
  doc: string,
  text: string,
  canonical: string,
): Violation[] {
  const out: Violation[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (!line.includes("BRIDGE_PROTOCOL_VERSION")) continue;
    for (const m of line.matchAll(/`(\d+)`/g)) {
      if (m[1] !== canonical) {
        out.push({
          doc,
          line: i + 1,
          message: `bridge protocol version "${m[1]}" differs from the code's "${canonical}"`,
        });
      }
    }
  }
  return out;
}

/** TOKEN-PRESENCE check: the doc must name the literal as a whole `family`
 * token. A substring test would let a superstring stand in for it (the
 * per-asset `<asset>.attestation.jsonl` contains `attestation.json`). */
export function tokenPresenceViolation(
  doc: string,
  text: string,
  family: RegExp,
  literal: string,
  label: string,
): Violation | null {
  for (const m of text.matchAll(family)) {
    if (m[0] === literal) return null;
  }
  return { doc, line: 0, message: `must state the canonical ${label} "${literal}"` };
}

export function presenceViolation(
  doc: string,
  text: string,
  literal: string,
  label: string,
): Violation | null {
  if (text.includes(literal)) return null;
  return { doc, line: 0, message: `must state the canonical ${label} "${literal}"` };
}

/** Bounded so a copy that kept a retired key, or grew one, before or after the canonical run does not
 * count as current. */
function boundedListRegex(items: readonly string[]): RegExp {
  const escaped = RegExp.escape(items.join(", "));
  return new RegExp(`(?<![a-z0-9-], )${escaped}(?!, [a-z0-9-])`, "g");
}

/** Counts bounded copies anywhere in the doc. Prefer [`listSectionViolations`] when the copies must live
 * in named paragraphs: a bare count lets an unrelated correct copy mask a drifted one. */
export function listPresenceViolation(
  doc: string,
  text: string,
  items: readonly string[],
  label: string,
  occurrences = 1,
): Violation | null {
  const normalized = text.replaceAll("`", "").replace(/\s+/g, " ");
  const found = normalized.match(boundedListRegex(items))?.length ?? 0;
  if (found >= occurrences) return null;
  return {
    doc,
    line: 0,
    message:
      `must state the canonical ${label} "${items.join(", ")}" in all ${occurrences} ` +
      `place(s) that list it; found ${found}`,
  };
}

/** Each anchor's paragraph is checked in isolation, so a drift in one list fails even when a correct copy
 * exists elsewhere. */
export function listSectionViolations(
  doc: string,
  text: string,
  items: readonly string[],
  label: string,
  anchors: readonly string[],
): Violation[] {
  const out: Violation[] = [];
  const joined = items.join(", ");
  for (const anchor of anchors) {
    const idx = text.indexOf(anchor);
    if (idx === -1) {
      out.push({
        doc,
        line: 0,
        message: `must contain the "${anchor}" section that lists the ${label}`,
      });
      continue;
    }
    // The paragraph the anchor starts: up to the next blank line, so a
    // wrapped list is included and a copy in a different paragraph is not.
    const rest = text.slice(idx);
    const paraEnd = rest.search(/\n\s*\n/);
    const window = paraEnd === -1 ? rest : rest.slice(0, paraEnd);
    const normalized = window.replaceAll("`", "").replace(/\s+/g, " ");
    if (!boundedListRegex(items).test(normalized)) {
      out.push({
        doc,
        line: text.slice(0, idx).split("\n").length,
        message: `the "${anchor}" section must state the canonical ${label} "${joined}"`,
      });
    }
  }
  return out;
}

/** Whole-word matches on both sides, each with the input that motivated it:
 *   GENKAN_LOG must not be satisfied by GENKAN_LOG_FORMAT  -> the env var name is matched as a word
 *   "errors" must not stand in for "error"         -> each accepted value is matched as a word */
export function envTableViolations(
  doc: string,
  text: string,
  name: string,
  values: readonly string[],
): Violation[] {
  const nameWord = new RegExp(`\\b${name}\\b`);
  const rows = text
    .split("\n")
    .filter((l) => nameWord.test(l))
    .join("\n");
  if (rows === "") return [{ doc, line: 0, message: `must document the ${name} env var` }];
  return values
    .filter((v) => !new RegExp(`\\b${v}\\b`).test(rows))
    .map((v) => ({
      doc,
      line: 0,
      message: `documents ${name} but not its accepted value "${v}"`,
    }));
}

if (import.meta.main) {
  const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
  /** Read a doc named by a rule below; a rename must surface as this gate's
   * own failure, not a bare ENOENT stack. */
  const readDoc = (p: string): string => {
    try {
      return readFileSync(resolve(root, p), "utf8");
    } catch (err) {
      throw new Error(`cannot read ${p} (renamed? update its entries in this check): ${err}`);
    }
  };

  const bridgeVersion = String(BRIDGE_PROTOCOL_VERSION);
  const auditLimit = String(AUDIT_DEFAULT_LIMIT);

  // Scope: living markdown only. CHANGELOG.md is release history; sources and
  // tests have their own gates. The security
  // policy sits in GitHub's community-health directory, so it is named here -
  // the rest of .github/ (agent instructions, templates) stays out of scope.
  const docs = execFileSync("git", ["ls-files", "*.md", "docs/**/*.md"], {
    cwd: root,
    encoding: "utf8",
  })
    .split("\n")
    .filter(
      (p) =>
        p !== "" &&
        p !== "CHANGELOG.md" &&
        (!p.includes("/") || p.startsWith("docs/") || p === ".github/SECURITY.md"),
    );

  const violations: Violation[] = [];
  const families: Array<{
    label: string;
    family: RegExp;
    allowed: ReadonlySet<string>;
  }> = [
    {
      // Any reverse-DNS identifier in our namespace must be one of the
      // current canonical values: the host id (and its manifest filename
      // form) and the enclave keychain label. Anything else fails by design
      // until it is added here alongside its own canonical source.
      label: "bridge identifier",
      family: /com\.vivswan\.[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?/g,
      allowed: new Set([NATIVE_HOST_ID, `${NATIVE_HOST_ID}.json`, KEYCHAIN_LABEL]),
    },
    {
      label: "extension id",
      family: /\b[a-p]{32}\b/g,
      allowed: new Set([PINNED_EXTENSION_ID]),
    },
    {
      label: "lock filename",
      family: /\brun(?:\.v\d+)?\.lock\b/g,
      allowed: new Set([LOCK_FILENAME]),
    },
    {
      // The presence spelling stays in the family so a doc naming the retired per-action presence domain fails.
      label: "enclave domain string",
      family: /genkan-(?:enclave|presence)-v\d+/g,
      allowed: new Set([CHALLENGE_DOMAIN]),
    },
    {
      label: "GENKAN_LOG env var",
      family: /\bGENKAN_LOG[A-Z0-9_]*/g,
      allowed: new Set([LOG_LEVEL_ENV, LOG_FORMAT_ENV]),
    },
    {
      label: "client-name env var",
      family: /\bGENKAN_CLIENT[A-Z0-9_]*/g,
      allowed: new Set([CLIENT_NAME_ENV]),
    },
    {
      label: "release attestation bundle",
      family: BUNDLE_TOKEN,
      allowed: new Set([RELEASE_BUNDLE_NAME]),
    },
    {
      // The manifest's floor is the only Chrome version the living docs name, so any other is a stale copy.
      label: "minimum Chrome version",
      family: CHROME_VERSION_TOKEN,
      allowed: new Set([`Chrome ${MINIMUM_CHROME_VERSION}`, `Chromium ${MINIMUM_CHROME_VERSION}`]),
    },
  ];
  for (const doc of docs) {
    const text = readDoc(doc);
    for (const f of families) {
      violations.push(...familyViolations(doc, text, f.label, f.family, f.allowed));
    }
    violations.push(...mcpLineViolations(doc, text, MCP_PROTOCOL_VERSION));
    violations.push(...bridgeVersionLineViolations(doc, text, bridgeVersion));
  }

  const presences: Array<[string, string, string]> = [
    [".github/SECURITY.md", NATIVE_HOST_ID, "native host id"],
    [".github/SECURITY.md", KEYCHAIN_LABEL, "enclave keychain label"],
    [".github/SECURITY.md", PINNED_EXTENSION_ID, "pinned extension id"],
    [".github/SECURITY.md", CHALLENGE_DOMAIN, "enclave challenge domain"],
    ["docs/release.md", PINNED_EXTENSION_ID, "pinned extension id"],
    ["docs/architecture.md", NATIVE_HOST_ID, "native host id"],
    ["docs/architecture.md", KEYCHAIN_LABEL, "enclave keychain label"],
    ["docs/architecture.md", LOCK_FILENAME, "lock filename"],
    ["docs/architecture.md", MCP_PROTOCOL_VERSION, "MCP protocol version"],
    ["docs/troubleshooting.md", NATIVE_HOST_ID, "native host id"],
    ["docs/troubleshooting.md", LOCK_FILENAME, "lock filename"],
    ["docs/release.md", `date string \`${MCP_PROTOCOL_VERSION}\``, "MCP protocol version row"],
    ["docs/release.md", `currently \`${bridgeVersion}\``, "bridge protocol version row"],
    ["docs/security/trust-boundaries.md", CLIENT_NAME_ENV, "client-name env var"],
    ["README.md", MCP_PROTOCOL_VERSION, "MCP protocol version"],
    // The pages that walk a user through loading the extension, and the platform-support statement.
    ["README.md", `Chrome ${MINIMUM_CHROME_VERSION}`, "minimum Chrome version"],
    ["docs/quickstart.md", `Chrome ${MINIMUM_CHROME_VERSION}`, "minimum Chrome version"],
    [".github/SECURITY.md", `Chrome ${MINIMUM_CHROME_VERSION}`, "minimum Chrome version"],
    ["docs/development.md", LOG_LEVEL_ENV, "log env var name"],
    // Since --help interpolates these consts, docs/cli.md holds the only
    // hand-written copies of the audit --limit default and the browser key list.
    ["docs/cli.md", `last ${auditLimit} records`, "audit --limit default"],
  ];
  for (const [doc, literal, label] of presences) {
    const v = presenceViolation(doc, readDoc(doc), literal, label);
    if (v) violations.push(v);
  }
  // The docs that tell users which bundle to verify against must name the
  // release-level one as a whole token, not inside a per-asset bundle name.
  for (const doc of [".github/SECURITY.md", "docs/release.md"]) {
    const v = tokenPresenceViolation(
      doc,
      readDoc(doc),
      BUNDLE_TOKEN,
      RELEASE_BUNDLE_NAME,
      "release attestation bundle",
    );
    if (v) violations.push(v);
  }
  // docs/cli.md lists the keys in two specific paragraphs: the doctor /
  // status prose ("for each known browser (...)") and the "Known browser
  // keys" reference. Each is pinned to its own paragraph, so a drift in
  // either fails even if a correct copy exists elsewhere in the doc.
  violations.push(
    ...listSectionViolations(
      "docs/cli.md",
      readDoc("docs/cli.md"),
      BROWSER_KEYS,
      "browser key list",
      ["for each known browser", "Known browser keys"],
    ),
  );

  for (const doc of ["README.md", "docs/cli.md"]) {
    const text = readDoc(doc);
    violations.push(...envTableViolations(doc, text, LOG_LEVEL_ENV, LOG_LEVELS));
    violations.push(...envTableViolations(doc, text, LOG_FORMAT_ENV, LOG_FORMATS));
  }

  if (violations.length > 0) {
    for (const v of violations) {
      console.error(`${v.doc}${v.line > 0 ? `:${v.line}` : ""}: ${v.message}`);
    }
    console.error(
      `\ncheck-docs-literals: ${violations.length} stale or missing doc literal(s). ` +
        "The canonical values are the generated contract modules in src/packages/shared/generated " +
        "(identity, enclave, protocol, host, each emitted from the Rust core), " +
        "RELEASE_BUNDLE_NAME (this script, mirroring the fleet's publish leg), and the extension's " +
        "manifest surface (src/apps/extension/src/lib/shared/manifest-surface.ts); update the docs to match.",
    );
    process.exit(1);
  }
  console.log(
    `check-docs-literals: ${docs.length} living docs agree with the canonical ` +
      `literals (host id, extension id, keychain label, ${LOCK_FILENAME}, enclave domains, ` +
      `MCP ${MCP_PROTOCOL_VERSION}, bridge v${bridgeVersion}, ${LOG_LEVEL_ENV}/${LOG_FORMAT_ENV}, ` +
      `audit --limit ${auditLimit}, browser keys ${BROWSER_KEYS.join(",")}, ` +
      `release bundle ${RELEASE_BUNDLE_NAME}, Chrome ${MINIMUM_CHROME_VERSION}+)`,
  );
}
