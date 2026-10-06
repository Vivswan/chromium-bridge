#!/usr/bin/env bun

// Docs-literal parity gate: the living docs must state the canonical identifiers, paths, and protocol
// versions exactly as the code defines them, or a rename in the code leaves the troubleshooting and
// security docs quietly wrong. The values come from the generated contract modules (check-gen keeps
// those equal to the Rust core), so no cargo is needed here, plus two the Rust core does not own: the
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
import { CHALLENGE_DOMAIN } from "../src/packages/shared/src/enclave.gen";
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
} from "../src/packages/shared/src/host.gen";
import { NATIVE_HOST_ID, PINNED_EXTENSION_ID } from "../src/packages/shared/src/identity.gen";
import {
  BRIDGE_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION,
} from "../src/packages/shared/src/protocol.gen";

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

/** The release-level attestation bundle's asset name. Source of truth:
 * the fleet's fleet-release-publish.yml (`BUNDLE_NAME`, the fleet's
 * publish leg the managed ci.yml calls), which no file in this repository
 * carries; SECURITY.md tells users to pass it to `gh attestation verify
 * --bundle`, so a fleet rename is a manual update here, and the test pins
 * that the name is a [`BUNDLE_TOKEN`] itself, or no doc could ever satisfy
 * the family check. */
export const RELEASE_BUNDLE_NAME = "attestation.json";

export const CHROME_VERSION_TOKEN = /\bChrom(?:e|ium) \d+\b/g;

/** FAMILY check: every match of `family` in the doc must be in `allowed`. */
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

/** MCP-version check: on lines mentioning MCP, every date-shaped token must be
 * the canonical protocol version. */
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

/** Bridge-version check: on lines mentioning BRIDGE_PROTOCOL_VERSION (the
 * compatibility table row and the README version rows all name the constant
 * next to its value), every backticked bare integer must be the current
 * version. */
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

/** PRESENCE check: the doc must contain the literal somewhere. */
export function presenceViolation(
  doc: string,
  text: string,
  literal: string,
  label: string,
): Violation | null {
  if (text.includes(literal)) return null;
  return { doc, line: 0, message: `must state the canonical ${label} "${literal}"` };
}

/** The bounded regex for a comma-joined list: matches the exact run and
 * rejects a superset that kept a retired key (or grew an extra one) before or
 * after the canonical run. Shared by the list checks. */
function boundedListRegex(items: readonly string[]): RegExp {
  const escaped = items.join(", ").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![a-z0-9-], )${escaped}(?!, [a-z0-9-])`, "g");
}

/** LIST-PRESENCE check: the doc must state the exact comma-joined list at
 * least `occurrences` times (tolerating line wraps and `code` spans). The
 * match is bounded: a doc copy that kept a retired key (or grew an extra one)
 * before or after the canonical run does not count as current. Prefer
 * [`listSectionViolations`] when the copies must live in specific paragraphs
 * (a bare count lets an unrelated correct copy mask a drifted one). */
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

/** LIST-SECTION check: the list must appear (bounded, wrap/`code` tolerant)
 * in the paragraph that begins at each `anchor` phrase. Anchoring to the
 * intended paragraphs closes the residual in the bare-count check: a drift in
 * one specific list fails even if a correct copy exists elsewhere in the doc,
 * because each anchor's own window is checked in isolation. */
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

/** ENV-TABLE check: within the doc's lines that mention the env var (as a
 * whole word - BB_LOG must not be satisfied by BB_LOG_FORMAT), every accepted
 * value must appear as a whole word (so "errors" cannot stand in for "error"
 * and the documented value set cannot lag a new or renamed level/format). */
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
      family: /chromium-bridge-(?:enclave|presence)-v\d+/g,
      allowed: new Set([CHALLENGE_DOMAIN]),
    },
    {
      label: "BB_LOG env var",
      family: /\bBB_LOG[A-Z0-9_]*/g,
      allowed: new Set([LOG_LEVEL_ENV, LOG_FORMAT_ENV]),
    },
    {
      label: "client-name env var",
      family: /\bCHROMIUM_BRIDGE_[A-Z0-9_]+\b/g,
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

  // The docs whose job is to state a value must state the current one.
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

  // The env-var reference tables must enumerate the full accepted value sets.
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
        "The canonical values are the generated contract modules in src/packages/shared/src " +
        "(identity, enclave, protocol, host .gen.ts, each emitted from the Rust core), " +
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
