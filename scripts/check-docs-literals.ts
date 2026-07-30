#!/usr/bin/env bun

// Docs-literal parity gate: the living docs must state the canonical
// identifiers, paths, and protocol versions exactly as the code defines them.
// The SSoT audit found these literals hand-copied into AGENTS.md, SECURITY.md,
// the READMEs, and docs/ with nothing checking them, so a rename in the code
// (host id, keychain label, run.lock -> run.v2.lock, an MCP version re-pin, a
// BB_LOG rename) would leave the troubleshooting and security docs quietly
// wrong - the docs a user follows when registration or pairing breaks.
//
// Like scripts/check-extension-id.ts, the canonical values are read from the
// Rust source TEXT (no cargo needed):
//
//   - native host id + pinned extension id  src/packages/core/src/identity.rs
//   - enclave keychain label                src/packages/core/src/enclave/mod.rs
//   - enclave domain-separation strings     src/packages/core/src/enclave/challenge.rs
//   - run.lock filename                     src/packages/core/src/ipc/lockfile.rs
//   - MCP protocol version                  src/packages/core/src/mcp_server.rs
//                                           (or an MCP_PROTOCOL_VERSION const in protocol.rs)
//   - client-name env var                   src/packages/core/src/mcp_server.rs
//   - bridge protocol version               src/packages/core/src/protocol.rs
//   - BB_* env var names and value sets     src/packages/core/src/log.rs
//
// Two kinds of assertion, both fail-closed on a missing canonical value:
//
//   - FAMILY: every doc token matching an identifier's shape (any
//     com.vivswan.* name, any [a-p]{32} id, any run*.lock filename, any
//     chromium-bridge-*-vN domain, any BB_LOG* var) must be a current
//     canonical value. This catches the stale copy a rename leaves behind.
//   - PRESENCE: the docs whose job is to state a value (AGENTS.md, SECURITY.md,
//     docs/compatibility.md, the BB_LOG tables) must contain the current one.
//     This catches the doc that never got the new value at all.
//
// Scope: the root *.md files (minus CHANGELOG.md, release history) and
// docs/**, EXCLUDING docs/adr/ - ADRs are point-in-time records and keep the
// identifiers they were decided with (the audit's genre exemption).

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface Violation {
  doc: string;
  line: number;
  message: string;
}

/** Extract a `[pub] const NAME: &str = "..."` literal from Rust source text.
 * Block comments are stripped first and the match is anchored to a
 * declaration at the start of a line, so a commented-out copy (either
 * comment style) can never be mistaken for the canonical value. Throws when
 * absent: a canonical value this gate cannot find must fail the gate (the
 * extraction pattern needs updating), never weaken it. */
export function rustStrConst(src: string, name: string, file: string): string {
  const uncommented = src.replace(/\/\*[\s\S]*?\*\//g, "");
  const m = uncommented.match(
    new RegExp(`^\\s*(?:pub(?:\\([^)]*\\))?\\s+)?const ${name}: &str = "([^"]+)"`, "m"),
  );
  if (!m?.[1]) throw new Error(`cannot find const ${name} in ${file}`);
  return m[1];
}

/** The lock filename from `runtime_dir().join("run.lock")` in lockfile.rs.
 * Anchored on the join call so the pre-planned rename to run.v2.lock is
 * picked up from the code, not hard-coded here. */
export function lockFilename(lockfileSrc: string): string {
  const m = lockfileSrc.match(/runtime_dir\(\)\.join\("(run[^"]*\.lock)"\)/);
  if (!m?.[1]) throw new Error("cannot find the run.lock join in ipc/lockfile.rs");
  return m[1];
}

/** The MCP protocol version. Today it is the literal in mcp_server.rs's
 * initialize result; a hoisted MCP_PROTOCOL_VERSION const in protocol.rs (the
 * audit's 4.1.5) is checked first so this gate survives that refactor. */
export function mcpProtocolVersion(protocolSrc: string, mcpServerSrc: string): string {
  const hoisted = protocolSrc.match(/MCP_PROTOCOL_VERSION: &str = "(\d{4}-\d{2}-\d{2})"/);
  if (hoisted?.[1]) return hoisted[1];
  const inline = mcpServerSrc.match(/"protocolVersion": "(\d{4}-\d{2}-\d{2})"/);
  if (inline?.[1]) return inline[1];
  throw new Error("cannot find the MCP protocol version in protocol.rs or mcp_server.rs");
}

export function bridgeProtocolVersion(protocolSrc: string): string {
  const m = protocolSrc.match(/BRIDGE_PROTOCOL_VERSION: u32 = (\d+)/);
  if (!m?.[1]) throw new Error("cannot find BRIDGE_PROTOCOL_VERSION in protocol.rs");
  return m[1];
}

/** Every BB_* env var name log.rs reads. */
export function logEnvVars(logSrc: string): string[] {
  const names = [...logSrc.matchAll(/std::env::var(?:_os)?\("(BB_[A-Z0-9_]+)"\)/g)].map(
    (m) => m[1],
  );
  if (names.length === 0) throw new Error("cannot find any BB_* env var reads in log.rs");
  return [...new Set(names)] as string[];
}

/** The accepted lowercase values of one env var, from its `match
 * std::env::var("NAME")` block: the explicit `Some("error") | Some("ERROR")`
 * arms (only the lowercase spelling is the documented one) plus the variant
 * the `_ =>` default arm falls back to - the default value is part of the
 * documented set even though no arm spells it out. */
export function envValueSet(logSrc: string, name: string): string[] {
  const block = logSrc.match(new RegExp(`match std::env::var\\("${name}"\\)[^}]*`));
  if (!block) throw new Error(`cannot find the match block for ${name} in log.rs`);
  const values = [...block[0].matchAll(/Some\("([a-z]+)"\)/g)].map((m) => m[1]) as string[];
  const fallback = block[0].match(/_ => \w+::(\w+)/)?.[1]?.toLowerCase();
  if (fallback && !values.includes(fallback)) values.push(fallback);
  if (values.length === 0) throw new Error(`no accepted values parsed for ${name}`);
  return values;
}

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
 * the canonical protocol version. Filename tokens (ADR titles like
 * 0007-mcp-protocol-version-2025-06-18.md keep their minting date forever)
 * are stripped before scanning. */
export function mcpLineViolations(doc: string, text: string, canonical: string): Violation[] {
  const out: Violation[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (!line.includes("MCP")) continue;
    const prose = line.replace(/[A-Za-z0-9._/-]*\.md\b/g, "");
    for (const m of prose.matchAll(/\b\d{4}-\d{2}-\d{2}\b/g)) {
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
  const rust = (p: string) => readFileSync(resolve(root, "src/packages/core/src", p), "utf8");
  /** Read a doc named by a rule below; a rename must surface as this gate's
   * own failure, not a bare ENOENT stack. */
  const readDoc = (p: string): string => {
    try {
      return readFileSync(resolve(root, p), "utf8");
    } catch (err) {
      throw new Error(`cannot read ${p} (renamed? update its entries in this check): ${err}`);
    }
  };

  const identityRs = rust("identity.rs");
  const hostId = rustStrConst(identityRs, "NATIVE_HOST_ID", "identity.rs");
  const extensionId = rustStrConst(identityRs, "PINNED_EXTENSION_ID", "identity.rs");
  const keyLabel = rustStrConst(rust("enclave/mod.rs"), "KEY_LABEL", "enclave/mod.rs");
  const challengeRs = rust("enclave/challenge.rs");
  const challengeDomain = rustStrConst(challengeRs, "CHALLENGE_DOMAIN", "enclave/challenge.rs");
  const presenceDomain = rustStrConst(challengeRs, "PRESENCE_DOMAIN", "enclave/challenge.rs");
  const lockName = lockFilename(rust("ipc/lockfile.rs"));
  const protocolRs = rust("protocol.rs");
  const mcpServerRs = rust("mcp_server.rs");
  const mcpVersion = mcpProtocolVersion(protocolRs, mcpServerRs);
  const clientNameEnv = rustStrConst(mcpServerRs, "CLIENT_NAME_ENV", "mcp_server.rs");
  const bridgeVersion = bridgeProtocolVersion(protocolRs);
  const logRs = rust("log.rs");
  const envNames = logEnvVars(logRs);
  const logLevels = envValueSet(logRs, "BB_LOG");
  const logFormats = envValueSet(logRs, "BB_LOG_FORMAT");
  // The desktop app's bundle id, canonical in the Tauri config.
  const bundleId = (
    JSON.parse(readFileSync(resolve(root, "src/apps/desktop/tauri.conf.json"), "utf8")) as {
      identifier?: unknown;
    }
  ).identifier;
  if (typeof bundleId !== "string" || !bundleId.startsWith("com.vivswan.")) {
    throw new Error("cannot find the bundle identifier in src/apps/desktop/tauri.conf.json");
  }

  // Scope: living markdown only. ADRs are point-in-time records; CHANGELOG.md
  // is release history; sources and tests have their own gates.
  const docs = execFileSync("git", ["ls-files", "*.md", "docs/**/*.md"], {
    cwd: root,
    encoding: "utf8",
  })
    .split("\n")
    .filter(
      (p) =>
        p !== "" &&
        p !== "CHANGELOG.md" &&
        !p.startsWith("docs/adr/") &&
        (!p.includes("/") || p.startsWith("docs/")),
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
      // form), the enclave keychain label, and the desktop app's bundle id
      // (canonical in tauri.conf.json). Anything else fails by design until
      // it is added here alongside its own canonical source.
      label: "bridge identifier",
      family: /com\.vivswan\.[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?/g,
      allowed: new Set([hostId, `${hostId}.json`, keyLabel, bundleId]),
    },
    {
      label: "extension id",
      family: /\b[a-p]{32}\b/g,
      allowed: new Set([extensionId]),
    },
    {
      label: "lock filename",
      family: /\brun(?:\.v\d+)?\.lock\b/g,
      allowed: new Set([lockName]),
    },
    {
      label: "enclave domain string",
      family: /chromium-bridge-(?:enclave|presence)-v\d+/g,
      allowed: new Set([challengeDomain, presenceDomain]),
    },
    {
      label: "BB_LOG env var",
      family: /\bBB_LOG[A-Z0-9_]*/g,
      allowed: new Set(envNames),
    },
    {
      label: "client-name env var",
      family: /\bCHROMIUM_BRIDGE_[A-Z0-9_]+\b/g,
      allowed: new Set([clientNameEnv]),
    },
  ];
  for (const doc of docs) {
    const text = readDoc(doc);
    for (const f of families) {
      violations.push(...familyViolations(doc, text, f.label, f.family, f.allowed));
    }
    // docs/README.md's ADR index restates historical ADR titles in prose;
    // every other doc's MCP-version mentions must be current.
    if (doc !== "docs/README.md") {
      violations.push(...mcpLineViolations(doc, text, mcpVersion));
    }
    violations.push(...bridgeVersionLineViolations(doc, text, bridgeVersion));
  }

  // The docs whose job is to state a value must state the current one.
  const presences: Array<[string, string, string]> = [
    ["AGENTS.md", hostId, "native host id"],
    ["AGENTS.md", keyLabel, "enclave keychain label"],
    ["SECURITY.md", hostId, "native host id"],
    ["SECURITY.md", keyLabel, "enclave keychain label"],
    ["SECURITY.md", extensionId, "pinned extension id"],
    ["SECURITY.md", challengeDomain, "enclave challenge domain"],
    ["docs/chrome-web-store.md", extensionId, "pinned extension id"],
    ["docs/architecture.md", hostId, "native host id"],
    ["docs/architecture.md", keyLabel, "enclave keychain label"],
    ["docs/architecture.md", lockName, "lock filename"],
    ["docs/architecture.md", mcpVersion, "MCP protocol version"],
    ["docs/operations.md", lockName, "lock filename"],
    ["docs/wsl.md", hostId, "native host id"],
    ["docs/wsl.md", lockName, "lock filename"],
    ["docs/compatibility.md", `date string \`${mcpVersion}\``, "MCP protocol version row"],
    ["docs/compatibility.md", `currently \`${bridgeVersion}\``, "bridge protocol version row"],
    ["docs/security/threat-model.md", clientNameEnv, "client-name env var"],
    ["README.md", mcpVersion, "MCP protocol version"],
    ["docs/development.md", "BB_LOG", "log env var name"],
  ];
  for (const [doc, literal, label] of presences) {
    const v = presenceViolation(doc, readDoc(doc), literal, label);
    if (v) violations.push(v);
  }

  // The env-var reference tables must enumerate the full accepted value sets.
  for (const doc of ["README.md", "docs/operations.md", "docs/cli.md"]) {
    const text = readDoc(doc);
    violations.push(...envTableViolations(doc, text, "BB_LOG", logLevels));
    violations.push(...envTableViolations(doc, text, "BB_LOG_FORMAT", logFormats));
  }

  if (violations.length > 0) {
    for (const v of violations) {
      console.error(`${v.doc}${v.line > 0 ? `:${v.line}` : ""}: ${v.message}`);
    }
    console.error(
      `\ncheck-docs-literals: ${violations.length} stale or missing doc literal(s). ` +
        "The canonical values live in the Rust core (identity.rs, enclave/, " +
        "ipc/lockfile.rs, protocol.rs, mcp_server.rs, log.rs); update the docs to match.",
    );
    process.exit(1);
  }
  console.log(
    `check-docs-literals: ${docs.length} living docs agree with the canonical ` +
      `literals (host id, extension id, keychain label, ${lockName}, enclave domains, ` +
      `MCP ${mcpVersion}, bridge v${bridgeVersion}, ${envNames.join("/")})`,
  );
}
