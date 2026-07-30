#!/usr/bin/env bun

// Docs-policy parity gate: the security tables users read before trusting or
// relaxing a gate must match the canonical policy sources.
//
//   - docs/security/tool-risk-matrix.md: its per-tool rows (name, Risk, Chrome
//     perm), its "off by default" claims, and every settings key it names are
//     diffed against the generated catalogue metadata
//     (src/packages/shared/src/ops.gen.ts <- catalogue.rs via `moon run gen`,
//     freshness enforced by check-gen) and the settings schema defaults
//     (src/packages/shared/src/settings.ts).
//   - SECURITY.md: the fail-safe-defaults table's Default cells are diffed
//     against the same schema defaults.
//   - The "N tools" headline in all three READMEs and docs/architecture.md is
//     diffed against the catalogue's tool count.
//
// Without this gate the audit's finding stands: add, rename, or re-risk a
// tool (or flip a default) and the project's primary security pitch keeps
// advertising the old policy with every check green.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { OP_NAMES, TOOL_META } from "../src/packages/shared/src/ops.gen";
import { DEFAULTS } from "../src/packages/shared/src/settings";

export interface MatrixRow {
  name: string;
  risk: string;
  perm: string;
  protection: string;
}

/** Parse the risk matrix's per-tool rows: `| \`name\` | Risk | ... | \`perm\` | protection |`. */
export function parseRiskMatrix(md: string): MatrixRow[] {
  const rows: MatrixRow[] = [];
  for (const line of md.split("\n")) {
    const cells = line.split("|").map((c) => c.trim());
    // A tool row: leading empty cell, then a backticked snake_case tool name,
    // in the 7-column table (8 separators -> 9 cells).
    const name = cells[1]?.match(/^`([a-z_]+)`$/)?.[1];
    if (cells.length < 9 || !name) continue;
    const risk = (cells[2] ?? "")
      .replaceAll("*", "")
      .replace(/\[\d+\]/g, "")
      .trim()
      .toLowerCase();
    // The perm cell must LEAD with the backticked permission ("`tabs` (via a
    // routed `tab_list` per browser)"); anchoring keeps a reworded
    // parenthetical from being read as the permission.
    const perm = cells[6]?.match(/^`([a-z_]+)`/)?.[1] ?? "";
    rows.push({ name, risk, perm, protection: cells[7] ?? "" });
  }
  return rows;
}

/** Diff the matrix rows against the catalogue: exact name set, risk, perm. */
export function riskMatrixViolations(
  rows: MatrixRow[],
  names: readonly string[] = OP_NAMES,
  meta: Readonly<Record<string, { risk: string; permission: string }>> = TOOL_META,
): string[] {
  const out: string[] = [];
  const documented = new Set(rows.map((r) => r.name));
  for (const name of names) {
    if (!documented.has(name)) out.push(`tool \`${name}\` is missing from the risk matrix`);
  }
  for (const row of rows) {
    const m = meta[row.name];
    if (!m) {
      out.push(`risk matrix documents \`${row.name}\`, which is not in the catalogue`);
      continue;
    }
    if (row.risk !== m.risk) {
      out.push(`\`${row.name}\` risk is "${row.risk}" but the catalogue says "${m.risk}"`);
    }
    if (row.perm !== m.permission) {
      out.push(
        `\`${row.name}\` Chrome perm is "${row.perm}" but the catalogue says "${m.permission}"`,
      );
    }
  }
  return out;
}

/** The opt-in tools' rows must claim "off by default" exactly when their gate
 * setting defaults to false (and never claim it when it defaults to true). */
export function offByDefaultViolations(
  rows: MatrixRow[],
  matrixMd: string,
  defaults: Readonly<Record<string, unknown>> = DEFAULTS,
  names: readonly string[] = OP_NAMES,
): string[] {
  const out: string[] = [];
  const gates: Array<[tool: string, key: string]> = [
    ["page_upload", "fileUploadEnabled"],
    ["page_handle_dialog", "handleDialogEnabled"],
  ];
  for (const [tool, key] of gates) {
    const row = rows.find((r) => r.name === tool);
    if (!row) {
      // Fail closed on a renamed tool: if the catalogue no longer knows this
      // name either, both this gate and riskMatrixViolations would go silent.
      if (!names.includes(tool)) {
        out.push(`gate entry \`${tool}\` is not a catalogue tool (renamed? update the gates list)`);
      }
      continue; // otherwise the missing row is already a riskMatrixViolations finding
    }
    if (!(key in defaults)) {
      // Fail closed on a renamed gate setting: with `defaults[key]` undefined
      // both arms below would go silent forever.
      out.push(`gate setting \`${key}\` (for \`${tool}\`) is not a settings key in settings.ts`);
      continue;
    }
    const claimsOff = row.protection.toLowerCase().includes("off by default");
    if (defaults[key] === false && !claimsOff) {
      out.push(`\`${tool}\` defaults off (${key}: false) but its row no longer says so`);
    }
    if (defaults[key] !== false && claimsOff) {
      out.push(`\`${tool}\` row claims "off by default" but ${key} defaults to ${defaults[key]}`);
    }
  }
  const cdpOffClaim = /CDP mode \(opt-in, off by default\)/.test(matrixMd);
  if (defaults.cdpMode === false && !cdpOffClaim) {
    out.push(
      'cdpMode defaults off but the matrix no longer says "CDP mode (opt-in, off by default)"',
    );
  }
  if (defaults.cdpMode !== false && cdpOffClaim) {
    out.push(
      `the matrix claims CDP mode is off by default but cdpMode defaults to ${defaults.cdpMode}`,
    );
  }
  return out;
}

/** Matrix tokens that look like settings keys but legitimately are not.
 * Empty today; a backticked camelCase Chrome permission or API name (say
 * `nativeMessaging`) would land here with a reviewed reason, never by
 * loosening the scan. */
export const MATRIX_NON_SETTINGS_TOKENS: ReadonlySet<string> = new Set();

/** Every backticked camelCase token in the matrix must be a real settings key
 * (they are how the doc names the user-configurable gates). */
export function settingsKeyViolations(
  md: string,
  defaults: Readonly<Record<string, unknown>> = DEFAULTS,
  allowed: ReadonlySet<string> = MATRIX_NON_SETTINGS_TOKENS,
): string[] {
  const out: string[] = [];
  for (const m of md.matchAll(/`([a-z]+[A-Z][A-Za-z]*)`/g)) {
    const key = m[1] ?? "";
    if (!(key in defaults) && !allowed.has(key)) {
      out.push(
        `names \`${key}\`, which is not a settings key in settings.ts ` +
          "(a legitimate non-settings token goes in MATRIX_NON_SETTINGS_TOKENS)",
      );
    }
  }
  return out;
}

/** The settings SECURITY.md's fail-safe-defaults table documents. A pinned
 * list, like the repo's other pin tests: dropping (or reformatting away) a
 * row must fail here and force a conscious edit, not vanish silently. Adding
 * a row needs no code change; removing one means updating this pin. */
export const REQUIRED_SECURITY_DEFAULT_ROWS = [
  "confirmPageEval",
  "pageEvalEnabled",
  "touchIdConfirm",
  "confirmHighRiskClick",
  "confirmTabClose",
  "confirmGraceMs",
] as const;

/** Parse SECURITY.md's fail-safe-defaults table (`| \`key\` | \`default\` | ...`)
 * and diff each Default cell against the schema defaults; the pinned row set
 * must all be present. */
export function securityDefaultsViolations(
  securityMd: string,
  defaults: Readonly<Record<string, unknown>> = DEFAULTS,
  requiredRows: readonly string[] = REQUIRED_SECURITY_DEFAULT_ROWS,
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of securityMd.split("\n")) {
    const m = line.match(/^\| `([a-z]+[A-Z][A-Za-z]*)` \| `([^`]+)` \|/);
    const key = m?.[1];
    const cell = m?.[2];
    if (!key || !cell) continue;
    seen.add(key);
    if (!(key in defaults)) {
      out.push(`SECURITY.md documents \`${key}\`, which is not a settings key in settings.ts`);
      continue;
    }
    const canonical = String(defaults[key as keyof typeof defaults]);
    if (cell !== canonical) {
      out.push(
        `SECURITY.md says \`${key}\` defaults to \`${cell}\` but settings.ts says \`${canonical}\``,
      );
    }
  }
  for (const key of requiredRows) {
    if (!seen.has(key)) {
      out.push(
        `SECURITY.md's fail-safe-defaults table lost its \`${key}\` row ` +
          "(or a reformat broke the row parser); restore it or update the pinned row list",
      );
    }
  }
  return out;
}

/** The "N tools" headline claims, per doc. Returns violations. */
export function toolCountViolations(
  texts: Readonly<Record<string, string>>,
  count: number = OP_NAMES.length,
): string[] {
  // The zh claims are matched via \u escapes ("N ge gongju" in simplified and
  // traditional forms) so this file stays CJK-free for check-cjk.ts.
  const claims: Array<[doc: string, pattern: RegExp]> = [
    ["README.md", /## What you can do: (\d+) tools/],
    ["README.zh_CN.md", /## .+: (\d+) \u4E2A\u5DE5\u5177/],
    ["README.zh_TW.md", /## .+: (\d+) \u500B\u5DE5\u5177/],
    ["docs/architecture.md", /\((\d+) tools;/],
  ];
  const out: string[] = [];
  for (const [doc, pattern] of claims) {
    const text = texts[doc];
    if (text === undefined) {
      out.push(`${doc}: not provided to the tool-count check`);
      continue;
    }
    const m = text.match(pattern);
    if (!m?.[1]) {
      out.push(`${doc}: the "N tools" headline was not found (pattern ${pattern})`);
    } else if (Number(m[1]) !== count) {
      out.push(`${doc}: claims ${m[1]} tools but the catalogue has ${count}`);
    }
  }
  return out;
}

if (import.meta.main) {
  const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
  const read = (p: string) => readFileSync(resolve(root, p), "utf8");

  const matrixMd = read("docs/security/tool-risk-matrix.md");
  const securityMd = read("SECURITY.md");
  const rows = parseRiskMatrix(matrixMd);

  const violations = [
    ...riskMatrixViolations(rows),
    ...offByDefaultViolations(rows, matrixMd),
    ...settingsKeyViolations(matrixMd),
    ...securityDefaultsViolations(securityMd),
    ...toolCountViolations({
      "README.md": read("README.md"),
      "README.zh_CN.md": read("README.zh_CN.md"),
      "README.zh_TW.md": read("README.zh_TW.md"),
      "docs/architecture.md": read("docs/architecture.md"),
    }),
  ];

  if (violations.length > 0) {
    for (const v of violations) console.error(`check-docs-policy: ${v}`);
    console.error(
      `\ncheck-docs-policy: ${violations.length} doc/policy mismatch(es). The canonical ` +
        "sources are the tool catalogue (catalogue.rs via ops.gen.ts) and the settings " +
        "schema (src/packages/shared/src/settings.ts); update the docs to match.",
    );
    process.exit(1);
  }
  console.log(
    `check-docs-policy: risk matrix (${rows.length} tools), SECURITY.md defaults, ` +
      `and the ${OP_NAMES.length}-tool headlines match the catalogue and settings schema`,
  );
}
