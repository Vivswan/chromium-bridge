import { describe, expect, test } from "bun:test";
import {
  type MatrixRow,
  offByDefaultViolations,
  parseRiskMatrix,
  riskMatrixViolations,
  securityDefaultsViolations,
  settingsKeyViolations,
  toolCountViolations,
} from "../check-docs-policy";

const row = (name: string, risk: string, perm: string, protection = "-") =>
  `| \`${name}\` | ${risk} | reads | writes | no | \`${perm}\` | ${protection} |`;

const META = {
  tab_list: { risk: "low", permission: "tabs" },
  page_eval: { risk: "critical", permission: "scripting" },
  page_upload: { risk: "critical", permission: "debugger" },
} as const;
const NAMES = ["tab_list", "page_eval", "page_upload"] as const;

// The matrix is prose: bold, footnote markers, and a backticked perm are read past, and a line that is
// not a row is not one.
test("parseRiskMatrix extracts name, normalized risk, and the perm's backticked token", () => {
  const md = [
    "| Tool | Risk | Reads | Writes | Credentials? | Chrome perm | User protection |",
    "|---|---|---|---|---|---|---|",
    row("page_eval", "**Critical**", "scripting", "**every-call** confirm"),
    row("page_click", "High [1]", "scripting"),
    "prose mentioning `not_a_row`",
  ].join("\n");
  expect(parseRiskMatrix(md)).toEqual([
    {
      name: "page_eval",
      risk: "critical",
      perm: "scripting",
      protection: "**every-call** confirm",
    },
    { name: "page_click", risk: "high", perm: "scripting", protection: "-" },
  ]);
});

// The matrix is held to the catalogue in both directions, and a stale level or perm names which.
describe("riskMatrixViolations", () => {
  const good = () =>
    parseRiskMatrix(
      [
        row("tab_list", "Low", "tabs"),
        row("page_eval", "**Critical**", "scripting"),
        row("page_upload", "**Critical**", "debugger", "**off by default** (opt-in)"),
      ].join("\n"),
    );
  test.each<[name: string, rows: MatrixRow[], violations: string[]]>([
    ["a matrix matching the catalogue passes", good(), []],
    [
      "a catalogue tool the matrix dropped is flagged",
      good().filter((r) => r.name !== "page_eval"),
      ["tool `page_eval` is missing from the risk matrix"],
    ],
    [
      "a matrix row for a tool the catalogue no longer has is flagged",
      [...good(), ...parseRiskMatrix(row("page_ghost", "Low", "tabs"))],
      ["risk matrix documents `page_ghost`, which is not in the catalogue"],
    ],
    [
      "a stale risk level or Chrome perm is flagged",
      parseRiskMatrix(
        [
          row("tab_list", "High", "tabs"),
          row("page_eval", "**Critical**", "debugger"),
          row("page_upload", "**Critical**", "debugger", "**off by default**"),
        ].join("\n"),
      ),
      [
        '`tab_list` risk is "high" but the catalogue says "low"',
        '`page_eval` Chrome perm is "debugger" but the catalogue says "scripting"',
      ],
    ],
  ])("%s", (_name, rows, violations) => {
    expect(riskMatrixViolations(rows, NAMES, META)).toEqual(violations);
  });
});

// An "off by default" claim binds both ways to the policy contract's defaults: a default flipped on with
// the claim still standing, and an off default whose row dropped the claim, are both drift.
describe("offByDefaultViolations", () => {
  const cdpClaim = "- **CDP mode (opt-in, off by default)**: the `cdpMode` setting ...";
  const off = {
    fileUploadEnabled: false,
    handleDialogEnabled: false,
    pageEvalEnabled: false,
    cdpMode: false,
  };

  test.each<
    [name: string, rows: MatrixRow[], defaults: Record<string, boolean>, violations: string[]]
  >([
    [
      "off-by-default claims matching the policy contract's defaults pass",
      parseRiskMatrix(
        [
          row("page_upload", "**Critical**", "debugger", "**off by default** (opt-in)"),
          row("page_handle_dialog", "High", "debugger", "**off by default** (opt-in)"),
          row(
            "page_eval",
            "**Critical**",
            "scripting",
            "**off by default** under host-owned policy",
          ),
        ].join("\n"),
      ),
      off,
      [],
    ],
    [
      "a default flipped to true with a stale off-by-default claim is flagged",
      parseRiskMatrix(
        row("page_upload", "**Critical**", "debugger", "**off by default** (opt-in)"),
      ),
      { ...off, fileUploadEnabled: true },
      ['`page_upload` row claims "off by default" but fileUploadEnabled defaults to true'],
    ],
    [
      "an off default whose row dropped the claim is flagged, as is a cdpMode flip",
      parseRiskMatrix(
        [
          row("page_upload", "**Critical**", "debugger", "allowlist only"),
          row("page_eval", "**Critical**", "scripting", "every-call confirm"),
        ].join("\n"),
      ),
      { ...off, handleDialogEnabled: true, cdpMode: true },
      [
        "`page_upload` defaults off (fileUploadEnabled: false) but its row no longer says so",
        "`page_eval` defaults off (pageEvalEnabled: false) but its row no longer says so",
        "the matrix claims CDP mode is off by default but cdpMode defaults to true",
      ],
    ],
  ])("%s", (_name, rows, defaults, violations) => {
    expect(offByDefaultViolations(rows, cdpClaim, defaults)).toEqual(violations);
  });

  test("a renamed gate field fails closed instead of silencing both arms", () => {
    const rows = parseRiskMatrix(
      row("page_upload", "**Critical**", "debugger", "**off by default** (opt-in)"),
    );
    // fileUploadEnabled no longer exists in the policy contract: the gate
    // must say so, not fall through the strict-equality arms forever.
    const defaults = { handleDialogEnabled: false, pageEvalEnabled: false, cdpMode: false };
    expect(
      offByDefaultViolations(rows, cdpClaim, defaults, [
        "page_upload",
        "page_handle_dialog",
        "page_eval",
      ]),
    ).toEqual([
      "gate field `fileUploadEnabled` (for `page_upload`) is not a policy field in the " +
        "generated policy contract (generated/policy.ts)",
    ]);
  });

  test("a renamed gate TOOL fails closed too, not just a renamed key", () => {
    // Catalogue and matrix renamed the tool together, so riskMatrixViolations is clean; only the gates
    // list still says page_upload, and silence here would mean that gate stopped being verified.
    const rows = parseRiskMatrix(
      row("page_attach_file", "**Critical**", "debugger", "**off by default** (opt-in)"),
    );
    expect(
      offByDefaultViolations(rows, cdpClaim, off, [
        "page_attach_file",
        "page_handle_dialog",
        "page_eval",
      ]),
    ).toEqual([
      "gate entry `page_upload` is not a catalogue tool (renamed? update the gates list)",
    ]);
  });
});

// A backticked camelCase token is how the matrix names a gate, so a renamed setting leaves a stale token
// behind; a reviewed non-settings token passes only through the explicit allowlist.
describe("settingsKeyViolations", () => {
  const stale =
    "names `confirmEvalPrompt`, which is neither a policy field (generated/policy.ts) nor a settings " +
    "key (settings.ts) (a legitimate non-settings token goes in MATRIX_NON_SETTINGS_TOKENS)";
  test.each<
    [
      name: string,
      md: string,
      defaults: Record<string, unknown>,
      allowed: Set<string> | undefined,
      violations: string[],
    ]
  >([
    [
      "a renamed setting's stale token is flagged; tool names are not tokens",
      "gates: `confirmPageEval` and `confirmEvalPrompt`; tools like `page_eval` are fine",
      { confirmPageEval: true },
      undefined,
      [stale],
    ],
    [
      "a non-settings token is flagged without the allowlist",
      "needs the `nativeMessaging` permission",
      {},
      undefined,
      [stale.replace("confirmEvalPrompt", "nativeMessaging")],
    ],
    [
      "and passes through it",
      "needs the `nativeMessaging` permission",
      {},
      new Set(["nativeMessaging"]),
      [],
    ],
  ])("%s", (_name, md, defaults, allowed, violations) => {
    expect(settingsKeyViolations(md, defaults, allowed)).toEqual(violations);
  });
});

// SECURITY.md's defaults table is held to the contract cell by cell, and the pinned rows make a dropped
// or reformatted row (or a vanished table) fail by name instead of passing vacuously.
describe("securityDefaultsViolations", () => {
  const table = [
    "| Setting | Default | Relaxing it means | Residual risk you accept |",
    "| `confirmPageEval` | `true` | ... | ... |",
    "| `confirmGraceMs` | `60000` | ... | ... |",
  ].join("\n");
  const required = ["confirmPageEval", "confirmGraceMs"];
  const lost = (key: string) =>
    `SECURITY.md's fail-safe-defaults table lost its \`${key}\` row ` +
    "(or a reformat broke the row parser); restore it or update the pinned row list";

  test.each<[name: string, md: string, defaults: Record<string, unknown>, violations: string[]]>([
    [
      "default cells matching the schema pass",
      table,
      { confirmPageEval: true, confirmGraceMs: 60000 },
      [],
    ],
    [
      "a changed schema default with a stale doc cell is flagged",
      table,
      { confirmPageEval: true, confirmGraceMs: 30000 },
      [
        "SECURITY.md says `confirmGraceMs` defaults to `60000` but the canonical contract " +
          "says `30000`",
      ],
    ],
    [
      "a row for a key neither contract has is flagged",
      table,
      { confirmGraceMs: 60000 },
      [
        "SECURITY.md documents `confirmPageEval`, which is neither a policy field " +
          "(generated/policy.ts) nor a settings key (settings.ts)",
      ],
    ],
    [
      "a dropped or reformatted pinned row is flagged, never skipped silently",
      "| `confirmGraceMs` | `60000` | ... | ... |",
      { confirmGraceMs: 60000 },
      [lost("confirmPageEval")],
    ],
    [
      "a vanished table fails on every pinned row instead of passing vacuously",
      "no table here",
      {},
      [lost("confirmPageEval"), lost("confirmGraceMs")],
    ],
  ])("%s", (_name, md, defaults, violations) => {
    expect(securityDefaultsViolations(md, defaults, required)).toEqual(violations);
  });
});

// The "N tools" headlines are prose copies of the catalogue count; a reworded headline the pattern cannot
// find fails loudly rather than reading as current.
describe("toolCountViolations", () => {
  const texts = {
    "README.md": "## What you can do: 26 tools",
    "docs/architecture.md": "| `tools/` | The tool catalogue (26 tools; the source) |",
  };
  test.each<[name: string, texts: Record<string, string>, count: number, violations: string[]]>([
    ["headlines matching the catalogue count pass", texts, 26, []],
    [
      "every stale headline is flagged when a tool is added",
      texts,
      27,
      [
        "README.md: claims 26 tools but the catalogue has 27",
        "docs/architecture.md: claims 26 tools but the catalogue has 27",
      ],
    ],
    [
      "a reworded headline the pattern cannot find fails loudly",
      { ...texts, "README.md": "## Tools galore" },
      26,
      [
        'README.md: the "N tools" headline was not found (pattern /## What you can do: (\\d+) tools/)',
      ],
    ],
  ])("%s", (_name, docs, count, violations) => {
    expect(toolCountViolations(docs, count)).toEqual(violations);
  });
});
