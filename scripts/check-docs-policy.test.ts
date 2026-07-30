import { describe, expect, test } from "bun:test";
import {
  offByDefaultViolations,
  parseRiskMatrix,
  riskMatrixViolations,
  securityDefaultsViolations,
  settingsKeyViolations,
  toolCountViolations,
} from "./check-docs-policy";

const row = (name: string, risk: string, perm: string, protection = "-") =>
  `| \`${name}\` | ${risk} | reads | writes | no | \`${perm}\` | ${protection} |`;

const META = {
  tab_list: { risk: "low", permission: "tabs" },
  page_eval: { risk: "critical", permission: "scripting" },
  page_upload: { risk: "critical", permission: "debugger" },
} as const;
const NAMES = ["tab_list", "page_eval", "page_upload"] as const;

describe("parseRiskMatrix", () => {
  test("extracts name, normalized risk, and the perm's backticked token", () => {
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
});

describe("riskMatrixViolations", () => {
  const good = () =>
    parseRiskMatrix(
      [
        row("tab_list", "Low", "tabs"),
        row("page_eval", "**Critical**", "scripting"),
        row("page_upload", "**Critical**", "debugger", "**off by default** (opt-in)"),
      ].join("\n"),
    );

  test("a matrix matching the catalogue passes", () => {
    expect(riskMatrixViolations(good(), NAMES, META)).toEqual([]);
  });

  test("a catalogue tool the matrix dropped is flagged", () => {
    const rows = good().filter((r) => r.name !== "page_eval");
    expect(riskMatrixViolations(rows, NAMES, META)).toEqual([
      "tool `page_eval` is missing from the risk matrix",
    ]);
  });

  test("a matrix row for a tool the catalogue no longer has is flagged", () => {
    const rows = [...good(), ...parseRiskMatrix(row("page_ghost", "Low", "tabs"))];
    expect(riskMatrixViolations(rows, NAMES, META)).toEqual([
      "risk matrix documents `page_ghost`, which is not in the catalogue",
    ]);
  });

  test("a stale risk level or Chrome perm is flagged", () => {
    const rows = parseRiskMatrix(
      [
        row("tab_list", "High", "tabs"),
        row("page_eval", "**Critical**", "debugger"),
        row("page_upload", "**Critical**", "debugger", "**off by default**"),
      ].join("\n"),
    );
    expect(riskMatrixViolations(rows, NAMES, META)).toEqual([
      '`tab_list` risk is "high" but the catalogue says "low"',
      '`page_eval` Chrome perm is "debugger" but the catalogue says "scripting"',
    ]);
  });
});

describe("offByDefaultViolations", () => {
  const cdpClaim = "- **CDP mode (opt-in, off by default)**: the `cdpMode` setting ...";

  test("off-by-default claims matching the schema defaults pass", () => {
    const rows = parseRiskMatrix(
      [
        row("page_upload", "**Critical**", "debugger", "**off by default** (opt-in)"),
        row("page_handle_dialog", "High", "debugger", "**off by default** (opt-in)"),
      ].join("\n"),
    );
    const defaults = { fileUploadEnabled: false, handleDialogEnabled: false, cdpMode: false };
    expect(offByDefaultViolations(rows, cdpClaim, defaults)).toEqual([]);
  });

  test("a default flipped to true with a stale off-by-default claim is flagged", () => {
    const rows = parseRiskMatrix(
      row("page_upload", "**Critical**", "debugger", "**off by default** (opt-in)"),
    );
    const defaults = { fileUploadEnabled: true, handleDialogEnabled: false, cdpMode: false };
    const v = offByDefaultViolations(rows, cdpClaim, defaults);
    expect(v).toEqual([
      '`page_upload` row claims "off by default" but fileUploadEnabled defaults to true',
    ]);
  });

  test("an off default whose row dropped the claim is flagged, as is a cdpMode flip", () => {
    const rows = parseRiskMatrix(row("page_upload", "**Critical**", "debugger", "allowlist only"));
    const defaults = { fileUploadEnabled: false, handleDialogEnabled: true, cdpMode: true };
    expect(offByDefaultViolations(rows, cdpClaim, defaults)).toEqual([
      "`page_upload` defaults off (fileUploadEnabled: false) but its row no longer says so",
      "the matrix claims CDP mode is off by default but cdpMode defaults to true",
    ]);
  });

  test("a renamed gate setting fails closed instead of silencing both arms", () => {
    const rows = parseRiskMatrix(
      row("page_upload", "**Critical**", "debugger", "**off by default** (opt-in)"),
    );
    // fileUploadEnabled no longer exists in the schema: the gate must say so,
    // not fall through the strict-equality arms forever.
    const defaults = { handleDialogEnabled: false, cdpMode: false };
    const v = offByDefaultViolations(rows, cdpClaim, defaults, [
      "page_upload",
      "page_handle_dialog",
    ]);
    expect(v).toEqual([
      "gate setting `fileUploadEnabled` (for `page_upload`) is not a settings key in settings.ts",
    ]);
  });

  test("a renamed gate TOOL fails closed too, not just a renamed key", () => {
    // The tool was renamed consistently in the catalogue and the matrix, so
    // riskMatrixViolations is clean - but the gates list still says
    // page_upload. Silence here would mean the off-by-default gate simply
    // stopped being verified.
    const rows = parseRiskMatrix(
      row("page_attach_file", "**Critical**", "debugger", "**off by default** (opt-in)"),
    );
    const defaults = { fileUploadEnabled: false, handleDialogEnabled: false, cdpMode: false };
    const v = offByDefaultViolations(rows, cdpClaim, defaults, [
      "page_attach_file",
      "page_handle_dialog",
    ]);
    expect(v).toEqual([
      "gate entry `page_upload` is not a catalogue tool (renamed? update the gates list)",
    ]);
  });
});

describe("settingsKeyViolations", () => {
  test("a renamed setting leaves a stale backticked key behind and is flagged", () => {
    const md = "gates: `confirmPageEval` and `confirmEvalPrompt`; tools like `page_eval` are fine";
    const v = settingsKeyViolations(md, { confirmPageEval: true });
    expect(v).toHaveLength(1);
    expect(v[0]).toContain("`confirmEvalPrompt`");
  });

  test("a reviewed non-settings token passes only via the explicit allowlist", () => {
    const md = "needs the `nativeMessaging` permission";
    expect(settingsKeyViolations(md, {})).toHaveLength(1);
    expect(settingsKeyViolations(md, {}, new Set(["nativeMessaging"]))).toEqual([]);
  });
});

describe("securityDefaultsViolations", () => {
  const table = [
    "| Setting | Default | Relaxing it means | Residual risk you accept |",
    "| `confirmPageEval` | `true` | ... | ... |",
    "| `confirmGraceMs` | `60000` | ... | ... |",
  ].join("\n");
  const required = ["confirmPageEval", "confirmGraceMs"];

  test("default cells matching the schema pass", () => {
    expect(
      securityDefaultsViolations(table, { confirmPageEval: true, confirmGraceMs: 60000 }, required),
    ).toEqual([]);
  });

  test("a changed schema default with a stale doc cell is flagged", () => {
    expect(
      securityDefaultsViolations(table, { confirmPageEval: true, confirmGraceMs: 30000 }, required),
    ).toEqual([
      "SECURITY.md says `confirmGraceMs` defaults to `60000` but settings.ts says `30000`",
    ]);
  });

  test("a row for a key the schema no longer has is flagged", () => {
    expect(securityDefaultsViolations(table, { confirmGraceMs: 60000 }, required)).toEqual([
      "SECURITY.md documents `confirmPageEval`, which is not a settings key in settings.ts",
    ]);
  });

  test("a dropped or reformatted pinned row is flagged, never skipped silently", () => {
    const oneRow = "| `confirmGraceMs` | `60000` | ... | ... |";
    const v = securityDefaultsViolations(oneRow, { confirmGraceMs: 60000 }, required);
    expect(v).toHaveLength(1);
    expect(v[0]).toContain("lost its `confirmPageEval` row");
  });

  test("a vanished table fails on every pinned row instead of passing vacuously", () => {
    expect(securityDefaultsViolations("no table here", {}, required)).toHaveLength(2);
  });
});

describe("toolCountViolations", () => {
  const texts = {
    "README.md": "## What you can do: 26 tools",
    // "## Ni neng zuo shen me: 26 ge gongju" (simplified / traditional), via
    // \u escapes so this file stays CJK-free (check-cjk.ts).
    "README.zh_CN.md": "## \u4F60\u80FD\u505A\u4EC0\u4E48: 26 \u4E2A\u5DE5\u5177",
    "README.zh_TW.md": "## \u4F60\u80FD\u505A\u4EC0\u9EBC: 26 \u500B\u5DE5\u5177",
    "docs/architecture.md": "| `tools/` | The tool catalogue (26 tools; the source) |",
  };

  test("headlines matching the catalogue count pass", () => {
    expect(toolCountViolations(texts, 26)).toEqual([]);
  });

  test("every stale headline is flagged when a tool is added", () => {
    const v = toolCountViolations(texts, 27);
    expect(v).toHaveLength(4);
    for (const doc of Object.keys(texts)) {
      expect(v.join("\n")).toContain(`${doc}: claims 26 tools but the catalogue has 27`);
    }
  });

  test("a reworded headline the pattern cannot find fails loudly", () => {
    const v = toolCountViolations({ ...texts, "README.md": "## Tools galore" }, 26);
    expect(v).toEqual([
      'README.md: the "N tools" headline was not found (pattern /## What you can do: (\\d+) tools/)',
    ]);
  });
});
