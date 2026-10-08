import { describe, expect, test } from "bun:test";
import {
  BUNDLE_TOKEN,
  bridgeVersionLineViolations,
  CHROME_VERSION_TOKEN,
  envTableViolations,
  familyViolations,
  listPresenceViolation,
  listSectionViolations,
  mcpLineViolations,
  presenceViolation,
  tokenPresenceViolation,
  type Violation,
} from "../check-docs-literals";

const HOST_ID = "com.vivswan.chromium_bridge.host";
const KEY_LABEL = "com.vivswan.chromium-bridge.enclave.signing.v1";
const idFamily = /com\.vivswan\.[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?/g;
const ids = new Set([HOST_ID, `${HOST_ID}.json`, KEY_LABEL]);
const BUNDLE = "release attestation bundle";

// The family regexes are hand-rolled matchers over prose nothing else checks: a stale copy a rename left
// behind must be flagged with its line, and a longer token sharing the canonical prefix is compared whole.
describe("familyViolations", () => {
  const cases: ReadonlyArray<
    readonly [
      name: string,
      text: string,
      label: string,
      family: RegExp,
      allowed: ReadonlySet<string>,
      violations: Violation[],
    ]
  > = [
    [
      "the stale release-level bundle name is flagged; per-asset bundles are not",
      [
        "ships `chromium-bridge-v1-macos-arm64.attestation.jsonl` and `<asset>.attestation.jsonl` bundles",
        "verify with `--bundle attestation.json`, then read attestation.json.",
        "the release-level `attestation.jsonl` (one JSONL line per asset)",
      ].join("\n"),
      BUNDLE,
      BUNDLE_TOKEN,
      new Set(["attestation.json"]),
      [
        {
          doc: "d.md",
          line: 3,
          message:
            'stale release attestation bundle "attestation.jsonl" (canonical: attestation.json)',
        },
      ],
    ],
    [
      "a longer filename sharing the canonical prefix is compared whole, not by prefix",
      "download attestation.json.sig",
      BUNDLE,
      BUNDLE_TOKEN,
      new Set(["attestation.json"]),
      [
        {
          doc: "d.md",
          line: 1,
          message:
            'stale release attestation bundle "attestation.json.sig" (canonical: attestation.json)',
        },
      ],
    ],
    [
      "a stale Chrome version of any digit width is flagged; the floor passes in either spelling",
      [
        "needs Chrome 134 or later; Chromium 134 behaves the same",
        "Chrome 99 was the old floor",
        "Chromium 1000 is not a release",
        "Chrome 116 or later",
      ].join("\n"),
      "minimum Chrome version",
      CHROME_VERSION_TOKEN,
      new Set(["Chrome 134", "Chromium 134"]),
      [
        {
          doc: "d.md",
          line: 2,
          message: 'stale minimum Chrome version "Chrome 99" (canonical: Chrome 134, Chromium 134)',
        },
        {
          doc: "d.md",
          line: 3,
          message:
            'stale minimum Chrome version "Chromium 1000" (canonical: Chrome 134, Chromium 134)',
        },
        {
          doc: "d.md",
          line: 4,
          message:
            'stale minimum Chrome version "Chrome 116" (canonical: Chrome 134, Chromium 134)',
        },
      ],
    ],
    [
      "canonical identifiers (and the manifest filename form) pass",
      `host id \`${HOST_ID}\` writes ${HOST_ID}.json under the label ${KEY_LABEL}`,
      "bridge identifier",
      idFamily,
      ids,
      [],
    ],
    [
      "a stale identifier a rename left behind is flagged with its line",
      `fine: ${HOST_ID}\nstale: com.vivswan.browser_bridge.host\n`,
      "bridge identifier",
      idFamily,
      ids,
      [
        {
          doc: "d.md",
          line: 2,
          message: `stale bridge identifier "com.vivswan.browser_bridge.host" (canonical: ${[...ids].join(", ")})`,
        },
      ],
    ],
    [
      "a stale keychain label version is flagged",
      "label `com.vivswan.chromium-bridge.enclave.signing.v2`",
      "bridge identifier",
      idFamily,
      ids,
      [
        {
          doc: "d.md",
          line: 1,
          message: `stale bridge identifier "com.vivswan.chromium-bridge.enclave.signing.v2" (canonical: ${[...ids].join(", ")})`,
        },
      ],
    ],
    [
      "a stale lock filename is flagged once the code moves to run.v2.lock",
      "run.lock",
      "lock",
      /\brun(?:\.v\d+)?\.lock\b/g,
      new Set(["run.v2.lock"]),
      [{ doc: "d.md", line: 1, message: 'stale lock "run.lock" (canonical: run.v2.lock)' }],
    ],
    [
      "a stale BB_ env var name is flagged",
      "set BB_LOG_LEVEL=debug",
      "BB_LOG env var",
      /\bBB_LOG[A-Z_]*/g,
      new Set(["BB_LOG", "BB_LOG_FORMAT"]),
      [
        {
          doc: "d.md",
          line: 1,
          message: 'stale BB_LOG env var "BB_LOG_LEVEL" (canonical: BB_LOG, BB_LOG_FORMAT)',
        },
      ],
    ],
  ];

  test.each(cases)("%s", (_name, text, label, family, allowed, violations) => {
    expect(familyViolations("d.md", text, label, family, allowed)).toEqual(violations);
  });
});

test("presence needs the bare bundle name; per-asset bundle names cannot stand in for it", () => {
  const perAssetOnly = "ships `<asset>.attestation.jsonl` and `foo.zip.attestation.json` bundles";
  expect({
    perAsset: tokenPresenceViolation(
      "d.md",
      perAssetOnly,
      BUNDLE_TOKEN,
      "attestation.json",
      BUNDLE,
    ),
    bare: tokenPresenceViolation(
      "d.md",
      "--bundle attestation.json",
      BUNDLE_TOKEN,
      "attestation.json",
      BUNDLE,
    ),
  }).toEqual({
    perAsset: {
      doc: "d.md",
      line: 0,
      message: 'must state the canonical release attestation bundle "attestation.json"',
    },
    bare: null,
  });
});

// A date elsewhere on the page (an audit example) is not a protocol version; only MCP lines are read.
describe("mcpLineViolations", () => {
  test.each<[name: string, text: string, canonical: string, violations: Violation[]]>([
    [
      "the pinned version on MCP lines passes; other dates elsewhere are ignored",
      "MCP protocol `2025-06-18` is pinned\naudit example ts 2026-07-17\n",
      "2025-06-18",
      [],
    ],
    [
      "a stale version on an MCP line is flagged after a re-pin",
      "| MCP protocol | `2025-06-18` |",
      "2026-03-26",
      [
        {
          doc: "d.md",
          line: 1,
          message: 'MCP protocol version "2025-06-18" differs from the code\'s "2026-03-26"',
        },
      ],
    ],
  ])("%s", (_name, text, canonical, violations) => {
    expect(mcpLineViolations("d.md", text, canonical)).toEqual(violations);
  });
});

// Only the backticked integers on a line naming the constant are copies of it; prose naming the constant
// without a value is not.
describe("bridgeVersionLineViolations", () => {
  test.each<[name: string, text: string, canonical: string, violations: Violation[]]>([
    [
      "the current version next to the constant's name passes",
      "| Internal bridge protocol | `1` (`BRIDGE_PROTOCOL_VERSION` in protocol.rs) |",
      "1",
      [],
    ],
    [
      "a stale README/compatibility row is flagged after a version bump",
      "| version | monotonic integer (currently `1`) | `BRIDGE_PROTOCOL_VERSION` in protocol.rs |",
      "2",
      [
        {
          doc: "d.md",
          line: 1,
          message: 'bridge protocol version "1" differs from the code\'s "2"',
        },
      ],
    ],
    [
      "prose mentioning the constant without a value is not flagged",
      "bump `BRIDGE_PROTOCOL_VERSION` when the wire contract breaks",
      "2",
      [],
    ],
  ])("%s", (_name, text, canonical, violations) => {
    expect(bridgeVersionLineViolations("d.md", text, canonical)).toEqual(violations);
  });
});

test("a doc missing the canonical value is flagged; one naming it is not", () => {
  expect({
    missing: presenceViolation("d.md", "no ids here", HOST_ID, "native host id"),
    present: presenceViolation("d.md", `id: ${HOST_ID}`, HOST_ID, "native host id"),
  }).toEqual({
    missing: {
      doc: "d.md",
      line: 0,
      message: `must state the canonical native host id "${HOST_ID}"`,
    },
    present: null,
  });
});

// The env table's accepted values are matched as words on the rows naming the variable, so a new value the
// code accepts and the table lacks is flagged by name, and a doc that stops mentioning the variable at all
// fails rather than passing with nothing to compare.
describe("envTableViolations", () => {
  const table = "| `BB_LOG` | `error` \\| `warn` \\| `info` \\| `debug` | ... |";
  test.each<[name: string, text: string, values: string[], violations: Violation[]]>([
    ["a table listing every accepted value passes", table, ["error", "warn", "info", "debug"], []],
    [
      "a table lagging a new accepted value is flagged",
      table,
      ["error", "warn", "info", "trace"],
      [{ doc: "d.md", line: 0, message: 'documents BB_LOG but not its accepted value "trace"' }],
    ],
    [
      "a doc that stops mentioning the env var at all is flagged",
      "nothing",
      ["debug"],
      [{ doc: "d.md", line: 0, message: "must document the BB_LOG env var" }],
    ],
  ])("%s", (_name, text, values, violations) => {
    expect(envTableViolations("d.md", text, "BB_LOG", values)).toEqual(violations);
  });
});

test("a doc lagging the browser key list is flagged with the canonical list; a wrapped list passes", () => {
  const keys = ["chrome", "brave", "edge"];
  expect({
    wrapped: listPresenceViolation(
      "d.md",
      "keys (chrome, brave,\n  edge)",
      keys,
      "browser key list",
    ),
    lagging: listPresenceViolation("d.md", "keys (chrome, brave)", keys, "browser key list"),
  }).toEqual({
    wrapped: null,
    lagging: {
      doc: "d.md",
      line: 0,
      message:
        'must state the canonical browser key list "chrome, brave, edge" in all 1 place(s) that list it; found 0',
    },
  });
});

test("section anchoring pins each list to its own paragraph", () => {
  const keys = ["chrome", "brave"];
  const anchors = ["for each known browser", "Known browser keys"];
  const doc = [
    "for each known browser (chrome, brave), whether it is present.",
    "",
    "Known browser keys: `chrome`, `brave`.",
  ].join("\n");
  // A decoy correct copy elsewhere restores a bare count to 2; anchoring still fails the drifted paragraph.
  const drifted = [
    "for each known browser (chrome, brave), whether it is present.",
    "",
    "Known browser keys: `chrome`, `brave`, `opera`.",
    "",
    "aside: chrome, brave.",
  ].join("\n");
  expect({
    current: listSectionViolations("d.md", doc, keys, "browser key list", anchors),
    drifted: listSectionViolations("d.md", drifted, keys, "browser key list", anchors),
    noSection: listSectionViolations("d.md", "no such section here", keys, "browser key list", [
      "Known browser keys",
    ]),
  }).toEqual({
    current: [],
    drifted: [
      {
        doc: "d.md",
        line: 3,
        message:
          'the "Known browser keys" section must state the canonical browser key list "chrome, brave"',
      },
    ],
    noSection: [
      {
        doc: "d.md",
        line: 0,
        message: 'must contain the "Known browser keys" section that lists the browser key list',
      },
    ],
  });
});
