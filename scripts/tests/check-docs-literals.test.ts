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
  RELEASE_BUNDLE_NAME,
  tokenPresenceViolation,
} from "../check-docs-literals";

const HOST_ID = "com.vivswan.chromium_bridge.host";
const KEY_LABEL = "com.vivswan.chromium-bridge.enclave.signing.v1";
const idFamily = () => /com\.vivswan\.[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?/g;

describe("release attestation bundle", () => {
  const LABEL = "release attestation bundle";

  test("the release bundle name is itself a BUNDLE_TOKEN, so a doc can name it", () => {
    expect(RELEASE_BUNDLE_NAME).toBe("attestation.json");
    expect(RELEASE_BUNDLE_NAME).toMatch(new RegExp(`^(?:${BUNDLE_TOKEN.source})$`));
  });

  test("the stale release-level name is flagged; per-asset bundles are not", () => {
    const allowed = new Set(["attestation.json"]);
    const text = [
      "ships `chromium-bridge-v1-macos-arm64.attestation.jsonl` and `<asset>.attestation.jsonl` bundles",
      "verify with `--bundle attestation.json`, then read attestation.json.",
      "the release-level `attestation.jsonl` (one JSONL line per asset)",
    ].join("\n");
    expect(familyViolations("d.md", text, LABEL, BUNDLE_TOKEN, allowed)).toEqual([
      {
        doc: "d.md",
        line: 3,
        message:
          'stale release attestation bundle "attestation.jsonl" (canonical: attestation.json)',
      },
    ]);
  });

  test("a longer filename sharing the canonical prefix is compared whole, not by prefix", () => {
    const v = familyViolations(
      "d.md",
      "download attestation.json.sig",
      LABEL,
      BUNDLE_TOKEN,
      new Set(["attestation.json"]),
    );
    expect(v).toHaveLength(1);
    expect(v[0]?.message).toContain('"attestation.json.sig"');
  });

  test("presence needs the bare name; per-asset bundle names cannot stand in for it", () => {
    const perAssetOnly = "ships `<asset>.attestation.jsonl` and `foo.zip.attestation.json` bundles";
    expect(
      tokenPresenceViolation("d.md", perAssetOnly, BUNDLE_TOKEN, "attestation.json", LABEL),
    ).toMatchObject({ doc: "d.md", message: expect.stringContaining("attestation.json") });
    expect(
      tokenPresenceViolation(
        "d.md",
        "--bundle attestation.json",
        BUNDLE_TOKEN,
        "attestation.json",
        LABEL,
      ),
    ).toBeNull();
  });
});

describe("minimum Chrome version", () => {
  test("a stale version of any digit width is flagged; the floor passes in either spelling", () => {
    const allowed = new Set(["Chrome 134", "Chromium 134"]);
    const text = [
      "needs Chrome 134 or later; Chromium 134 behaves the same",
      "Chrome 99 was the old floor",
      "Chromium 1000 is not a release",
      "Chrome 116 or later",
    ].join("\n");
    expect(
      familyViolations("d.md", text, "minimum Chrome version", CHROME_VERSION_TOKEN, allowed).map(
        (v) => [v.line, v.message],
      ),
    ).toEqual([
      [2, 'stale minimum Chrome version "Chrome 99" (canonical: Chrome 134, Chromium 134)'],
      [3, 'stale minimum Chrome version "Chromium 1000" (canonical: Chrome 134, Chromium 134)'],
      [4, 'stale minimum Chrome version "Chrome 116" (canonical: Chrome 134, Chromium 134)'],
    ]);
  });
});

describe("familyViolations", () => {
  const allowed = new Set([HOST_ID, `${HOST_ID}.json`, KEY_LABEL]);

  test("canonical identifiers (and the manifest filename form) pass", () => {
    const text = `host id \`${HOST_ID}\` writes ${HOST_ID}.json under the label ${KEY_LABEL}`;
    expect(familyViolations("d.md", text, "bridge identifier", idFamily(), allowed)).toEqual([]);
  });

  test("a stale identifier a rename left behind is flagged with its line", () => {
    const text = `fine: ${HOST_ID}\nstale: com.vivswan.browser_bridge.host\n`;
    const v = familyViolations("d.md", text, "bridge identifier", idFamily(), allowed);
    expect(v).toHaveLength(1);
    expect(v[0]?.line).toBe(2);
    expect(v[0]?.message).toContain("com.vivswan.browser_bridge.host");
  });

  test("a stale keychain label version is flagged", () => {
    const text = "label `com.vivswan.chromium-bridge.enclave.signing.v2`";
    expect(familyViolations("d.md", text, "bridge identifier", idFamily(), allowed)).toHaveLength(
      1,
    );
  });

  test("a stale lock filename is flagged once the code moves to run.v2.lock", () => {
    const family = /\brun(?:\.v\d+)?\.lock\b/g;
    expect(familyViolations("d.md", "run.lock", "lock", family, new Set(["run.v2.lock"]))).toEqual([
      { doc: "d.md", line: 1, message: 'stale lock "run.lock" (canonical: run.v2.lock)' },
    ]);
  });

  test("a stale BB_ env var name is flagged", () => {
    const family = /\bBB_LOG[A-Z_]*/g;
    const v = familyViolations(
      "d.md",
      "set BB_LOG_LEVEL=debug",
      "BB_LOG env var",
      family,
      new Set(["BB_LOG", "BB_LOG_FORMAT"]),
    );
    expect(v).toHaveLength(1);
    expect(v[0]?.message).toContain("BB_LOG_LEVEL");
  });
});

describe("mcpLineViolations", () => {
  test("the pinned version on MCP lines passes; other dates elsewhere are ignored", () => {
    const text = "MCP protocol `2025-06-18` is pinned\naudit example ts 2026-07-17\n";
    expect(mcpLineViolations("d.md", text, "2025-06-18")).toEqual([]);
  });

  test("a stale version on an MCP line is flagged after a re-pin", () => {
    const text = "| MCP protocol | `2025-06-18` |";
    const v = mcpLineViolations("d.md", text, "2026-03-26");
    expect(v).toHaveLength(1);
    expect(v[0]?.message).toContain("2025-06-18");
  });
});

describe("bridgeVersionLineViolations", () => {
  test("the current version next to the constant's name passes", () => {
    const text = "| Internal bridge protocol | `1` (`BRIDGE_PROTOCOL_VERSION` in protocol.rs) |";
    expect(bridgeVersionLineViolations("d.md", text, "1")).toEqual([]);
  });

  test("a stale README/compatibility row is flagged after a version bump", () => {
    const text =
      "| version | monotonic integer (currently `1`) | `BRIDGE_PROTOCOL_VERSION` in protocol.rs |";
    const v = bridgeVersionLineViolations("d.md", text, "2");
    expect(v).toHaveLength(1);
    expect(v[0]?.message).toContain('"1"');
  });

  test("prose mentioning the constant without a value is not flagged", () => {
    const text = "bump `BRIDGE_PROTOCOL_VERSION` when the wire contract breaks";
    expect(bridgeVersionLineViolations("d.md", text, "2")).toEqual([]);
  });
});

describe("presence and env tables", () => {
  test("a doc missing the canonical value is flagged", () => {
    expect(presenceViolation("d.md", "no ids here", HOST_ID, "native host id")).toMatchObject({
      doc: "d.md",
      message: expect.stringContaining(HOST_ID),
    });
    expect(presenceViolation("d.md", `id: ${HOST_ID}`, HOST_ID, "native host id")).toBeNull();
  });

  test("an env table lagging a new accepted value is flagged", () => {
    const text = "| `BB_LOG` | `error` \\| `warn` \\| `info` \\| `debug` | ... |";
    expect(envTableViolations("d.md", text, "BB_LOG", ["error", "warn", "info", "debug"])).toEqual(
      [],
    );
    const v = envTableViolations("d.md", text, "BB_LOG", ["error", "warn", "info", "trace"]);
    expect(v).toHaveLength(1);
    expect(v[0]?.message).toContain('"trace"');
  });

  test("a doc that stops mentioning the env var at all is flagged", () => {
    const v = envTableViolations("d.md", "nothing", "BB_LOG", ["debug"]);
    expect(v).toHaveLength(1);
    expect(v[0]?.message).toContain("must document");
  });

  test("a doc lagging the browser key list is flagged; a wrapped list passes", () => {
    const keys = ["chrome", "brave", "edge"];
    expect(
      listPresenceViolation("d.md", "keys (chrome, brave,\n  edge)", keys, "browser key list"),
    ).toBeNull();
    expect(
      listPresenceViolation("d.md", "keys (chrome, brave)", keys, "browser key list"),
    ).toMatchObject({
      doc: "d.md",
      message: expect.stringContaining("chrome, brave, edge"),
    });
  });

  test("section anchoring pins each list to its own paragraph", () => {
    const keys = ["chrome", "brave"];
    const doc = [
      "for each known browser (chrome, brave), whether it is present.",
      "",
      "Known browser keys: `chrome`, `brave`.",
    ].join("\n");
    expect(
      listSectionViolations("d.md", doc, keys, "browser key list", [
        "for each known browser",
        "Known browser keys",
      ]),
    ).toEqual([]);

    // A decoy correct copy elsewhere restores a bare count to 2; anchoring still fails the drifted paragraph.
    const drifted = [
      "for each known browser (chrome, brave), whether it is present.",
      "",
      "Known browser keys: `chrome`, `brave`, `opera`.",
      "",
      "aside: chrome, brave.",
    ].join("\n");
    const v = listSectionViolations("d.md", drifted, keys, "browser key list", [
      "for each known browser",
      "Known browser keys",
    ]);
    expect(v).toHaveLength(1);
    expect(v[0]?.message).toContain("Known browser keys");

    expect(
      listSectionViolations("d.md", "no such section here", keys, "browser key list", [
        "Known browser keys",
      ]),
    ).toHaveLength(1);
  });
});
