import { describe, expect, test } from "bun:test";
import {
  bridgeProtocolVersion,
  bridgeVersionLineViolations,
  envTableViolations,
  envValueSet,
  familyViolations,
  lockFilename,
  logEnvVars,
  mcpLineViolations,
  mcpProtocolVersion,
  presenceViolation,
  rustStrConst,
} from "./check-docs-literals";

const HOST_ID = "com.vivswan.chromium_bridge.host";
const KEY_LABEL = "com.vivswan.chromium-bridge.enclave.signing.v1";
const idFamily = () => /com\.vivswan\.[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?/g;

describe("canonical extraction", () => {
  test("reads a &str const from Rust source text", () => {
    const src = `pub const NATIVE_HOST_ID: &str = "${HOST_ID}";`;
    expect(rustStrConst(src, "NATIVE_HOST_ID", "identity.rs")).toBe(HOST_ID);
  });

  test("a missing const is an error, never a silent pass", () => {
    expect(() => rustStrConst("nothing here", "NATIVE_HOST_ID", "identity.rs")).toThrow(
      "identity.rs",
    );
  });

  test("a commented-out const is not mistaken for the canonical value", () => {
    const src = `// const NATIVE_HOST_ID: &str = "com.vivswan.old.host";\npub const NATIVE_HOST_ID: &str = "${HOST_ID}";`;
    expect(rustStrConst(src, "NATIVE_HOST_ID", "identity.rs")).toBe(HOST_ID);
    const blockSrc = `/*\nconst NATIVE_HOST_ID: &str = "com.vivswan.old.host";\n*/\npub const NATIVE_HOST_ID: &str = "${HOST_ID}";`;
    expect(rustStrConst(blockSrc, "NATIVE_HOST_ID", "identity.rs")).toBe(HOST_ID);
    expect(() =>
      rustStrConst('// const NATIVE_HOST_ID: &str = "x";', "NATIVE_HOST_ID", "identity.rs"),
    ).toThrow("identity.rs");
    expect(() =>
      rustStrConst('/*\nconst NATIVE_HOST_ID: &str = "x";\n*/', "NATIVE_HOST_ID", "identity.rs"),
    ).toThrow("identity.rs");
  });

  test("reads the lock filename from the join call, including a future rename", () => {
    expect(lockFilename('runtime_dir().join("run.lock")')).toBe("run.lock");
    expect(lockFilename('runtime_dir().join("run.v2.lock")')).toBe("run.v2.lock");
    expect(() => lockFilename("no join here")).toThrow("lockfile");
  });

  test("MCP version: a hoisted protocol.rs const wins over the inline literal", () => {
    const inline = '"protocolVersion": "2025-06-18",';
    expect(mcpProtocolVersion("", inline)).toBe("2025-06-18");
    const hoisted = 'pub const MCP_PROTOCOL_VERSION: &str = "2026-03-26";';
    expect(mcpProtocolVersion(hoisted, inline)).toBe("2026-03-26");
    expect(() => mcpProtocolVersion("", "")).toThrow("MCP protocol version");
  });

  test("reads the bridge protocol version integer", () => {
    expect(bridgeProtocolVersion("pub const BRIDGE_PROTOCOL_VERSION: u32 = 1;")).toBe("1");
    expect(() => bridgeProtocolVersion("")).toThrow("BRIDGE_PROTOCOL_VERSION");
  });

  test("collects the BB_* env var names log.rs reads", () => {
    const src = 'std::env::var("BB_LOG") ... std::env::var("BB_LOG_FORMAT")';
    expect(logEnvVars(src)).toEqual(["BB_LOG", "BB_LOG_FORMAT"]);
    expect(() => logEnvVars("no vars")).toThrow("log.rs");
  });

  test("collects an env var's accepted values, including the default arm's", () => {
    const src = `
    *T.get_or_init(|| match std::env::var("BB_LOG").ok().as_deref() {
        Some("error") | Some("ERROR") => Level::Error,
        Some("debug") | Some("DEBUG") => Level::Debug,
        _ => Level::Info,
    })`;
    // "info" has no explicit arm - it is the silent fallback - but it is a
    // documented value, so the parser must include it.
    expect(envValueSet(src, "BB_LOG")).toEqual(["error", "debug", "info"]);
    expect(() => envValueSet(src, "BB_MISSING")).toThrow("BB_MISSING");
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

  test("ADR filenames keep their minting date without tripping the check", () => {
    const text =
      "| MCP | `2026-03-26` ([ADR-0007](./adr/0007-mcp-protocol-version-2025-06-18.md)) |";
    expect(mcpLineViolations("d.md", text, "2026-03-26")).toEqual([]);
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
});
