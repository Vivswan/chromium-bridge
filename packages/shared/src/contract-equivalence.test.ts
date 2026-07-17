// The contract-equivalence gate: the hand-written Zod envelope validators
// must be structurally equivalent to the canonical contracts/*.schema.json.
// The contract files stay the language-neutral source of truth; this test is
// what makes the Zod layer a *verified consumer* instead of a second,
// hand-synced copy. Drift on either side fails CI with the differing paths.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { z } from "zod";
import { BridgeReqSchema, BridgeRespSchema } from "./envelope";
import { diffSchemas, normalizeJsonSchema } from "./json-schema-normalize";

const CONTRACTS = resolve(import.meta.dir, "../../../contracts");

function loadContract(name: string): unknown {
  return JSON.parse(readFileSync(resolve(CONTRACTS, name), "utf8"));
}

function expectEquivalent(zodSchema: z.ZodType, contractFile: string): void {
  const fromZod = normalizeJsonSchema(z.toJSONSchema(zodSchema));
  const fromContract = normalizeJsonSchema(loadContract(contractFile));
  const diff = diffSchemas(fromZod, fromContract);
  if (diff.length > 0) {
    throw new Error(
      `Zod schema and contracts/${contractFile} have drifted apart:\n  ${diff.join("\n  ")}`,
    );
  }
  expect(diff).toEqual([]);
}

describe("contract equivalence (z.toJSONSchema vs contracts/*.schema.json)", () => {
  test("BridgeReqSchema matches bridge-request.schema.json", () => {
    expectEquivalent(BridgeReqSchema, "bridge-request.schema.json");
  });

  test("BridgeRespSchema matches bridge-response.schema.json", () => {
    expectEquivalent(BridgeRespSchema, "bridge-response.schema.json");
  });

  // Guard the guard: the normalizer must still see real differences after
  // stripping representation noise, or the tests above prove nothing.
  test("the normalized diff detects a real structural difference", () => {
    const a = normalizeJsonSchema(z.toJSONSchema(z.strictObject({ id: z.int() })));
    const b = normalizeJsonSchema(z.toJSONSchema(z.strictObject({ id: z.string() })));
    expect(diffSchemas(a, b)).not.toEqual([]);
  });
});
