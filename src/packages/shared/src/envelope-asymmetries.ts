// The extension's deliberate parser asymmetries, as GENERATOR INPUT: every place the enforced validators in
// envelope.gen.ts accept more or less than the Rust parser. scripts/gen-envelope.ts applies each entry at its path
// (refusing a path the Rust schema lacks or a node outside the shape the change expects) and emits the enforced
// validator as the faithful base plus exactly these changes; scripts/check-envelope.ts runs every probe against
// the generated base and enforced validators and prints this table for the PR reviewer.
//
// Direction is judged against the parsers, not their schemas: the Rust side is serde's Deserialize (a
// `schemars(with = "String")` newtype still refuses at Deserialize), the Zod side the extension's parse at the
// boundary (the enforced validator plus, for the request, parseBridgeReq's per-op step).
//
//   narrow -> every value the Zod side accepts, the Rust parser accepts too (the extension only refuses earlier);
//             its `refuses` probes name values the base admits and the enforced validator refuses
//   widen  -> the Zod side accepts at least one value the Rust parser refuses; its `accepts` probes name values
//             the enforced validator admits (the base refuses them when the schema can see the widening)

export type AsymmetryDirection = "widen" | "narrow";

/** One change the generator applies to the Rust-derived node at an entry's path, in order. */
export type Change =
  /** Constraints on a string node (the Rust side has a plain String). */
  | { change: "string"; minLength?: number; maxLength?: number; pattern?: string }
  /** A string arm beside a numeric node: `z.union([<node>, z.string()])`. */
  | { change: "string-arm" }
  /** serde's adjacently tagged enum (one object variant per `kind` const, all with the same `value` shape)
   * spelled as one object with `kind: z.enum([...])`. */
  | { change: "tag-union-as-enum-object" }
  /** The node is replaced by a schema another generated module already owns; the generator cross-checks an
   * object node's field inventory and field types against that schema. */
  | { change: "generated-schema"; symbol: string; from: string };

export type Asymmetry = {
  direction: AsymmetryDirection;
  /** One sentence a reviewer reads in the gate's table: for a widen, why accepting more than the host is safe;
   * for a narrow, what the extension refuses early. */
  reason: string;
  changes: readonly Change[];
  /** Values placed at the entry's path in a representative frame. `refuses`: the enforced validator refuses
   * each, and a narrow entry's base admits at least one (the narrowing is this layer's). `accepts`: the enforced
   * validator admits each, a narrow entry's base admits every one (no hidden widening), and a widen entry's base
   * refuses at least one unless `evidence` says the widening is invisible to the schema. */
  probes: { refuses?: readonly unknown[]; accepts?: readonly unknown[] };
  /** A widening the schema-faithful base cannot show: the Rust side refuses in a newtype's Deserialize that
   * schemars renders as a plain String. The reason names the grammar. */
  evidence?: "parser";
};

/** Rules the generator applies to every reader validator rather than at one path. The gate proves the first
 * two per frame (null at every Option field refused; an added field admitted on control frames); the third is
 * the emitter's integer form everywhere, so it has no probe of its own. */
export const READER_RULES = [
  {
    rule: "optional-only",
    direction: "narrow",
    reason:
      "Every Option field accepts absence only: the host omits an absent field (skip_serializing_if), so a " +
      "null arm would admit a frame no writer produces.",
  },
  {
    rule: "loose-frames",
    direction: "widen",
    reason:
      "Control frames are read loose where the host refuses unknown fields: the host may add fields, and the " +
      "extension acts only on the fields it validated (and, for signed statements, verifies in " +
      "enclave-verify.ts), so an unknown field is ignored rather than fatal. Not the envelopes, and not a " +
      "node replaced by a strict generated schema.",
  },
  {
    rule: "safe-integers",
    direction: "narrow",
    reason:
      "Every integer is a JS-safe integer (z.number().int()): above 2^53 - 1 a JS number cannot represent " +
      "every value, so two consecutive host u64 values could read equal here.",
  },
] as const satisfies readonly { rule: string; direction: AsymmetryDirection; reason: string }[];

const ID_STRING_ARM: Asymmetry = {
  direction: "widen",
  reason:
    "Forward compatibility: a string arm beside the host's non-negative JS-safe integer; the host, the only " +
    "assigner of ids, refuses a string in its own u64 parse.",
  changes: [{ change: "string-arm" }],
  probes: { accepts: ["req-9"] },
};

const PROOF_MATERIAL: Asymmetry = {
  direction: "narrow",
  reason:
    "The empty string is refused early on key material the host produces itself (signature, key id, public " +
    "key); the host leaves that to signature verification.",
  changes: [{ change: "string", minLength: 1 }],
  probes: { refuses: [""] },
};

const SIGNED_ARTIFACT: Asymmetry = {
  direction: "narrow",
  reason:
    "The empty string is refused early on a signed artifact the host only ever sends whole; the host leaves " +
    "that to signature verification.",
  changes: [{ change: "string", minLength: 1 }],
  probes: { refuses: [""] },
};

/** Keyed by reader: the two envelopes by name, every host->extension control frame by its `type` tag. */
export const ASYMMETRIES: Readonly<Record<string, Readonly<Record<string, Asymmetry>>>> = {
  request: {
    "$.properties.id": ID_STRING_ARM,
    "$.properties.op": {
      direction: "narrow",
      reason:
        "The empty op is refused early; an unknown op is refused on both sides (the Rust command enum, the " +
        "catalogue lookup in parseBridgeReq), so this entry covers the empty string only.",
      changes: [{ change: "string", minLength: 1 }],
      probes: { refuses: [""] },
    },
    "$.properties.browser": {
      direction: "narrow",
      reason:
        "The browser-label grammar is enforced early; the host only ever stamps a validated label.",
      changes: [{ change: "string", minLength: 1, maxLength: 32, pattern: "^[A-Za-z0-9._-]+$" }],
      probes: { refuses: ["", "a b", "x".repeat(33)], accepts: ["brave", "work.1_2-3"] },
    },
    "$.properties.args": {
      direction: "narrow",
      reason:
        "The host leaves args free-form at the envelope (its command enum validates them per op); the " +
        "extension narrows them to the generated OpArgs bag here and to the op's own validator in " +
        "parseBridgeReq.",
      changes: [{ change: "generated-schema", symbol: "OpArgsSchema", from: "./ops.gen" }],
      probes: { refuses: ["not an object", { notAnArg: 1 }], accepts: [{}] },
    },
  },
  response: {
    "$.properties.id": ID_STRING_ARM,
  },
  enclave_proof: {
    "$.properties.sig": PROOF_MATERIAL,
    "$.properties.key_id": PROOF_MATERIAL,
    "$.properties.pubkey": PROOF_MATERIAL,
  },
  presence_proof: {
    "$.properties.sig": PROOF_MATERIAL,
    "$.properties.key_id": PROOF_MATERIAL,
    "$.properties.pubkey": PROOF_MATERIAL,
  },
  client_list_result: {
    "$.properties.clients.items.properties.name": {
      direction: "narrow",
      reason:
        "A blank client label fails the frame early; the host validates labels when it pairs a client, not " +
        "when it loads the allowlist it forwards, so this line is the extension's own.",
      changes: [{ change: "string", minLength: 1 }],
      probes: { refuses: [""] },
    },
    "$.properties.clients.items.properties.anchor": {
      direction: "widen",
      reason:
        "The extension only displays the anchor, so one object with a kind enum skips the HashDigest grammar " +
        "(lowercase hex, 20 or 32 bytes) the host's parse enforces (TeamId is non-empty on both sides); " +
        "admission is decided by the host, whose own parse refuses a malformed value when it loads the " +
        "allowlist.",
      changes: [{ change: "tag-union-as-enum-object" }],
      evidence: "parser",
      probes: {
        accepts: [{ kind: "hash", value: "zz" }],
        refuses: [{ kind: "root", value: "x" }, { kind: "hash" }, "hash:x"],
      },
    },
    "$.properties.clients.items.properties.anchor.properties.value": {
      direction: "narrow",
      reason: "An empty anchor value is refused early; the host's own parse refuses it too.",
      changes: [{ change: "string", minLength: 1 }],
      probes: { refuses: [""] },
    },
  },
  policy_current: {
    "$.properties.baseline": SIGNED_ARTIFACT,
    "$.properties.sig": SIGNED_ARTIFACT,
    "$.properties.overlay": {
      direction: "narrow",
      reason:
        "The overlay is the generated PolicyOverlaySchema: strict like the host's, with the disabledTools caps " +
        "applied at parse time where the host applies them in PolicyDoc::validate; an overlay field the " +
        "catalogue does not own is a policy claim nobody owns and fails the frame.",
      changes: [
        { change: "generated-schema", symbol: "PolicyOverlaySchema", from: "./policy.gen" },
      ],
      probes: {
        refuses: [{ disabledTools: [""] }, { disabledTools: ["a".repeat(129)] }, { cdpMode: null }],
        accepts: [{ pageEvalEnabled: false, confirmGraceMs: Number.MAX_SAFE_INTEGER }],
      },
    },
  },
};
