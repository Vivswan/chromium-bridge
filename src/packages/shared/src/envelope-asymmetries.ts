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
  | { change: "generated-schema"; symbol: string; from: string }
  /** A whole frame (the `$` path) whose boolean `discriminant` selects which Option fields a host-emitted frame
   * carries: the generator emits one arm per value as a `z.discriminatedUnion`, each arm requiring its
   * `required` fields and refusing its `forbidden` ones. Applied after the field-level changes, so an arm
   * inherits them. */
  | {
      change: "ok-split";
      discriminant: string;
      arms: readonly { when: boolean; required: readonly string[]; forbidden: readonly string[] }[];
    };

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

/** The verdict frames the host builds from one typed value (`KillStatus`, `PolicyStatus`, `EnrollOutcome`,
 * `PresenceOutcome` in protocol/control.rs): on the wire every field is an Option, so the faithful base admits
 * mixtures the producer can never emit. The split names the two shapes; `okSplit` builds an entry from them. */
function okSplit(
  frame: string,
  ok: { required: readonly string[]; forbidden: readonly string[] },
  refused: { required: readonly string[]; forbidden: readonly string[] },
  probes: Asymmetry["probes"],
): Asymmetry {
  const arm = (
    when: boolean,
    rule: { required: readonly string[]; forbidden: readonly string[] },
  ) =>
    [
      `ok: ${when}`,
      rule.required.length > 0 ? `always carries ${rule.required.join(", ")}` : "",
      rule.forbidden.length > 0 ? `never carries ${rule.forbidden.join(", ")}` : "",
    ]
      .filter(Boolean)
      .join(" ");
  return {
    direction: "narrow",
    reason:
      `${frame} is emitted from one typed verdict: ${arm(true, ok)}; ${arm(false, refused)}; a mixture is not ` +
      "the host's frame.",
    changes: [
      {
        change: "ok-split",
        discriminant: "ok",
        arms: [
          { when: true, ...ok },
          { when: false, ...refused },
        ],
      },
    ],
    probes,
  };
}

const HOST_MINTED: Asymmetry = {
  direction: "narrow",
  reason:
    "The empty string is refused early on a value the host mints itself (a WebAuthn challenge, the action " +
    "a tap approves, an enrolled credential id); the host never sends one.",
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
  cancel: {
    "$.properties.id": ID_STRING_ARM,
  },
  enclave_proof: {
    "$.properties.sig": PROOF_MATERIAL,
    "$.properties.key_id": PROOF_MATERIAL,
    "$.properties.pubkey": PROOF_MATERIAL,
  },
  client_list_result: {
    "$.properties.clients.items.properties.name": {
      direction: "widen",
      reason:
        "The extension only displays the name, so the plain string skips the label grammar (1-32 chars of " +
        "[A-Za-z0-9._-], starting alphanumeric) the host's ClientName parse enforces when it loads the allowlist " +
        "it forwards.",
      changes: [],
      evidence: "parser",
      probes: { accepts: ["", "bad name!", "x".repeat(33), "-flag"] },
    },
    "$.properties.clients.items.properties.anchor": {
      direction: "widen",
      reason:
        "The extension only displays the anchor, so one object with a kind enum skips the HashDigest grammar " +
        "(lowercase hex, 20 or 32 bytes) the host's parse enforces (SignerId is non-empty on both sides); " +
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
  enroll_options: {
    "$.properties.challenge": HOST_MINTED,
  },
  enroll_result: {
    "$.properties.credential_id": HOST_MINTED,
    $: okSplit(
      "enroll_result",
      { required: ["credential_id"], forbidden: ["reason"] },
      { required: ["reason"], forbidden: ["credential_id"] },
      {
        refuses: [
          { type: "enroll_result", ok: true },
          { type: "enroll_result", ok: true, credential_id: "Y3JlZC1h", reason: "r" },
          { type: "enroll_result", ok: false },
          { type: "enroll_result", ok: false, credential_id: "Y3JlZC1h", reason: "r" },
        ],
        accepts: [
          { type: "enroll_result", ok: true, credential_id: "Y3JlZC1h" },
          { type: "enroll_result", ok: false, reason: "attestation_format" },
        ],
      },
    ),
  },
  presence_result: {
    $: okSplit(
      "presence_result",
      { required: [], forbidden: ["reason"] },
      { required: ["reason"], forbidden: [] },
      {
        refuses: [
          { type: "presence_result", ok: true, reason: "r" },
          { type: "presence_result", ok: false },
        ],
        accepts: [
          { type: "presence_result", ok: true },
          { type: "presence_result", ok: false, reason: "sign_count_not_increased" },
        ],
      },
    ),
  },
  registration_status_result: {
    $: okSplit(
      "registration_status_result",
      { required: ["browsers"], forbidden: ["error"] },
      { required: ["error"], forbidden: ["browsers"] },
      {
        refuses: [
          { type: "registration_status_result", ok: true },
          { type: "registration_status_result", ok: true, browsers: [], error: "e" },
          { type: "registration_status_result", ok: false },
          { type: "registration_status_result", ok: false, browsers: [], error: "e" },
        ],
        accepts: [
          { type: "registration_status_result", ok: true, browsers: [] },
          { type: "registration_status_result", ok: false, error: "HOME is not set" },
        ],
      },
    ),
  },
  policy_restrict_result: {
    $: okSplit(
      "policy_restrict_result",
      { required: [], forbidden: ["error"] },
      { required: ["error"], forbidden: [] },
      {
        refuses: [
          { type: "policy_restrict_result", ok: true, error: "restriction failed" },
          { type: "policy_restrict_result", ok: false },
        ],
        accepts: [
          { type: "policy_restrict_result", ok: true },
          { type: "policy_restrict_result", ok: false, error: "relaxes the effective policy" },
        ],
      },
    ),
  },
  presence_request: {
    "$.properties.challenge": HOST_MINTED,
    "$.properties.action": HOST_MINTED,
  },
  policy_current: {
    $: okSplit(
      "policy_current",
      { required: ["baseline"], forbidden: ["error"] },
      { required: ["error"], forbidden: ["baseline", "sig", "overlay"] },
      {
        refuses: [
          { type: "policy_current", ok: true, baseline: "e30=", error: "boom" },
          { type: "policy_current", ok: true },
          { type: "policy_current", ok: false, baseline: "e30=", error: "boom" },
          { type: "policy_current", ok: false, sig: "c2ln", error: "boom" },
          { type: "policy_current", ok: false, overlay: {}, error: "boom" },
          { type: "policy_current", ok: false },
        ],
        accepts: [
          { type: "policy_current", ok: true, baseline: "e30=", sig: "c2ln", overlay: {} },
          { type: "policy_current", ok: false, error: "no policy baseline" },
        ],
      },
    ),
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
