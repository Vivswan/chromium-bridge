//! Emit the host-owned policy contract (ADR-0032) as one JSON document on
//! stdout: the policy signing domain, the document schema version, the
//! JS-safe revision bound, the field catalogue with each field's declared
//! permissive direction (in declaration order), and the deny-baseline
//! defaults in wire spelling. `scripts/gen-ops.ts` (run via `moon run gen`)
//! consumes this to generate `src/packages/shared/src/policy.gen.ts`; the
//! emitted JSON itself is never checked in - the Rust sources are the
//! contract (ADR-0028).
//!
//! Direction totality is asserted by construction: the loop below iterates
//! `PolicyField::ALL` and `direction`'s match is exhaustive, so a field
//! without a direction fails to compile before it can be emitted. The
//! defaults come from serializing `PolicyDoc::default()` through serde -
//! the exact wire spelling the signed bytes use - and the emitter fails if
//! the resulting keys are not exactly the scoping fields plus the catalogue.
//!
//! Run:
//!   cargo run -q -p chromium-bridge-core --example emit_policy_contract

use chromium_bridge_core::enclave::POLICY_DOMAIN;
use chromium_bridge_core::policy::{
    direction, Direction, PolicyDoc, PolicyField, DISABLED_TOOLS_MAX_ENTRIES,
    DISABLED_TOOL_NAME_MAX_BYTES, JS_SAFE_INT_MAX, POLICY_DOC_VERSION,
};
use serde_json::{json, Value};

/// The stable string tags `policy.gen.ts` spells directions in. Chosen once,
/// here; the generator refuses any tag outside this union, so a new
/// direction variant must extend both sides deliberately.
fn direction_tag(d: Direction) -> &'static str {
    match d {
        Direction::TruePermissive => "truePermissive",
        Direction::FalsePermissive => "falsePermissive",
        Direction::GrowsPermissive => "growsPermissive",
        Direction::GrowsPermissiveZeroTop => "growsPermissiveZeroTop",
        Direction::ShrinksPermissiveSet => "shrinksPermissiveSet",
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fields: Vec<Value> = PolicyField::ALL
        .iter()
        .map(|f| {
            json!({
                "name": f.wire_name(),
                "direction": direction_tag(direction(*f)),
            })
        })
        .collect();

    // The deny baseline in wire spelling: serialize the default document
    // (the same serde path the signed bytes take) and split off the three
    // scoping fields, leaving exactly the 15 field values.
    let doc = serde_json::to_value(PolicyDoc::default())?;
    let mut defaults = doc
        .as_object()
        .cloned()
        .ok_or("PolicyDoc::default() did not serialize to a JSON object")?;
    let v = defaults.remove("v").ok_or("default document lacks `v`")?;
    let revision = defaults
        .remove("revision")
        .ok_or("default document lacks `revision`")?;
    let touched = defaults
        .remove("touched")
        .ok_or("default document lacks `touched`")?;

    // The remaining keys must be the catalogue, exactly: a PolicyDoc struct
    // field the catalogue does not own (or the reverse) fails generation
    // here rather than emitting a defaults bag the schema disagrees with.
    for f in PolicyField::ALL {
        if !defaults.contains_key(f.wire_name()) {
            return Err(format!("default document lacks the {} field", f.wire_name()).into());
        }
    }
    if defaults.len() != PolicyField::ALL.len() {
        return Err(format!(
            "default document carries {} value fields, the catalogue owns {}",
            defaults.len(),
            PolicyField::ALL.len()
        )
        .into());
    }

    let out = json!({
        "policyDomain": POLICY_DOMAIN,
        "docVersion": POLICY_DOC_VERSION,
        "revisionMax": JS_SAFE_INT_MAX,
        "disabledToolsMaxEntries": DISABLED_TOOLS_MAX_ENTRIES,
        "disabledToolNameMaxBytes": DISABLED_TOOL_NAME_MAX_BYTES,
        "fields": fields,
        "defaults": Value::Object(defaults),
        "docDefaults": {
            "v": v,
            "revision": revision,
            "touched": touched,
        },
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
