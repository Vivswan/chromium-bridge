//! The seed corpus, generated from the production types every time the fuzzer runs (`moon run
//! fuzz-seeds`, the nightly job's first step) instead of committed: a committed corpus is a second copy
//! of the types, and it drifted (record seeds carrying a version the ladder never had, frames captured
//! from a real client). Every happy-path seed goes through the real encoder (`bridge_write`,
//! `nm_write_frame`, the record envelope's `encode`, the tool catalogue's own schemas), and every
//! adversarial seed is a one-step mutation of one of those, labelled with the reader that must refuse
//! it. Deterministic by construction: no randomness, no clock, no environment.
//!
//! One submodule per seed directory, named like the `fuzz_targets/<name>.rs` binary it feeds; this
//! module holds the shared shapes, the encoders and mutations, the dictionary, and the proof.
//!
//! ```text
//! corpus()           -> every directory, in memory, with each seed's expected verdict
//! json_dictionary()  -> the libFuzzer token dictionary derived from the JSON seeds
//! write_corpus()     -> seeds/<target>/<name> and dictionaries/json_protocol.dict on disk
//! ```

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use genkan_core::protocol::{bridge_write, nm_write_frame};
use genkan_core::tools::{self, ToolId};
use serde_json::{json, Map, Value};

use crate::targets::Target;

/// `serde_json::to_value` of a production frame; infallible for every type here. Defined before the
/// submodules so each of them sees it.
macro_rules! json_of {
    ($frame:expr) => {
        serde_json::to_value(&$frame).expect("a production frame serializes")
    };
}

mod attach;
mod bridge_envelope;
mod classify_frame;
mod handshake;
mod mcp_jsonrpc;
mod nm_frame;
mod policy_doc;
mod registration_manifest;
mod webauthn_authdata;

/// Whether the reader a seed targets accepts those bytes.
pub type Reader = fn(&[u8]) -> bool;

/// A seed's expected verdict from the reader it targets. Every `Refused` seed is a one-step mutation of
/// an `Accepted` one, so the pair states which check refuses it.
#[derive(Debug, Clone, Copy)]
pub enum Expect {
    Accepted(Reader),
    Refused(Reader),
}

#[derive(Debug, Clone)]
pub struct Seed {
    /// The file name inside the target's seed directory.
    pub name: String,
    pub bytes: Vec<u8>,
    pub expect: Expect,
}

impl Seed {
    fn accepted(name: impl Into<String>, bytes: Vec<u8>, reader: Reader) -> Seed {
        Seed {
            name: name.into(),
            bytes,
            expect: Expect::Accepted(reader),
        }
    }

    fn refused(name: impl Into<String>, bytes: Vec<u8>, reader: Reader) -> Seed {
        Seed {
            name: name.into(),
            bytes,
            expect: Expect::Refused(reader),
        }
    }
}

/// One target's seed directory, `seeds/<target.name>/`.
#[derive(Debug, Clone)]
pub struct Directory {
    pub target: Target,
    pub seeds: Vec<Seed>,
}

/// Every seed directory. One entry per byte-input target; the `Arbitrary`-input targets
/// (`handshake_verify`, `enclave_challenge`) take no seeds because their byte encoding is the
/// `arbitrary` crate's, not a wire format.
pub fn corpus() -> Vec<Directory> {
    vec![
        attach::directory(),
        bridge_envelope::directory(),
        classify_frame::directory(),
        handshake::directory(),
        mcp_jsonrpc::directory(),
        nm_frame::directory(),
        policy_doc::directory(),
        registration_manifest::directory(),
        webauthn_authdata::directory(),
    ]
}

/// The crate-relative path of the generated JSON token dictionary, the one `scripts/fuzz-smoke.ts`
/// hands libFuzzer for every JSON-speaking target.
pub const JSON_DICTIONARY: &str = "dictionaries/json_protocol.dict";

/// What [`write_corpus`] put on disk, for the generator's summary lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub directories: Vec<Written>,
    pub dictionary_words: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub target: &'static str,
    pub accepted: usize,
    pub refused: usize,
}

/// Replace `fuzz_dir/seeds/` with the generated corpus and rewrite the JSON dictionary. The seeds tree
/// is removed whole, so a stale `seeds/<target>` cannot outlive its target.
pub fn write_corpus(fuzz_dir: &Path) -> io::Result<Summary> {
    let corpus = corpus();
    let seeds_dir = fuzz_dir.join("seeds");
    match fs::remove_dir_all(&seeds_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut directories = Vec::new();
    for dir in &corpus {
        let path = seeds_dir.join(dir.target.name);
        fs::create_dir_all(&path)?;
        let mut written = Written {
            target: dir.target.name,
            accepted: 0,
            refused: 0,
        };
        for seed in &dir.seeds {
            fs::write(path.join(&seed.name), &seed.bytes)?;
            match seed.expect {
                Expect::Accepted(_) => written.accepted += 1,
                Expect::Refused(_) => written.refused += 1,
            }
        }
        directories.push(written);
    }
    let words = json_dictionary(&corpus);
    let dictionary = fuzz_dir.join(JSON_DICTIONARY);
    fs::create_dir_all(
        dictionary
            .parent()
            .expect("JSON_DICTIONARY names a file inside a directory"),
    )?;
    fs::write(&dictionary, render_dictionary(&words))?;
    Ok(Summary {
        directories,
        dictionary_words: words.len(),
    })
}

// ---- Encoders and mutations, shared by the directories ---------------------------------------------

/// One NDJSON line, the bridge and MCP framing (`bridge_write`'s bytes).
fn ndjson(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    bridge_write(&mut bytes, value).expect("writing to a Vec cannot fail");
    bytes
}

/// One native-messaging frame (`nm_write_frame`'s bytes).
fn nm(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    nm_write_frame(&mut bytes, value).expect("a seed frame is under the outgoing cap");
    bytes
}

fn compact(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("a Value serializes")
}

/// `value` after `edit`: the one-step mutations (an unknown field, a wrong type, a bound plus one).
fn edited(value: &Value, edit: impl FnOnce(&mut Value)) -> Value {
    let mut copy = value.clone();
    edit(&mut copy);
    copy
}

/// `value` with `key` removed from its top-level object.
fn without(value: &Value, key: &str) -> Value {
    edited(value, |v| {
        v.as_object_mut()
            .expect("a seed frame is an object")
            .remove(key);
    })
}

/// `value` serialized with `key` repeated in front: valid JSON that a last-wins parser reads as
/// `value` itself, which is exactly what a duplicate-key refusal must catch.
fn repeated_key(value: &Value, key: &str) -> Vec<u8> {
    let field = &value[key];
    let text = serde_json::to_string(value).expect("a Value serializes");
    let rest = text.strip_prefix('{').expect("a seed frame is an object");
    format!("{{\"{key}\":{field},{rest}").into_bytes()
}

/// The simplest instance a JSON Schema fragment admits: the catalogue's own argument schemas drive the
/// request seeds, so a new tool gets its seed without a hand-written fixture. Only required properties
/// are filled; an optional one left out is the simplest instance of all.
fn instance_of(schema: &Value) -> Value {
    if let Some(first) = schema
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|options| options.first())
    {
        return first.clone();
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("object") => {
            let properties = schema.get("properties").and_then(Value::as_object);
            let required = schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            let mut object = Map::new();
            for name in required {
                let property = properties.and_then(|p| p.get(name)).unwrap_or_else(|| {
                    panic!("required property {name} has no schema in {schema}")
                });
                object.insert(name.to_string(), instance_of(property));
            }
            Value::Object(object)
        }
        Some("string") => json!("example"),
        Some("integer" | "number") => json!(1),
        Some("boolean") => json!(true),
        Some("array") => json!([]),
        Some(_) | None => panic!("no instance rule for the schema fragment {schema}"),
    }
}

/// One request per catalogue tool: the tool's name, its schema-derived arguments, and those
/// arguments parsed back through the tool's own typed parser, so each seed is a request the
/// extension's validator for that tool accepts.
fn tool_requests() -> Vec<(&'static str, Value, tools::BridgeCommand)> {
    tools::all()
        .map(|tool| {
            let id = ToolId::from_name(tool.name).expect("a catalogue tool resolves by name");
            let args = instance_of(&Value::Object(tool.args_schema()));
            let command = id.parse_args(args.clone()).unwrap_or_else(|e| {
                panic!(
                    "{}: the schema-derived arguments must parse: {e}",
                    tool.name
                )
            });
            (tool.name, args, command)
        })
        .collect()
}

// ---- The dictionary ----------------------------------------------------------------------------------

/// libFuzzer silently drops a dictionary word longer than this (its `Word` is a 64-byte fixed array).
const DICTIONARY_WORD_MAX: usize = 64;

/// Every object key and string value in the JSON seeds, plus the JSON structure tokens, bounded to
/// what libFuzzer keeps: mutation then reaches past the JSON parser into the typed decodes. Derived
/// from the corpus, so a renamed tag or a re-pinned protocol literal lands here the same run.
pub fn json_dictionary(corpus: &[Directory]) -> BTreeSet<Vec<u8>> {
    fn collect(value: &Value, words: &mut BTreeSet<Vec<u8>>) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    words.insert(key.as_bytes().to_vec());
                    collect(inner, words);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| collect(item, words)),
            Value::String(text) => {
                words.insert(text.as_bytes().to_vec());
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    let mut words = BTreeSet::new();
    for token in ["{", "}", "[", "]", ":", ",", "\"", "true", "false", "null"] {
        words.insert(token.as_bytes().to_vec());
    }
    for seed in corpus.iter().flat_map(|dir| &dir.seeds) {
        if let Ok(value) = serde_json::from_slice::<Value>(&seed.bytes) {
            collect(&value, &mut words);
        }
    }
    words.retain(|word| !word.is_empty() && word.len() <= DICTIONARY_WORD_MAX);
    words
}

/// The dictionary file in libFuzzer's syntax: one quoted word per line, with `\\`, `\"`, and `\xHH`
/// for every byte outside printable ASCII.
pub fn render_dictionary(words: &BTreeSet<Vec<u8>>) -> String {
    let mut out = String::from(
        "# libFuzzer dictionary for the JSON-speaking targets, generated by `moon run fuzz-seeds` from\n\
         # the seed corpus (src/packages/core/fuzz/src/seeds/). Do not edit.\n\n",
    );
    for word in words {
        out.push('"');
        for &byte in word {
            match byte {
                b'\\' => out.push_str("\\\\"),
                b'"' => out.push_str("\\\""),
                0x20..=0x7e => out.push(char::from(byte)),
                _ => out.push_str(&format!("\\x{byte:02x}")),
            }
        }
        out.push_str("\"\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use genkan_core::identity::NATIVE_HOST_ID;
    use genkan_core::protocol::{
        MCP_META_CLIENT_CAPABILITIES, MCP_META_PROTOCOL_VERSION, MCP_META_SERVER_INFO,
        MCP_PROTOCOL_VERSION,
    };
    use genkan_core::registration::fuzz_api;

    use super::*;

    fn fuzz_dir() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    fn bytes_by_name(corpus: &[Directory]) -> BTreeMap<String, Vec<u8>> {
        corpus
            .iter()
            .flat_map(|dir| {
                dir.seeds.iter().map(move |seed| {
                    (
                        format!("{}/{}", dir.target.name, seed.name),
                        seed.bytes.clone(),
                    )
                })
            })
            .collect()
    }

    /// The production readers are the only authority on what a seed reaches: a record version above
    /// the ladder, a moved bound, or a renamed tag turns an accepted seed into a refused one (or the
    /// reverse) and fails here, instead of silently costing the fuzzer the branch the seed was for.
    /// Every seed also runs through its target in-process, so a seed that trips an oracle is a finding
    /// before any nightly run.
    #[test]
    fn every_seed_survives_its_target_and_its_reader_agrees_with_its_label() {
        let corpus = corpus();
        assert_eq!(
            bytes_by_name(&corpus),
            bytes_by_name(&super::corpus()),
            "two generator runs must emit identical bytes"
        );
        for dir in &corpus {
            let mut names = BTreeSet::new();
            let (mut accepted, mut refused) = (0, 0);
            for seed in &dir.seeds {
                let id = format!("{}/{}", dir.target.name, seed.name);
                assert!(names.insert(&seed.name), "{id} is emitted twice");
                (dir.target.run)(&seed.bytes);
                let (reader, expected) = match seed.expect {
                    Expect::Accepted(reader) => (reader, true),
                    Expect::Refused(reader) => (reader, false),
                };
                assert_eq!(
                    reader(&seed.bytes),
                    expected,
                    "{id}: the reader {} the seed its label says it must {}",
                    if expected { "refused" } else { "accepted" },
                    if expected { "accept" } else { "refuse" },
                );
                if expected {
                    accepted += 1;
                } else {
                    refused += 1;
                }
            }
            assert!(
                accepted > 0 && refused > 0,
                "{}: a directory carries both happy-path and adversarial seeds ({accepted} accepted, {refused} refused)",
                dir.target.name
            );
        }
    }

    /// `scripts/fuzz-smoke.ts` hands `seeds/<target>` to the binary of the same name, so every
    /// directory must be a byte-input binary that runs the body the test above ran, and every byte-input
    /// binary must have a directory. The `Arbitrary` binaries are told apart by their derive.
    #[test]
    fn every_byte_input_binary_has_a_directory_that_runs_its_body() {
        let corpus = corpus();
        let binaries: BTreeMap<String, String> = fs::read_dir(fuzz_dir().join("fuzz_targets"))
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let name = path.file_stem().unwrap().to_str().unwrap().to_string();
                (name, fs::read_to_string(&path).unwrap())
            })
            .collect();
        let byte_input: BTreeSet<&str> = binaries
            .iter()
            .filter(|(_, source)| !source.contains("derive(Arbitrary"))
            .map(|(name, _)| name.as_str())
            .collect();
        let directories: BTreeSet<&str> = corpus.iter().map(|dir| dir.target.name).collect();
        assert_eq!(
            directories, byte_input,
            "the seed directories and the byte-input fuzz binaries are the same set"
        );
        for dir in &corpus {
            let delegation = format!("targets::{}(", dir.target.name);
            assert!(
                binaries[dir.target.name].contains(&delegation),
                "fuzz_targets/{}.rs must call {delegation}",
                dir.target.name
            );
        }
    }

    /// libFuzzer parses the dictionary itself, so the rendered file must read back, under its syntax
    /// (quoted words, `\\` `\"` `\xHH`, at most 64 bytes), to exactly the word set, and the derivation
    /// must reach the literals the fuzzer most needs to synthesize (our host id, the MCP protocol pin,
    /// the `_meta` keys, the manifest ownership marker). The cap and the escapes are exercised on a
    /// synthetic directory whose words sit exactly on and over the cap, so the filter is seen refusing.
    #[test]
    fn the_dictionary_reads_back_under_libfuzzer_syntax_and_carries_the_protocol_literals() {
        fn read_back(rendered: &str) -> BTreeSet<Vec<u8>> {
            let mut words = BTreeSet::new();
            for line in rendered.lines() {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let inner = line
                    .strip_prefix('"')
                    .and_then(|l| l.strip_suffix('"'))
                    .unwrap_or_else(|| panic!("not a quoted word: {line}"));
                let mut decoded = Vec::new();
                let mut bytes = inner.bytes();
                while let Some(byte) = bytes.next() {
                    if byte != b'\\' {
                        assert!(
                            (0x20..=0x7e).contains(&byte) && byte != b'"',
                            "raw byte {byte:#04x} outside printable ASCII in {line}"
                        );
                        decoded.push(byte);
                        continue;
                    }
                    match bytes.next() {
                        Some(b'\\') => decoded.push(b'\\'),
                        Some(b'"') => decoded.push(b'"'),
                        Some(b'x') => {
                            // libFuzzer's parser takes exactly two hex digits here, and from_str_radix
                            // alone would also take a sign.
                            let hex: Vec<u8> = bytes.by_ref().take(2).collect();
                            assert!(
                                hex.len() == 2 && hex.iter().all(u8::is_ascii_hexdigit),
                                "malformed \\x escape in {line}"
                            );
                            decoded.push(
                                u8::from_str_radix(std::str::from_utf8(&hex).unwrap(), 16).unwrap(),
                            );
                        }
                        other => panic!("unknown escape {other:?} in {line}"),
                    }
                }
                assert!(
                    (1..=DICTIONARY_WORD_MAX).contains(&decoded.len()),
                    "{line} decodes to {} bytes",
                    decoded.len()
                );
                assert!(words.insert(decoded), "{line} is listed twice");
            }
            words
        }

        let words = json_dictionary(&corpus());
        assert_eq!(
            read_back(&render_dictionary(&words)),
            words,
            "the file reads back to the word set"
        );
        for malformed in [
            "\"\\xf\"",
            "\"\\x+1\"",
            "\"\\xzz\"",
            "\"\\q\"",
            "\"unterminated",
            "\"\"",
        ] {
            assert!(
                std::panic::catch_unwind(|| read_back(malformed)).is_err(),
                "the read-back must refuse {malformed} as libFuzzer does"
            );
        }
        for literal in [
            NATIVE_HOST_ID,
            MCP_PROTOCOL_VERSION,
            MCP_META_PROTOCOL_VERSION,
            MCP_META_CLIENT_CAPABILITIES,
            MCP_META_SERVER_INFO,
            fuzz_api::MANIFEST_DESCRIPTION,
        ] {
            assert!(
                words.contains(literal.as_bytes()),
                "the dictionary lost {literal:?}"
            );
        }

        // The control: one synthetic seed whose strings sit on the cap, over it, and need every escape.
        let on_cap = "y".repeat(DICTIONARY_WORD_MAX);
        let over_cap = "x".repeat(DICTIONARY_WORD_MAX + 1);
        let probe = Directory {
            target: crate::targets::ATTACH,
            seeds: vec![Seed::accepted(
                "probe",
                compact(
                    &json!({ "k\"ey": on_cap, "esc\\aped": over_cap, "utf8": "\u{e9}", "": 1 }),
                ),
                |_| true,
            )],
        };
        let synthetic = json_dictionary(&[probe]);
        let expected: BTreeSet<Vec<u8>> = [
            "{",
            "}",
            "[",
            "]",
            ":",
            ",",
            "\"",
            "true",
            "false",
            "null",
            "k\"ey",
            "esc\\aped",
            "utf8",
            "\u{e9}",
        ]
        .into_iter()
        .map(|s| s.as_bytes().to_vec())
        .chain([on_cap.into_bytes()])
        .collect();
        assert_eq!(
            synthetic, expected,
            "the over-cap word and the empty key are left out, the on-cap word is kept"
        );
        let rendered = render_dictionary(&synthetic);
        assert!(
            rendered.contains("\"k\\\"ey\"")
                && rendered.contains("\"esc\\\\aped\"")
                && rendered.contains("\"\\xc3\\xa9\""),
            "every escape libFuzzer knows is used: {rendered}"
        );
        assert_eq!(read_back(&rendered), synthetic, "the escapes read back");
    }
}
