//! One loader and one writer for every JSON record in the 0700 runtime directory.
//!
//! A record file is an envelope, `{"version": N, ...body}`, where N counts the migration rungs the body has
//! been through. The version is never declared: it IS the length of the record's ladder in
//! [`crate::migrations`], so a rung cannot land without the version moving and the version cannot move
//! without a rung. No reader branches on a version; the ladder is the only home for compatibility code.
//!
//! ```text
//! absent file                 -> Ok(None); each record says what absence means (bootstrap, no policy yet)
//! over MAX_BYTES              -> refused unread (fsguard::read_capped)
//! version above the ladder    -> refused: a newer binary's file, or a forged one, is never half-read
//! version below the ladder    -> the pending rungs run in order, then the body parses as the record type
//! damaged JSON, unknown field -> refused; every record is deny_unknown_fields and every caller fails closed
//! repeated key, any depth     -> refused; a record has exactly one accepted spelling
//! ```
//!
//! Writes serialize under the current version, refuse a body the read cap could not load back, and land
//! atomically at 0600 through [`crate::fsguard::write_private_atomic`]. Every mutation demands the
//! [`RuntimeLockToken`] that only [`crate::ipc::with_runtime_lock`] mints, so a lock-free rewrite does not
//! compile.

use std::collections::BTreeSet;
use std::fmt::{self, Display};
use std::fs;
use std::io;
use std::path::PathBuf;

use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::fsguard;
use crate::ipc::{self, RuntimeLockToken};

/// One migration step: lifts a record body from version `i` to `i + 1`. Rung `i` of a ladder is applied
/// to a file stored at version `i`.
pub type Rung = fn(Value) -> io::Result<Value>;

/// What a record declares: its file name, its read cap, and its ladder. Everything else comes from
/// [`RuntimeRecord`], which every `Record` gets.
pub trait Record: Serialize + DeserializeOwned + Sized {
    /// File name inside [`ipc::runtime_dir`].
    const FILE: &'static str;
    /// Read cap; a larger file is refused unread.
    const MAX_BYTES: usize;
    /// The migration ladder, from `crate::migrations`.
    const MIGRATIONS: &'static [Rung];
}

/// The loader and writer shared by every [`Record`], implemented once below. A second impl does not
/// compile; an inherent method on a record would shadow these at its call sites, and the matrix test
/// refuses one.
pub trait RuntimeRecord: Record {
    const VERSION: usize = Self::MIGRATIONS.len();

    fn path() -> PathBuf {
        ipc::runtime_dir().join(Self::FILE)
    }

    /// Read the record. `Ok(None)` when the file does not exist. A present file that cannot be read is
    /// an error, never a silent `None`: treating a damaged record as absent would fail open.
    fn load() -> io::Result<Option<Self>> {
        match fsguard::read_capped(&Self::path(), Self::MAX_BYTES)? {
            Some(bytes) => Self::decode(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn decode(bytes: &[u8]) -> io::Result<Self> {
        serde_json::from_slice::<NoDuplicateKeys>(bytes).map_err(|e| invalid(Self::FILE, e))?;
        let envelope: Envelope<Map<String, Value>> =
            serde_json::from_slice(bytes).map_err(|e| invalid(Self::FILE, e))?;
        let Some(pending) = Self::MIGRATIONS.get(envelope.version..) else {
            return Err(invalid(
                Self::FILE,
                format!(
                    "version {} is above this binary's {}; refusing a file it cannot read",
                    envelope.version,
                    Self::VERSION
                ),
            ));
        };
        let body = pending
            .iter()
            .try_fold(Value::Object(envelope.body), |body, rung| rung(body))?;
        serde_json::from_value(body).map_err(|e| invalid(Self::FILE, e))
    }

    /// The bytes [`write`](Self::write) lands. Refuses a body over the read cap: a record that persists
    /// fine and then fails every load is worse than a refused write.
    fn encode(&self) -> io::Result<Vec<u8>> {
        let bytes = serde_json::to_vec_pretty(&Envelope {
            version: Self::VERSION,
            body: self,
        })?;
        if bytes.len() > Self::MAX_BYTES {
            return Err(invalid(
                Self::FILE,
                format!(
                    "would serialize to {} bytes, over the {}-byte read cap",
                    bytes.len(),
                    Self::MAX_BYTES
                ),
            ));
        }
        Ok(bytes)
    }

    fn write(&self, _lock: &RuntimeLockToken) -> io::Result<()> {
        fsguard::write_private_atomic(&Self::path(), &self.encode()?)
    }

    fn remove(_lock: &RuntimeLockToken) -> io::Result<()> {
        match fs::remove_file(Self::path()) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            Ok(()) | Err(_) => Ok(()),
        }
    }
}

impl<T: Record> RuntimeRecord for T {}

/// The on-disk shape. `B` is the borrowed record on write and a raw map on read, so the rungs run
/// before the body is typed.
#[derive(Serialize, Deserialize)]
struct Envelope<B> {
    version: usize,
    #[serde(flatten)]
    body: B,
}

/// Refuses an object with a repeated key at any depth: `serde_json::Value` keeps the last duplicate, so
/// `{"killed":true,"killed":false}` would otherwise read as not killed.
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(Self)
    }
}

impl<'de> Visitor<'de> for NoDuplicateKeys {
    type Value = Self;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value without repeated object keys")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self, E> {
        Ok(Self)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self, E> {
        Ok(Self)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self, E> {
        Ok(Self)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self, E> {
        Ok(Self)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self, E> {
        Ok(Self)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self, E> {
        Ok(Self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self, A::Error> {
        while seq.next_element::<Self>()?.is_some() {}
        Ok(Self)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self, A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if seen.contains(&key) {
                return Err(de::Error::custom(format!("repeated key {key:?}")));
            }
            seen.insert(key);
            map.next_value::<Self>()?;
        }
        Ok(Self)
    }
}

fn invalid(file: &str, e: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{file}: {e}"))
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::path::Path;

    use syn::ext::IdentExt;
    use syn::spanned::Spanned;

    use super::*;
    use crate::allowlist::{Allowlist, Anchor, ClientEntry};
    use crate::enclave::{base64_encode, HostConfig};
    use crate::ipc::HashDigest;
    use crate::lang::LangStore;
    use crate::policy::{PolicyHistory, PolicyHistoryEntry, PolicyOverlay, PolicyStore};
    use crate::revocation::Revocation;
    use crate::test_support::scratch_runtime_dir;

    /// The facts the trait cannot force on a record: a `deny_unknown_fields` body, a `PartialEq` over
    /// every persisted field, the cap honoured before parsing, and the 0600 mode the writer promises.
    fn exercise<T: Record + PartialEq + Debug>(exercised: &mut BTreeSet<String>, sample: T) {
        let file = T::FILE;
        let type_name = std::any::type_name::<T>().rsplit("::").next().unwrap();
        assert!(
            exercised.insert(type_name.into()),
            "{file}: exercised twice"
        );
        assert!(T::load().unwrap().is_none(), "{file}: absent reads as None");

        ipc::with_runtime_lock(|lock| sample.write(lock)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(T::path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode & 0o077,
                0,
                "{file}: mode {mode:o} leaks group/other bits"
            );
        }
        assert_eq!(T::load().unwrap().unwrap(), sample, "{file}: round trip");

        let written: Map<String, Value> =
            serde_json::from_slice(&fs::read(T::path()).unwrap()).unwrap();
        assert_eq!(
            written.get("version"),
            Some(&Value::from(T::VERSION)),
            "{file}: the envelope carries the ladder length"
        );
        let edited = |edit: fn(&mut Map<String, Value>)| {
            let mut copy = written.clone();
            edit(&mut copy);
            serde_json::to_vec(&copy).unwrap()
        };
        // The written sample with its first body key repeated in front, so the document stays valid JSON
        // and `Value` alone would read it as the sample.
        let (key, value) = written.iter().find(|(k, _)| *k != "version").unwrap();
        let repeated = format!(
            "{{\"{key}\":{value},{}",
            serde_json::to_string(&written)
                .unwrap()
                .strip_prefix('{')
                .unwrap()
        )
        .into_bytes();
        // Valid JSON padded past the cap: an uncapped read would load it.
        let padded = {
            let mut bytes = serde_json::to_vec(&written).unwrap();
            bytes.resize(T::MAX_BYTES + 1, b' ');
            bytes
        };
        let tampered: [(&str, Vec<u8>); 6] = [
            (
                "version above the ladder",
                edited(|m| {
                    let above = m["version"].as_u64().unwrap() + 1;
                    m.insert("version".into(), Value::from(above));
                }),
            ),
            (
                "version missing",
                edited(|m| {
                    m.remove("version");
                }),
            ),
            (
                "unknown field",
                edited(|m| {
                    m.insert("surprise".into(), Value::Bool(true));
                }),
            ),
            ("repeated key", repeated),
            ("damaged json", b"{ not json".to_vec()),
            ("over the cap", padded),
        ];
        for (case, bytes) in tampered {
            fs::write(T::path(), bytes).unwrap();
            let err = T::load().expect_err(&format!("{file}: {case} must be refused"));
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidData,
                "{file}: {case}: {err}"
            );
        }

        ipc::with_runtime_lock(|lock| T::remove(lock)).unwrap();
        assert!(T::load().unwrap().is_none(), "{file}: removed");
        ipc::with_runtime_lock(|lock| T::remove(lock)).unwrap();
    }

    /// What the ladder rule refuses in one module, from a `syn` parse of its source. The trait cannot
    /// enumerate its implementors, so this is what ties the matrix to them.
    ///
    /// ```text
    /// impl Record for T                  -> T joins the set the matrix must exercise
    /// inherent fn load, const VERSION    -> refused: shadows the shared loader at a `T::load()` call site
    /// serde(default), serde(alias)       -> refused: a value for an absent field, a second accepted name
    /// serde(rename = ..)                 -> refused: fixes the wire name outside the type's own spelling
    /// serde(rename_all = ..)             -> allowed: the one spelling of every field
    /// serde(deserialize_with = ..)       -> allowed: serde still refuses an absent field without `default`,
    ///                                       and whether the fn refuses a malformed value is in its body
    /// ```
    ///
    /// Items a `macro_rules!` emits (PolicyOverlay's arms in `policy/mod.rs`) are opaque to the parse.
    fn scan_module(source: &str) -> (Vec<String>, Vec<String>) {
        const METHODS: [&str; 6] = ["load", "decode", "encode", "write", "remove", "path"];
        const COMPAT: [&str; 3] = ["default", "alias", "rename"];
        // Every name goes through here: `r#load`, `impl r#Record` and `#[r#cfg_attr]` spell the same items.
        fn name(path: &syn::Path) -> String {
            path.segments
                .last()
                .map(|s| s.ident.unraw().to_string())
                .unwrap_or_default()
        }
        fn skip_value(meta: &syn::meta::ParseNestedMeta) -> syn::Result<()> {
            if meta.input.peek(syn::Token![=]) {
                meta.value()?.parse::<syn::Expr>()?;
            } else if meta.input.peek(syn::token::Paren) {
                // A whole group, not nested metas: `all()` and `rename(serialize = ..)` carry no key of ours.
                meta.input.parse::<proc_macro2::TokenTree>()?;
            }
            Ok(())
        }
        fn serde_item(
            meta: &syn::meta::ParseNestedMeta,
            refused: &mut Vec<String>,
        ) -> syn::Result<()> {
            let key = name(&meta.path);
            if COMPAT.contains(&key.as_str()) {
                refused.push(format!(
                    "{}: #[serde({key})]",
                    meta.path.span().start().line
                ));
            }
            skip_value(meta)
        }
        fn serde_attrs(attrs: &[syn::Attribute], refused: &mut Vec<String>) {
            for attr in attrs {
                if name(attr.path()) == "serde" {
                    attr.parse_nested_meta(|meta| serde_item(&meta, refused))
                        .unwrap();
                } else if name(attr.path()) == "cfg_attr" {
                    attr.parse_nested_meta(|meta| {
                        if name(&meta.path) == "serde" {
                            meta.parse_nested_meta(|inner| serde_item(&inner, refused))
                        } else {
                            skip_value(&meta)
                        }
                    })
                    .unwrap();
                }
            }
        }
        fn walk(items: &[syn::Item], records: &mut Vec<String>, refused: &mut Vec<String>) {
            for item in items {
                if let syn::Item::Mod(module) = item {
                    if let Some((_, items)) = &module.content {
                        walk(items, records, refused);
                    }
                } else if let syn::Item::Struct(s) = item {
                    serde_attrs(&s.attrs, refused);
                    for field in &s.fields {
                        serde_attrs(&field.attrs, refused);
                    }
                } else if let syn::Item::Enum(e) = item {
                    serde_attrs(&e.attrs, refused);
                    for variant in &e.variants {
                        serde_attrs(&variant.attrs, refused);
                        for field in &variant.fields {
                            serde_attrs(&field.attrs, refused);
                        }
                    }
                } else if let syn::Item::Impl(imp) = item {
                    match &imp.trait_ {
                        Some((_, path, _)) => {
                            if let (true, syn::Type::Path(ty)) =
                                (name(path) == "Record", &*imp.self_ty)
                            {
                                records.push(name(&ty.path));
                            }
                        }
                        None => inherent_items(&imp.items, refused),
                    }
                }
            }
        }
        fn inherent_items(items: &[syn::ImplItem], refused: &mut Vec<String>) {
            for item in items {
                if let syn::ImplItem::Fn(f) = item {
                    let name = f.sig.ident.unraw();
                    if METHODS.contains(&name.to_string().as_str()) {
                        refused.push(format!("{}: inherent fn {name}", name.span().start().line));
                    }
                } else if let syn::ImplItem::Const(c) = item {
                    if c.ident.unraw() == "VERSION" {
                        refused.push(format!(
                            "{}: inherent const VERSION",
                            c.ident.span().start().line
                        ));
                    }
                }
            }
        }
        let (mut records, mut refused) = (Vec::new(), Vec::new());
        walk(
            &syn::parse_file(source).unwrap().items,
            &mut records,
            &mut refused,
        );
        (records, refused)
    }

    /// Persisted shapes the ladder rule binds without an `impl Record`, by path under `src/`. The audit
    /// trail is one JSON line per event with its own version stamp: the shared whole-file `load` and
    /// lock-holding atomic `write` do not fit an append-only log that must never take the runtime lock,
    /// so nothing in the module marks it and the scan names it here.
    const LINE_RECORD_MODULES: [&str; 1] = ["audit.rs"];

    fn record_impls_in_source() -> (BTreeSet<String>, Vec<String>) {
        fn walk(src: &Path, dir: &Path, types: &mut BTreeSet<String>, refused: &mut Vec<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(src, &path, types, refused);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let (records, found) = scan_module(&fs::read_to_string(&path).unwrap());
                let named = path
                    .strip_prefix(src)
                    .is_ok_and(|rel| LINE_RECORD_MODULES.iter().any(|m| Path::new(m) == rel));
                if records.is_empty() && !named {
                    continue;
                }
                types.extend(records);
                refused.extend(
                    found
                        .into_iter()
                        .map(|item| format!("{}:{item}", path.display())),
                );
            }
        }
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for module in LINE_RECORD_MODULES {
            assert!(
                src.join(module).is_file(),
                "{module}: named for the scan but not under src/"
            );
        }
        let (mut types, mut refused) = (BTreeSet::new(), Vec::new());
        walk(&src, &src, &mut types, &mut refused);
        (types, refused)
    }

    #[test]
    fn every_record_honours_the_cap_the_envelope_the_mode_and_strict_parsing() {
        let _dir = scratch_runtime_dir("runtime-record-matrix");
        let mut exercised = BTreeSet::new();
        exercise(
            &mut exercised,
            Allowlist {
                clients: vec![ClientEntry {
                    name: "codex".into(),
                    anchor: Anchor::Hash(HashDigest::try_from("ab".repeat(20)).unwrap()),
                    added_unix: 7,
                }],
            },
        );
        exercise(
            &mut exercised,
            Revocation {
                epoch: 5,
                clients_epoch: 2,
                host_key_epoch: 3,
                policy_epoch: 4,
                lang_epoch: 1,
                clients_enrolled: true,
                killed: true,
                kill_epoch: 5,
            },
        );
        exercise(
            &mut exercised,
            HostConfig {
                enrolled: true,
                granularity: "session".into(),
            },
        );
        exercise(
            &mut exercised,
            PolicyStore {
                baseline_b64: base64_encode(b"{}"),
                sig_b64: Some("c2ln".into()),
                key_id: Some("kid".into()),
                overlay: Some(PolicyOverlay {
                    page_eval_enabled: Some(false),
                    ..PolicyOverlay::default()
                }),
            },
        );
        exercise(
            &mut exercised,
            PolicyHistory {
                entries: vec![PolicyHistoryEntry {
                    baseline_b64: base64_encode(b"{}"),
                    sig_b64: None,
                    key_id: None,
                    overlay: None,
                    superseded_unix: 11,
                }],
            },
        );
        exercise(
            &mut exercised,
            LangStore {
                value: "zh_TW".into(),
                seq: 3,
            },
        );
        let (implemented, refused) = record_impls_in_source();
        assert_eq!(
            implemented, exercised,
            "every Record impl is exercised here, and only those"
        );
        assert!(
            refused.is_empty(),
            "outside crate::migrations a record module neither shadows the shared loader nor reads a second spelling: {refused:#?}"
        );
    }

    /// The scanner's controls. The matrix's census catches a scan that finds no records, but a scan that
    /// finds the records and refuses nothing keeps it green while saying nothing about the crate.
    #[test]
    fn record_module_scan_refuses_and_allows_the_right_items() {
        let cases: [(&str, &str, &[&str], &[&str]); 9] = [
            (
                "field default",
                "struct R {\n    #[serde(default)]\n    a: u64,\n}",
                &[],
                &["2: #[serde(default)]"],
            ),
            (
                "block comment inside the attribute",
                "struct R {\n    #[serde(/* older files */ default)]\n    a: u64,\n}",
                &[],
                &["2: #[serde(default)]"],
            ),
            (
                "cfg_attr wrapper and the nested rename form",
                "#[cfg_attr(feature = \"x\", serde(alias = \"b\"))]\nenum E {\n    #[serde(rename(deserialize = \"a\"))]\n    A,\n}",
                &[],
                &["1: #[serde(alias)]", "3: #[serde(rename)]"],
            ),
            (
                "rename_all, deserialize_with and skip_serializing_if stay allowed",
                "#[serde(rename_all = \"camelCase\", deny_unknown_fields)]\nstruct R {\n    #[serde(deserialize_with = \"de\", skip_serializing_if = \"Option::is_none\")]\n    a: Option<u64>,\n}",
                &[],
                &[],
            ),
            (
                "inherent shadows, not a free fn or a trait impl",
                "impl R {\n    fn load() {}\n    const VERSION: usize = 1;\n}\nfn load() {}\nimpl Other for R {\n    fn load() {}\n}",
                &[],
                &["2: inherent fn load", "3: inherent const VERSION"],
            ),
            (
                "raw identifiers spell the same shadows",
                "impl R {\n    fn r#load() {}\n    const r#VERSION: usize = 1;\n}",
                &[],
                &["2: inherent fn load", "3: inherent const VERSION"],
            ),
            (
                "raw spellings of the trait, the type and the attribute names",
                "impl r#Record for r#A {}\nstruct A {\n    #[r#cfg_attr(all(), r#serde(alias = \"legacy\"))]\n    a: u64,\n}",
                &["A"],
                &["3: #[serde(alias)]"],
            ),
            (
                "record impls by any path, in nested modules too",
                "mod inner {\n    impl crate::runtime_record::Record for A {}\n    impl Record for B<'static> {}\n}",
                &["A", "B"],
                &[],
            ),
            (
                "attribute text in a comment or a string is not an attribute",
                "/// Do not add #[serde(default)] here.\nconst NOTE: &str = \"#[serde(alias = \\\"k\\\")]\";\nfn consume_serde(default: u64) {}",
                &[],
                &[],
            ),
        ];
        for (case, source, records, refused) in cases {
            assert_eq!(
                scan_module(source),
                (
                    records.iter().map(ToString::to_string).collect(),
                    refused.iter().map(ToString::to_string).collect()
                ),
                "{case}"
            );
        }
    }
}
