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
    use std::collections::BTreeMap;
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

    /// What one module's source says to the ladder rule, from a `syn` parse. The trait cannot enumerate
    /// its implementors, so this is what ties the matrix to them.
    ///
    /// ```text
    /// impl Record for T                  -> record: T joins the set the matrix must exercise
    /// inherent fn load, const VERSION    -> shadow: hides the shared loader at a `T::load()` call site
    /// serde(default), serde(alias)       -> compat: a value for an absent field, a second accepted name
    /// serde(rename = ..)                 -> compat: fixes the wire name outside the type's own spelling
    /// serde(rename_all = ..)             -> allowed: the one spelling of every field
    /// serde(deserialize_with = ..)       -> allowed: serde still refuses an absent field without `default`,
    ///                                       and whether the fn refuses a malformed value is in its body
    /// ```
    ///
    /// Compat counts on types that derive `Deserialize`: on a Serialize-only type the same attributes name
    /// output and read nothing. Items a `macro_rules!` emits (PolicyOverlay's arms in `policy/mod.rs`,
    /// BridgeCommand's in `tools/catalogue.rs`) are opaque to the parse.
    #[derive(Debug, Default, PartialEq)]
    struct ModuleScan {
        records: Vec<String>,
        compat: Vec<String>,
        shadows: Vec<String>,
    }

    fn scan_module(source: &str) -> ModuleScan {
        const METHODS: [&str; 6] = ["load", "decode", "encode", "write", "remove", "path"];
        const COMPAT: [&str; 3] = ["default", "alias", "rename"];
        type Item<'a> = &'a mut dyn FnMut(&syn::meta::ParseNestedMeta<'_>) -> syn::Result<()>;
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
        fn each_item(attrs: &[syn::Attribute], tag: &str, item: Item) {
            fn under_cfg_attr(
                meta: &syn::meta::ParseNestedMeta,
                tag: &str,
                item: Item,
            ) -> syn::Result<()> {
                let key = name(&meta.path);
                if key == tag {
                    meta.parse_nested_meta(|inner| item(&inner))
                } else if key == "cfg_attr" {
                    meta.parse_nested_meta(|inner| under_cfg_attr(&inner, tag, item))
                } else {
                    skip_value(meta)
                }
            }
            for attr in attrs {
                if name(attr.path()) == tag {
                    attr.parse_nested_meta(|meta| item(&meta)).unwrap();
                } else if name(attr.path()) == "cfg_attr" {
                    attr.parse_nested_meta(|meta| under_cfg_attr(&meta, tag, item))
                        .unwrap();
                }
            }
        }
        fn derives_deserialize(attrs: &[syn::Attribute]) -> bool {
            let mut found = false;
            each_item(attrs, "derive", &mut |meta| {
                found |= name(&meta.path) == "Deserialize";
                Ok(())
            });
            found
        }
        fn compat_attrs(attrs: &[syn::Attribute], compat: &mut Vec<String>) {
            each_item(attrs, "serde", &mut |meta| {
                let key = name(&meta.path);
                if COMPAT.contains(&key.as_str()) {
                    compat.push(format!(
                        "{}: #[serde({key})]",
                        meta.path.span().start().line
                    ));
                }
                skip_value(meta)
            });
        }
        fn walk(items: &[syn::Item], scan: &mut ModuleScan) {
            for item in items {
                if let syn::Item::Mod(module) = item {
                    if let Some((_, items)) = &module.content {
                        walk(items, scan);
                    }
                } else if let syn::Item::Struct(s) = item {
                    if derives_deserialize(&s.attrs) {
                        compat_attrs(&s.attrs, &mut scan.compat);
                        for field in &s.fields {
                            compat_attrs(&field.attrs, &mut scan.compat);
                        }
                    }
                } else if let syn::Item::Enum(e) = item {
                    if derives_deserialize(&e.attrs) {
                        compat_attrs(&e.attrs, &mut scan.compat);
                        for variant in &e.variants {
                            compat_attrs(&variant.attrs, &mut scan.compat);
                            for field in &variant.fields {
                                compat_attrs(&field.attrs, &mut scan.compat);
                            }
                        }
                    }
                } else if let syn::Item::Impl(imp) = item {
                    match &imp.trait_ {
                        Some((_, path, _)) => {
                            if let (true, syn::Type::Path(ty)) =
                                (name(path) == "Record", &*imp.self_ty)
                            {
                                scan.records.push(name(&ty.path));
                            }
                        }
                        None => inherent_items(&imp.items, &mut scan.shadows),
                    }
                }
            }
        }
        fn inherent_items(items: &[syn::ImplItem], shadows: &mut Vec<String>) {
            for item in items {
                if let syn::ImplItem::Fn(f) = item {
                    let name = f.sig.ident.unraw();
                    if METHODS.contains(&name.to_string().as_str()) {
                        shadows.push(format!("{}: inherent fn {name}", name.span().start().line));
                    }
                } else if let syn::ImplItem::Const(c) = item {
                    if c.ident.unraw() == "VERSION" {
                        shadows.push(format!(
                            "{}: inherent const VERSION",
                            c.ident.span().start().line
                        ));
                    }
                }
            }
        }
        let mut scan = ModuleScan::default();
        walk(&syn::parse_file(source).unwrap().items, &mut scan);
        scan
    }

    /// The modules whose `Deserialize` types carry compat attributes today, by path under `src/`: the wire
    /// frames, whose generated TypeScript side reads the same spelling. The list only shrinks, and a scan
    /// that reaches no attribute cannot stay green. `crate::migrations` is the one home for compat code
    /// and is not scanned.
    const WIRE_SHAPE_MODULES: [&str; 4] = [
        "enclave/cli.rs",
        "protocol.rs",
        "protocol/control.rs",
        "tools/args.rs",
    ];

    /// Every `Record` implementor in the crate, and everything the ladder rule refuses outside
    /// `crate::migrations`.
    fn scan_crate() -> (BTreeSet<String>, Vec<String>) {
        fn walk(src: &Path, dir: &Path, found: &mut Vec<(PathBuf, ModuleScan)>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    if path.strip_prefix(src) != Ok(Path::new("migrations")) {
                        walk(src, &path, found);
                    }
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let scan = scan_module(&fs::read_to_string(&path).unwrap());
                    found.push((path.strip_prefix(src).unwrap().to_path_buf(), scan));
                }
            }
        }
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        walk(&src, &src, &mut found);
        let (mut records, mut refused) = (BTreeSet::new(), Vec::new());
        let mut wire_hits: BTreeMap<&str, usize> =
            WIRE_SHAPE_MODULES.iter().map(|m| (*m, 0)).collect();
        for (rel, scan) in found {
            let is_record = !scan.records.is_empty();
            records.extend(scan.records);
            let wire = WIRE_SHAPE_MODULES
                .iter()
                .find(|m| Path::new(m) == rel)
                .copied();
            let mut items = Vec::new();
            match wire {
                Some(module) => {
                    *wire_hits.get_mut(module).unwrap() = scan.compat.len();
                    if is_record {
                        items.push("a record module cannot be in WIRE_SHAPE_MODULES".to_string());
                    }
                }
                None => items.extend(
                    scan.compat
                        .into_iter()
                        .map(|item| format!("{item}, in a module not in WIRE_SHAPE_MODULES")),
                ),
            }
            if is_record {
                items.extend(scan.shadows);
            }
            refused.extend(
                items
                    .into_iter()
                    .map(|item| format!("{}:{item}", rel.display())),
            );
        }
        for (module, hits) in wire_hits {
            if hits == 0 {
                refused.push(format!(
                    "{module}: stale WIRE_SHAPE_MODULES entry, no compat attribute left"
                ));
            }
        }
        (records, refused)
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
        let (implemented, refused) = scan_crate();
        assert_eq!(
            implemented, exercised,
            "every Record impl is exercised here, and only those"
        );
        assert!(
            refused.is_empty(),
            "outside crate::migrations no module reads a second spelling beyond the wire shapes, and no record module shadows the shared loader: {refused:#?}"
        );
    }

    /// The scanner's controls. The matrix's census catches a scan that finds no records, but a scan that
    /// finds the records and refuses nothing keeps it green while saying nothing about the crate.
    #[test]
    fn record_module_scan_refuses_and_allows_the_right_items() {
        fn scan(records: &[&str], compat: &[&str], shadows: &[&str]) -> ModuleScan {
            let owned = |items: &[&str]| items.iter().map(ToString::to_string).collect();
            ModuleScan {
                records: owned(records),
                compat: owned(compat),
                shadows: owned(shadows),
            }
        }
        let cases: [(&str, &str, ModuleScan); 13] = [
            (
                "field default",
                "#[derive(Deserialize)]\nstruct R {\n    #[serde(default)]\n    a: u64,\n}",
                scan(&[], &["3: #[serde(default)]"], &[]),
            ),
            (
                "default with a provider fn",
                "#[derive(Deserialize)]\nstruct R {\n    #[serde(default = \"f\")]\n    a: u64,\n}",
                scan(&[], &["3: #[serde(default)]"], &[]),
            ),
            (
                "cfg_attr nested in cfg_attr",
                "#[derive(Deserialize)]\nstruct R {\n    #[cfg_attr(unix, cfg_attr(feature = \"x\", serde(default)))]\n    a: u64,\n}",
                scan(&[], &["3: #[serde(default)]"], &[]),
            ),
            (
                "block comment inside the attribute",
                "#[derive(Deserialize)]\nstruct R {\n    #[serde(/* older files */ default)]\n    a: u64,\n}",
                scan(&[], &["3: #[serde(default)]"], &[]),
            ),
            (
                "cfg_attr wrapper and the nested rename form",
                "#[derive(Deserialize)]\n#[cfg_attr(feature = \"x\", serde(alias = \"b\"))]\nenum E {\n    #[serde(rename(deserialize = \"a\"))]\n    A,\n}",
                scan(&[], &["2: #[serde(alias)]", "4: #[serde(rename)]"], &[]),
            ),
            (
                "rename_all, deserialize_with and skip_serializing_if stay allowed",
                "#[derive(Deserialize)]\n#[serde(rename_all = \"camelCase\", deny_unknown_fields)]\nstruct R {\n    #[serde(deserialize_with = \"de\", skip_serializing_if = \"Option::is_none\")]\n    a: Option<u64>,\n}",
                scan(&[], &[], &[]),
            ),
            (
                "a Serialize-only type's rename names output and reads nothing",
                "#[derive(Serialize)]\nstruct R {\n    #[serde(rename = \"a\", default)]\n    a: u64,\n}",
                scan(&[], &[], &[]),
            ),
            (
                "derive by path and under cfg_attr still makes the type a reader",
                "#[cfg_attr(feature = \"x\", derive(serde::Deserialize))]\nstruct R {\n    #[serde(default)]\n    a: u64,\n}",
                scan(&[], &["3: #[serde(default)]"], &[]),
            ),
            (
                "inherent shadows, not a free fn or a trait impl",
                "impl R {\n    fn load() {}\n    const VERSION: usize = 1;\n}\nfn load() {}\nimpl Other for R {\n    fn load() {}\n}",
                scan(&[], &[], &["2: inherent fn load", "3: inherent const VERSION"]),
            ),
            (
                "raw identifiers spell the same shadows",
                "impl R {\n    fn r#load() {}\n    const r#VERSION: usize = 1;\n}",
                scan(&[], &[], &["2: inherent fn load", "3: inherent const VERSION"]),
            ),
            (
                "raw spellings of the trait, the type and the attribute names",
                "impl r#Record for r#A {}\n#[r#derive(r#Deserialize)]\nstruct A {\n    #[r#cfg_attr(all(), r#serde(alias = \"legacy\"))]\n    a: u64,\n}",
                scan(&["A"], &["4: #[serde(alias)]"], &[]),
            ),
            (
                "record impls by any path, in nested modules too",
                "mod inner {\n    impl crate::runtime_record::Record for A {}\n    impl Record for B<'static> {}\n}",
                scan(&["A", "B"], &[], &[]),
            ),
            (
                "attribute text in a comment or a string is not an attribute",
                "/// Do not add #[serde(default)] here.\nconst NOTE: &str = \"#[serde(alias = \\\"k\\\")]\";\nfn consume_serde(default: u64) {}",
                scan(&[], &[], &[]),
            ),
        ];
        for (case, source, expected) in cases {
            assert_eq!(scan_module(source), expected, "{case}");
        }
    }
}
