//! One loader and one writer for every JSON record in the 0700 runtime directory.
//!
//! A record file is an envelope, `{"version": N, ...body}`, where N is the rung of the record's
//! [`Ladder`] the body stands on. The version is never declared: it is derived from the ladder in
//! [`crate::migrations`] (the floor plus the rung count, the rule on `Ladder`), so a rung cannot land
//! without the version moving. No reader branches on a version; the ladder is the only home for
//! compatibility code.
//!
//! ```text
//! absent file                 -> Ok(None); each record says what absence means (bootstrap, no policy yet)
//! over MAX_BYTES              -> refused unread (fsguard::read_capped)
//! version above the ladder    -> refused: a newer binary's file, or a forged one, is never half-read
//! version below the floor     -> refused: too old to climb, so no rung ever runs on a body it was not written for
//! version on the ladder       -> the pending rungs run in order, then the body parses as the record type
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

/// One migration step: lifts a record body from version `i` to `i + 1`.
pub type Rung = fn(Value) -> io::Result<Value>;

/// A record's migration ladder: its rungs, and the version the first rung lifts from. The explicit floor
/// is what makes retiring the oldest rung safe: without it every stored version would silently renumber
/// the moment `rungs[0]` is deleted, and the wrong rung would run on every existing file.
///
/// ```text
/// retire rung 0, raise first_version   -> current unchanged, every stored version keeps its meaning
/// stored < first_version               -> too old to climb: refused like any malformed record
/// ```
pub struct Ladder {
    pub first_version: usize,
    pub rungs: &'static [Rung],
}

impl Ladder {
    pub const fn current(&self) -> usize {
        self.first_version.saturating_add(self.rungs.len())
    }

    pub fn climb(&self, version: usize, body: Value) -> io::Result<Value> {
        let refused = |why: String| io::Error::new(io::ErrorKind::InvalidData, why);
        let Some(climbed) = version.checked_sub(self.first_version) else {
            return Err(refused(format!(
                "version {version} is below this binary's floor {}; too old to migrate",
                self.first_version
            )));
        };
        let pending = self.rungs.get(climbed..).ok_or_else(|| {
            refused(format!(
                "version {version} is above this binary's {}; refusing a file it cannot read",
                self.current()
            ))
        })?;
        pending.iter().try_fold(body, |body, rung| rung(body))
    }
}

/// What a record declares: its file name, its read cap, and its ladder. Everything else comes from
/// [`RuntimeRecord`], which every `Record` gets.
pub trait Record: Serialize + DeserializeOwned + Sized {
    /// File name inside [`ipc::runtime_dir`].
    const FILE: &'static str;
    /// Read cap; a larger file is refused unread.
    const MAX_BYTES: usize;
    /// The migration ladder, from `crate::migrations`.
    const LADDER: Ladder;
}

/// The loader and writer shared by every [`Record`], implemented once below. A second impl does not
/// compile; an inherent method on a record would shadow these at its call sites, and the matrix test
/// refuses one.
pub trait RuntimeRecord: Record {
    const VERSION: usize = Self::LADDER.current();

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
        let body = Self::LADDER
            .climb(envelope.version, Value::Object(envelope.body))
            .map_err(|e| invalid(Self::FILE, e))?;
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

    use serde_json::json;
    use syn::ext::IdentExt;
    use syn::spanned::Spanned;
    use syn::visit::Visit;

    use super::*;
    use crate::allowlist::{Anchor, ClientEntry};
    use crate::enclave::{base64_encode, HostConfig};
    use crate::ipc::HashDigest;
    use crate::lang::LangStore;
    use crate::policy::{PolicyHistory, PolicyHistoryEntry, PolicyOverlay, PolicyStore};
    use crate::test_support::scratch_runtime_dir;
    use crate::trust::{Clients, Trust};

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
            "{file}: the envelope carries the ladder's current version"
        );
        let edited = |edit: &dyn Fn(&mut Map<String, Value>)| {
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
        // One below a floor of zero is -1, which the usize envelope refuses as the floor would.
        let below_floor = i64::try_from(T::LADDER.first_version).unwrap() - 1;
        let tampered: [(&str, Vec<u8>); 7] = [
            (
                "version above the ladder",
                edited(&|m| {
                    m.insert("version".into(), Value::from(T::VERSION + 1));
                }),
            ),
            (
                "version below the floor",
                edited(&|m| {
                    m.insert("version".into(), Value::from(below_floor));
                }),
            ),
            (
                "version missing",
                edited(&|m| {
                    m.remove("version");
                }),
            ),
            (
                "unknown field",
                edited(&|m| {
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
    /// its implementors, so this is what ties the matrix to them. The visitor reaches items anywhere in
    /// the file, fn bodies and `const _` blocks included; a `macro_rules!` body is tokens to it.
    ///
    /// ```text
    /// impl Record for T                    -> record: T joins the set the matrix must exercise
    /// inherent fn load, const VERSION      -> shadow: hides the shared loader at a `T::load()` call site
    /// serde(default = "f"), serde(alias)   -> compat: a value for an absent field, a second accepted name
    /// serde(default) on a non-Option field -> compat: the type's Default fills the absent field; a genuine
    ///                                         default lives in the type's constructor or on the consuming
    ///                                         side (as `timeoutMs` does in the extension), never in serde
    /// serde(default) on an Option field    -> compat: serde reads an absent Option as None by itself, so
    ///                                         the attribute only reads as a compat hint
    ///   .. in one list with deserialize_with -> allowed: under a custom parse serde refuses an absent field
    ///                                         outright, so the pair is the one spelling of such a field
    /// serde(rename = ..)                   -> compat: a wire name outside the type's own spelling; a raw
    ///                                         identifier (`r#ref`) spells a keyword without it
    /// serde(rename_all = ..)               -> allowed: the one spelling of every field
    /// ```
    ///
    /// Compat counts on types that derive `Deserialize`: on a Serialize-only type the same attributes name
    /// output and read nothing. The two macros that emit wire types, `policy_fields!` (policy/mod.rs) and
    /// `catalogue!` (tools/catalogue.rs), take one literal per row and feed it to every carrier's `rename`
    /// and to the name lookups, so that `rename` is the type's own spelling; the parse never sees it.
    #[derive(Debug, Default, PartialEq)]
    struct ModuleScan {
        records: Vec<String>,
        compat: Vec<String>,
        shadows: Vec<String>,
    }

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

    /// One entry of an attribute's nested list: its key, whether a `= value` follows, and its line.
    struct Entry {
        key: String,
        has_value: bool,
        line: usize,
    }

    fn entry(meta: &syn::meta::ParseNestedMeta) -> syn::Result<Entry> {
        let entry = Entry {
            key: name(&meta.path),
            has_value: meta.input.peek(syn::Token![=]),
            line: meta.path.span().start().line,
        };
        skip_value(meta)?;
        Ok(entry)
    }

    /// Every `tag(..)` list among `attrs`, through any depth of `cfg_attr`, one call per list. A list under
    /// a `cfg_attr` is its own: its condition gates it apart from its siblings, so a judgment that spans two
    /// lists would read an inactive one.
    fn each_list(attrs: &[syn::Attribute], tag: &str, list: &mut dyn FnMut(Vec<Entry>)) {
        fn under_cfg_attr(
            meta: &syn::meta::ParseNestedMeta,
            tag: &str,
            list: &mut dyn FnMut(Vec<Entry>),
        ) -> syn::Result<()> {
            let key = name(&meta.path);
            if key == tag {
                let mut entries = Vec::new();
                meta.parse_nested_meta(|inner| {
                    entries.push(entry(&inner)?);
                    Ok(())
                })?;
                list(entries);
                Ok(())
            } else if key == "cfg_attr" {
                meta.parse_nested_meta(|inner| under_cfg_attr(&inner, tag, list))
            } else {
                skip_value(meta)
            }
        }
        for attr in attrs {
            if name(attr.path()) == tag {
                let mut entries = Vec::new();
                attr.parse_nested_meta(|inner| {
                    entries.push(entry(&inner)?);
                    Ok(())
                })
                .unwrap();
                list(entries);
            } else if name(attr.path()) == "cfg_attr" {
                attr.parse_nested_meta(|meta| under_cfg_attr(&meta, tag, list))
                    .unwrap();
            }
        }
    }

    fn derives_deserialize(attrs: &[syn::Attribute]) -> bool {
        let mut found = false;
        each_list(attrs, "derive", &mut |entries| {
            found |= entries.iter().any(|e| e.key == "Deserialize");
        });
        found
    }

    fn is_option(ty: &syn::Type) -> bool {
        matches!(ty, syn::Type::Path(p) if name(&p.path) == "Option")
    }

    impl ModuleScan {
        /// The compat attributes of one container or field (`ty` is the field's type, `None` for the
        /// container), by the rule in the type docs. The pair is judged within one `serde(..)` list.
        fn compat_attrs(&mut self, attrs: &[syn::Attribute], ty: Option<&syn::Type>) {
            each_list(attrs, "serde", &mut |entries| {
                let required_pair = ty.is_some_and(is_option)
                    && entries.iter().any(|e| e.key == "deserialize_with");
                for e in entries {
                    let compat = match e.key.as_str() {
                        "alias" | "rename" => true,
                        "default" => e.has_value || !required_pair,
                        _ => false,
                    };
                    if compat {
                        self.compat.push(format!("{}: #[serde({})]", e.line, e.key));
                    }
                }
            });
        }

        fn fields(&mut self, fields: &syn::Fields) {
            for field in fields {
                self.compat_attrs(&field.attrs, Some(&field.ty));
            }
        }
    }

    impl<'ast> syn::visit::Visit<'ast> for ModuleScan {
        fn visit_item_struct(&mut self, s: &'ast syn::ItemStruct) {
            if derives_deserialize(&s.attrs) {
                self.compat_attrs(&s.attrs, None);
                self.fields(&s.fields);
            }
            syn::visit::visit_item_struct(self, s);
        }

        fn visit_item_enum(&mut self, e: &'ast syn::ItemEnum) {
            if derives_deserialize(&e.attrs) {
                self.compat_attrs(&e.attrs, None);
                for variant in &e.variants {
                    self.compat_attrs(&variant.attrs, None);
                    self.fields(&variant.fields);
                }
            }
            syn::visit::visit_item_enum(self, e);
        }

        fn visit_item_impl(&mut self, imp: &'ast syn::ItemImpl) {
            match &imp.trait_ {
                Some((_, path, _)) => {
                    if let (true, syn::Type::Path(ty)) = (name(path) == "Record", &*imp.self_ty) {
                        self.records.push(name(&ty.path));
                    }
                }
                None => {
                    const METHODS: [&str; 6] =
                        ["load", "decode", "encode", "write", "remove", "path"];
                    for item in &imp.items {
                        if let syn::ImplItem::Fn(f) = item {
                            let name = f.sig.ident.unraw();
                            if METHODS.contains(&name.to_string().as_str()) {
                                self.shadows.push(format!(
                                    "{}: inherent fn {name}",
                                    name.span().start().line
                                ));
                            }
                        } else if let syn::ImplItem::Const(c) = item {
                            if c.ident.unraw() == "VERSION" {
                                self.shadows.push(format!(
                                    "{}: inherent const VERSION",
                                    c.ident.span().start().line
                                ));
                            }
                        }
                    }
                }
            }
            syn::visit::visit_item_impl(self, imp);
        }
    }

    fn scan_module(source: &str) -> ModuleScan {
        let mut scan = ModuleScan::default();
        scan.visit_file(&syn::parse_file(source).unwrap());
        scan
    }

    /// Every `Record` implementor in the crate, and everything the ladder rule refuses outside
    /// `crate::migrations`, the one home for compat code.
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
        for (rel, scan) in found {
            let is_record = !scan.records.is_empty();
            records.extend(scan.records);
            let mut items = scan.compat;
            if is_record {
                items.extend(scan.shadows);
            }
            refused.extend(
                items
                    .into_iter()
                    .map(|item| format!("{}:{item}", rel.display())),
            );
        }
        (records, refused)
    }

    #[test]
    fn every_record_honours_the_cap_the_envelope_the_mode_and_strict_parsing() {
        let _dir = scratch_runtime_dir("runtime-record-matrix");
        let mut exercised = BTreeSet::new();
        exercise(
            &mut exercised,
            Trust::fixture(
                5,
                true,
                Clients::Paired(vec![ClientEntry {
                    name: "codex".into(),
                    anchor: Anchor::Hash(HashDigest::try_from("ab".repeat(20)).unwrap()),
                    added_unix: 7,
                }]),
            )
            .with_markers(5, 3, 4, 1),
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
            "outside crate::migrations no module reads a second spelling or fills an absent field, and no record module shadows the shared loader: {refused:#?}"
        );
    }

    /// The floor, not the rung count, fixes which rung a stored version climbs. The control: the same
    /// hand-authored ladder with its first rung retired reads the same v2 file right when the floor was
    /// raised with it and wrong when it was not.
    #[test]
    fn a_stored_version_climbs_from_the_floor_and_is_refused_off_the_ladder() {
        fn parse_retries(mut body: Value) -> io::Result<Value> {
            let retries = body["retries"].as_str().unwrap().parse::<u64>().unwrap();
            body["retries"] = Value::from(retries);
            Ok(body)
        }
        fn add_backoff(mut body: Value) -> io::Result<Value> {
            body["backoff_ms"] = Value::from(500);
            Ok(body)
        }
        const FULL: Ladder = Ladder {
            first_version: 1,
            rungs: &[parse_retries, add_backoff],
        };
        const RETIRED_AND_RAISED: Ladder = Ladder {
            first_version: 2,
            rungs: &[add_backoff],
        };
        const RETIRED_FLOOR_KEPT: Ladder = Ladder {
            first_version: 1,
            rungs: &[add_backoff],
        };
        let v1 = || json!({"retries": "3"});
        let v2 = || json!({"retries": 3});
        let current = || json!({"retries": 3, "backoff_ms": 500});
        type Case = (
            &'static str,
            &'static Ladder,
            usize,
            Value,
            Result<Value, &'static str>,
        );
        let cases: [Case; 9] = [
            ("v1 climbs both rungs", &FULL, 1, v1(), Ok(current())),
            ("v2 climbs the last rung", &FULL, 2, v2(), Ok(current())),
            ("v3 stands on the top", &FULL, 3, current(), Ok(current())),
            (
                "v0 is below the floor",
                &FULL,
                0,
                v1(),
                Err("below this binary's floor 1"),
            ),
            (
                "v4 is above the ladder",
                &FULL,
                4,
                current(),
                Err("above this binary's 3"),
            ),
            (
                "retired and raised: v2 still climbs",
                &RETIRED_AND_RAISED,
                2,
                v2(),
                Ok(current()),
            ),
            (
                "retired and raised: v1 is too old",
                &RETIRED_AND_RAISED,
                1,
                v1(),
                Err("below this binary's floor 2"),
            ),
            (
                "floor kept: the same v2 file reads as the top, backoff never added",
                &RETIRED_FLOOR_KEPT,
                2,
                v2(),
                Ok(v2()),
            ),
            (
                "floor kept: v1 gets the wrong rung, retries stays a string",
                &RETIRED_FLOOR_KEPT,
                1,
                v1(),
                Ok(json!({"retries": "3", "backoff_ms": 500})),
            ),
        ];
        for (case, ladder, stored, body, expected) in cases {
            let climbed = ladder.climb(stored, body).map_err(|e| e.to_string());
            match expected {
                Ok(value) => assert_eq!(climbed, Ok(value), "{case}"),
                Err(refusal) => {
                    let err = climbed.expect_err(case);
                    assert!(err.contains(refusal), "{case}: {err}");
                }
            }
        }
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
        let cases: [(&str, &str, ModuleScan); 20] = [
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
                "bare default beside deserialize_with on an Option is the pair serde needs, not compat",
                "#[derive(Deserialize)]\nstruct R {\n    #[serde(default, deserialize_with = \"de\")]\n    a: Option<u64>,\n}",
                scan(&[], &[], &[]),
            ),
            (
                "a deserialize_with in another attribute may be cfg-gated off, so it makes no pair",
                "#[derive(Deserialize)]\nstruct R {\n    #[serde(default)]\n    #[cfg_attr(any(), serde(deserialize_with = \"de\"))]\n    a: Option<u64>,\n}",
                scan(&[], &["3: #[serde(default)]"], &[]),
            ),
            (
                "a deserialize_with in a sibling list of one cfg_attr is gated apart, so it makes no pair",
                "#[derive(Deserialize)]\nstruct R {\n    #[cfg_attr(all(), serde(default), cfg_attr(any(), serde(deserialize_with = \"de\")))]\n    a: Option<u64>,\n}",
                scan(&[], &["3: #[serde(default)]"], &[]),
            ),
            (
                "bare default beside deserialize_with on a non-Option fills the absent field",
                "#[derive(Deserialize)]\nstruct R {\n    #[serde(default, deserialize_with = \"de\")]\n    a: u64,\n}",
                scan(&[], &["3: #[serde(default)]"], &[]),
            ),
            (
                "a provider fn beside deserialize_with is a value for the absent field",
                "#[derive(Deserialize)]\nstruct R {\n    #[serde(default = \"f\", deserialize_with = \"de\")]\n    a: Option<u64>,\n}",
                scan(&[], &["3: #[serde(default)]"], &[]),
            ),
            (
                "bare default on an Option without deserialize_with is what serde does alone: a compat hint",
                "#[derive(Deserialize)]\nstruct R {\n    #[serde(default)]\n    a: Option<u64>,\n}",
                scan(&[], &["3: #[serde(default)]"], &[]),
            ),
            (
                "items inside a fn body and a const block are reached",
                "fn f() {\n    #[derive(Deserialize)]\n    struct R {\n        #[serde(default)]\n        a: u64,\n    }\n}\nconst _: () = {\n    impl Record for A {}\n};",
                scan(&["A"], &["4: #[serde(default)]"], &[]),
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
