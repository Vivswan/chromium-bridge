//! The Windows registry reads and writes (compiles cross-OS; the real ones are cfg(windows)). The non-Windows
//! stubs fail closed: a registry registration or pointer cannot be performed or observed from a Unix build.

use std::path::Path;

use crate::browsers::Hive;

/// Whether registry `v` names our manifest. Windows paths are case-insensitive and accept either
/// separator; we wrote the value ourselves, but normalize before comparing so a round-tripped
/// registration is never misreported as re-pointed.
pub(super) fn same_windows_path(v: &str, manifest_path: &Path) -> bool {
    let normalize = |p: &str| p.replace('/', "\\").to_ascii_lowercase();
    normalize(v) == normalize(&manifest_path.to_string_lossy())
}

#[cfg(windows)]
pub(super) fn registry_supported(_hive: Hive, _key: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn registry_supported(hive: Hive, key: &str) -> Result<(), String> {
    Err(format!(
        "registry registration ({hive}\\{key}) requires a Windows build of genkan"
    ))
}

#[cfg(windows)]
fn hive_root(hive: Hive) -> winreg::RegKey {
    winreg::RegKey::predef(match hive {
        Hive::CurrentUser => winreg::enums::HKEY_CURRENT_USER,
        Hive::LocalMachine => winreg::enums::HKEY_LOCAL_MACHINE,
    })
}

/// One registry key, read whole so ownership is judged on all of it.
pub(super) struct RegistryKey {
    /// Every value as (name, text), `""` naming the default value.
    pub(super) values: Vec<(String, String)>,
    /// How many child keys hang under it.
    pub(super) children: u32,
}

/// `<hive>\{key}` whole, or `None` when the key is absent. This engine writes
/// REG_SZ alone, so a value of any other type was never ours: it reads as its
/// type name in place of a text, which the ownership judgment calls foreign (a
/// shape an explicit `--fix` replaces whole), never as an error.
#[cfg(windows)]
pub(super) fn registry_key(hive: Hive, key: &str) -> Result<Option<RegistryKey>, String> {
    use winreg::types::FromRegValue;
    let subkey = match hive_root(hive).open_subkey(key) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut values = Vec::new();
    for entry in subkey.enum_values() {
        let (name, value) = entry.map_err(|e| format!("could not list its values: {e}"))?;
        let text = if value.vtype == winreg::enums::RegType::REG_SZ {
            String::from_reg_value(&value)
                .map_err(|e| format!("value {name:?} is not readable text: {e}"))?
        } else {
            format!("<{:?}>", value.vtype)
        };
        values.push((name, text));
    }
    let children = subkey
        .query_info()
        .map_err(|e| format!("could not count its child keys: {e}"))?
        .sub_keys;
    Ok(Some(RegistryKey { values, children }))
}

#[cfg(not(windows))]
pub(super) fn registry_key(_hive: Hive, _key: &str) -> Result<Option<RegistryKey>, String> {
    Err("registry access requires a Windows build of genkan".into())
}

/// The key's default value as the browser reads it: opened with the one right Chromium asks for
/// (KEY_QUERY_VALUE, so an ACL that denies enumeration does not hide a value the browser can read), and
/// `None` when the key or the value is absent or the value is of a type Chromium's string read refuses
/// (anything but REG_SZ and REG_EXPAND_SZ, REG_MULTI_SZ included, which winreg's String read would accept).
#[cfg(windows)]
pub(super) fn registry_default_value(hive: Hive, key: &str) -> Result<Option<String>, String> {
    use winreg::enums::{RegType, KEY_QUERY_VALUE};
    use winreg::types::FromRegValue;
    let subkey = match hive_root(hive).open_subkey_with_flags(key, KEY_QUERY_VALUE) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let raw = match subkey.get_raw_value("") {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if raw.vtype != RegType::REG_SZ && raw.vtype != RegType::REG_EXPAND_SZ {
        return Ok(None);
    }
    String::from_reg_value(&raw)
        .map(Some)
        .map_err(|e| e.to_string())
}

#[cfg(not(windows))]
pub(super) fn registry_default_value(_hive: Hive, _key: &str) -> Result<Option<String>, String> {
    Err("registry access requires a Windows build of genkan".into())
}

#[cfg(windows)]
pub(super) fn set_registry_value(
    hive: Hive,
    key: &str,
    name: &str,
    value: &str,
) -> Result<(), String> {
    let (subkey, _) = hive_root(hive)
        .create_subkey(key)
        .map_err(|e| format!("could not create {hive}\\{key}: {e}"))?;
    subkey
        .set_value(name, &value)
        .map_err(|e| format!("could not set {hive}\\{key}: {e}"))
}

#[cfg(not(windows))]
pub(super) fn set_registry_value(
    hive: Hive,
    key: &str,
    _name: &str,
    _value: &str,
) -> Result<(), String> {
    Err(format!(
        "registry registration ({hive}\\{key}) requires a Windows build of genkan"
    ))
}

/// Delete `<hive>\{key}` once its slot was judged ours. delete_subkey (not _all):
/// our keys have no children, and failing on an unexpected child is the
/// fail-closed behavior we want.
#[cfg(windows)]
pub(super) fn delete_registry_key(hive: Hive, key: &str) -> Result<(), String> {
    match hive_root(hive).delete_subkey(key) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not delete {hive}\\{key}: {e}")),
    }
}

#[cfg(not(windows))]
pub(super) fn delete_registry_key(hive: Hive, key: &str) -> Result<(), String> {
    Err(format!(
        "registry removal ({hive}\\{key}) requires a Windows build of genkan"
    ))
}
