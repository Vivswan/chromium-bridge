//! Browser-path resolver: which Chromium-family browsers exist on this
//! machine, and where each one looks for our native-messaging registration,
//! in both scopes the browser reads.
//!
//! This is the ONE source of per-browser path knowledge, shared by `doctor`
//! (diagnosis and `--fix` repair) and `uninstall` (both in
//! `crate::registration`). Everything here is a pure derivation from
//! an [`Os`] and a set of [`BaseDirs`]: no I/O happens in this module, so
//! every layout (macOS, Linux, Windows) is unit-testable from any host and
//! tests never touch a real user directory or system root. Callers do the
//! existence checks against the paths this module hands back.

use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

use crate::identity::{NATIVE_HOST_ID, PINNED_EXTENSION_ID};

/// The Chromium-family browsers we know how to register with by name. Any
/// other Chromium build is reachable through `doctor --fix`'s explicit
/// `--manifest-dir` escape hatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Browser {
    Chrome,
    Chromium,
    Brave,
    Edge,
    Vivaldi,
    Opera,
}

impl Browser {
    /// Every known browser, in the order reports should list them.
    pub const ALL: [Browser; 6] = [
        Browser::Chrome,
        Browser::Chromium,
        Browser::Brave,
        Browser::Edge,
        Browser::Vivaldi,
        Browser::Opera,
    ];

    /// The stable CLI key (`--browser chrome,brave`, wrapper suffix, label).
    pub fn key(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Chromium => "chromium",
            Browser::Brave => "brave",
            Browser::Edge => "edge",
            Browser::Vivaldi => "vivaldi",
            Browser::Opera => "opera",
        }
    }

    /// Parse a CLI key back into a browser. `None` for anything unknown, so
    /// the caller can fail loud instead of guessing.
    pub fn from_key(key: &str) -> Option<Browser> {
        Browser::ALL.iter().copied().find(|b| b.key() == key)
    }
}

/// Which OS layout to derive paths for. Parameterized (rather than `cfg`-only
/// code) so every layout compiles and is testable everywhere; [`Os::current`]
/// picks the real one at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    MacOs,
    Linux,
    Windows,
}

impl Os {
    /// The layout for the platform this binary was compiled for.
    pub fn current() -> Os {
        #[cfg(target_os = "macos")]
        {
            Os::MacOs
        }
        #[cfg(windows)]
        {
            Os::Windows
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            Os::Linux
        }
    }
}

/// Whom a registration serves: one account, or every account on the machine. Chromium's manifest lookup
/// checks the per-user location for an entry first and falls through to the machine-wide one only when
/// nothing sits there, so a per-user file of any content shadows the system one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// The account's own config root (`~/.config/<vendor>`, `~/Library/Application Support/<vendor>`, HKCU).
    User,
    /// The root-owned system directories (`/etc/opt/chrome`, `/Library/Google/Chrome`, HKLM).
    System,
}

impl Scope {
    /// The word reports print.
    pub fn key(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::System => "system",
        }
    }
}

/// One value per scope, resolved together so a row never carries one scope without the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Scoped<T> {
    pub user: T,
    pub system: T,
}

impl<T> Scoped<T> {
    pub fn get(&self, scope: Scope) -> &T {
        match scope {
            Scope::User => &self.user,
            Scope::System => &self.system,
        }
    }
}

/// The registry root a Windows registration hangs from: the scope's spelling there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    CurrentUser,
    LocalMachine,
}

impl Hive {
    pub fn for_scope(scope: Scope) -> Hive {
        match scope {
            Scope::User => Hive::CurrentUser,
            Scope::System => Hive::LocalMachine,
        }
    }
}

impl fmt::Display for Hive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Hive::CurrentUser => "HKCU",
            Hive::LocalMachine => "HKLM",
        })
    }
}

/// The base directories every browser path is derived from. Injected (never
/// read from the environment inside the resolver) so tests point them at
/// fixture directories.
#[derive(Debug, Clone)]
pub struct BaseDirs {
    /// `$HOME` / `%USERPROFILE%`.
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME` when set (Linux; defaults to `home/.config`).
    pub xdg_config_home: Option<PathBuf>,
    /// `$XDG_DATA_HOME` when set (Linux; defaults to `home/.local/share`).
    pub xdg_data_home: Option<PathBuf>,
    /// `%LOCALAPPDATA%` (Windows).
    pub local_app_data: Option<PathBuf>,
    /// `%APPDATA%` (Windows roaming; Opera keeps its profile there).
    pub roaming_app_data: Option<PathBuf>,
    /// `%ProgramFiles%` (Windows): where the machine-wide manifest store lives. Program Files rather than
    /// ProgramData because a standard account can pre-create a directory under the latter and keep
    /// control of it, which would put the manifest an HKLM key points at in that account's hands.
    pub program_files: Option<PathBuf>,
    /// The root every machine-wide path hangs from: `/` on Unix (`/etc`, `/Library`, `/opt`, `/var/lib`,
    /// `/Applications`), the system drive on Windows. Injected like every other root so tests resolve
    /// and scan a fixture tree, never the machine's own.
    pub system_root: PathBuf,
}

impl BaseDirs {
    /// Read the base directories from the process environment. A per-user
    /// command fails (rather than inventing a root like `/`) when the
    /// platform's home variable is missing or not absolute: writing
    /// registrations relative to a guessed or CWD-relative home would be
    /// worse than refusing. A machine-wide command needs no account (a
    /// package manager's maintainer script may run with no HOME at all), so
    /// there a missing home resolves to the superuser's, which is read for
    /// presence alone and never written. Relative XDG overrides are ignored,
    /// as the basedir spec requires.
    pub fn from_env(scope: Scope) -> Result<BaseDirs, String> {
        let os = Os::current();
        let system_root = match os {
            Os::MacOs | Os::Linux => PathBuf::from("/"),
            Os::Windows => std::env::var_os("SystemDrive")
                .map(|drive| PathBuf::from(format!("{}\\", drive.to_string_lossy())))
                .unwrap_or_else(|| PathBuf::from(r"C:\")),
        };
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .filter(|p| p.is_absolute());
        let home = match (home, scope) {
            (Some(home), Scope::User | Scope::System) => home,
            (None, Scope::System) => system_root.join(match os {
                Os::MacOs => "var/root",
                Os::Linux => "root",
                Os::Windows => "Windows/System32/config/systemprofile",
            }),
            (None, Scope::User) => {
                return Err("HOME (or USERPROFILE) is not set to an absolute path; cannot resolve per-user browser paths".into());
            }
        };
        let absolute = |v: std::ffi::OsString| {
            let p = PathBuf::from(v);
            if p.is_absolute() {
                Some(p)
            } else {
                None
            }
        };
        Ok(BaseDirs {
            home,
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").and_then(absolute),
            xdg_data_home: std::env::var_os("XDG_DATA_HOME").and_then(absolute),
            local_app_data: std::env::var_os("LOCALAPPDATA").and_then(absolute),
            roaming_app_data: std::env::var_os("APPDATA").and_then(absolute),
            program_files: std::env::var_os("ProgramFiles").and_then(absolute),
            system_root,
        })
    }

    fn config_home(&self) -> PathBuf {
        self.xdg_config_home
            .clone()
            .unwrap_or_else(|| self.home.join(".config"))
    }

    fn data_home(&self) -> PathBuf {
        self.xdg_data_home
            .clone()
            .unwrap_or_else(|| self.home.join(".local/share"))
    }

    fn local_app_data(&self) -> PathBuf {
        self.local_app_data
            .clone()
            .unwrap_or_else(|| self.home.join("AppData/Local"))
    }

    fn program_files(&self) -> PathBuf {
        self.program_files
            .clone()
            .unwrap_or_else(|| self.system_root.join("Program Files"))
    }
}

/// How a browser picks up the native-messaging manifest on this OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// macOS / Linux: the browser scans this `NativeMessagingHosts` directory
    /// for `<NATIVE_HOST_ID>.json`.
    ManifestDir(PathBuf),
    /// Windows: the browser reads this registry key (path relative to the
    /// hive); its default value must point at the manifest file, which we
    /// keep at `manifest_path`.
    Registry {
        hive: Hive,
        key: String,
        manifest_path: PathBuf,
    },
}

impl Registration {
    /// The manifest file this registration writes/reads.
    pub fn manifest_path(&self) -> PathBuf {
        match self {
            Registration::ManifestDir(dir) => dir.join(format!("{NATIVE_HOST_ID}.json")),
            Registration::Registry { manifest_path, .. } => manifest_path.clone(),
        }
    }

    /// Human-oriented description of where the registration lives, for
    /// reports (`doctor`, `install --list`).
    pub fn location(&self) -> String {
        match self {
            Registration::ManifestDir(_) => self.manifest_path().display().to_string(),
            Registration::Registry { hive, key, .. } => format!("{hive}\\{key}"),
        }
    }
}

/// Where a browser's manifest lookup lands in one scope: a directory of its own, or another browser's.
/// Brave's main delegate (brave-core `app/brave_main_delegate.cc`, `PreSandboxStartup`) points its
/// machine-wide directory at Chrome's on macOS and Linux, and its per-user one too on macOS alone (on
/// Linux that override resolves to Brave's own config root); Opera's extension documentation names
/// Chrome's locations alone. One directory holds one manifest: `doctor --fix --browser brave` on macOS
/// registers Chrome's row and `doctor` reports it under both; the label rule for a shared manifest is
/// `registration::Target`'s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Own {
        registration: Registration,
        /// The other browsers that read this directory; any means the wrapper gets no `--label`.
        readers: Vec<Browser>,
    },
    /// `registration` is `owner`'s own one in the same scope, resolved here so a target needs no second
    /// lookup.
    ReadsFrom {
        owner: Browser,
        registration: Registration,
    },
}

impl Lookup {
    /// The registration the browser reads, whosever it is.
    pub fn registration(&self) -> &Registration {
        match self {
            Lookup::Own { registration, .. } | Lookup::ReadsFrom { registration, .. } => {
                registration
            }
        }
    }

    /// The browser whose directory it is, when not this browser's own.
    pub fn owner(&self) -> Option<Browser> {
        match self {
            Lookup::Own { .. } => None,
            Lookup::ReadsFrom { owner, .. } => Some(*owner),
        }
    }
}

/// Where a browser reads the external-extension pointer that makes it offer
/// "Enable Chromium Bridge?" on its next start (the Web Store copy under
/// [`PINNED_EXTENSION_ID`]). Linux has none in either scope: Chrome there
/// installs an external extension without asking, which the threat model
/// refuses, so Linux users add the extension from the Web Store themselves.
/// Derived like the manifest location: Chrome's own paths from its
/// documentation, the other vendors from the same user-data root and
/// registry root they keep their manifests under; the machine-wide macOS
/// directory is one for all ([`MACOS_SYSTEM_POINTER_DIR`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionPointer {
    /// macOS: `<user data dir>/External Extensions/<PINNED_EXTENSION_ID>.json` per user, the one
    /// machine-wide directory otherwise.
    File(PathBuf),
    /// Windows: `<hive>\<vendor>\Extensions\<PINNED_EXTENSION_ID>` (path relative
    /// to the hive), string value `update_url`.
    Registry { hive: Hive, key: String },
}

impl ExtensionPointer {
    /// Human-oriented description of where the pointer lives, for reports.
    pub fn location(&self) -> String {
        match self {
            ExtensionPointer::File(path) => path.display().to_string(),
            ExtensionPointer::Registry { hive, key } => format!("{hive}\\{key}"),
        }
    }
}

/// One known browser on one OS: how to detect it and how to register with it in each scope.
#[derive(Debug, Clone)]
pub struct BrowserEntry {
    pub browser: Browser,
    /// Paths whose existence says the browser is installed, any one sufficing, per scope: the account's
    /// own signals decide a per-user repair, the machine-wide ones a `--system` repair, so an isolated
    /// account (the Linux registration smoke's XDG roots) sees nothing on a runner that ships Chrome under
    /// `/opt`. Purely paths; the caller checks existence.
    ///
    /// ```text
    /// macOS, user     -> the bundle under `/Applications` or `~/Applications`; the per-user config root is
    ///                    NOT a signal (an uninstalled browser leaves it behind forever, dev tooling creates
    ///                    a bare `Chromium` folder), so a fresh install counts before its first run and a
    ///                    leftover root never lights the row
    /// macOS, system   -> the bundle under `/Applications` alone
    /// Linux, user     -> the per-user config root (the browser ran as this account)
    /// Linux, system   -> the vendor package's install dir (installed for every account, as the .deb's
    ///                    post-install sees it from root)
    /// Windows         -> the per-user profile root in both; elevation keeps the account
    /// macOS app elsewhere -> reads "not detected" (residual); the user can register it explicitly
    /// ```
    pub presence: Scoped<Vec<PathBuf>>,
    /// Where the browser's lookup lands per scope.
    pub manifest: Scoped<Lookup>,
    /// The external-extension pointer per scope, or `None` on Linux, where none is written (see
    /// [`ExtensionPointer`]).
    pub pointer: Option<Scoped<ExtensionPointer>>,
}

impl BrowserEntry {
    /// Whether the browser looks present on this machine: the only I/O in this module, kept on the entry so
    /// `resolve` stays pure for tests. A display/guidance heuristic, not a security gate: default
    /// `doctor --fix` uses it to pick which browsers to register (fewer detected means fewer manifests
    /// written, never more), and the explicit register paths still reach an undetected browser.
    pub fn detected(&self, scope: Scope) -> bool {
        self.presence.get(scope).iter().any(|p| p.is_dir())
    }

    /// Present for either scope: what `doctor`'s row calls detected.
    pub fn installed(&self) -> bool {
        self.detected(Scope::User) || self.detected(Scope::System)
    }
}

/// The per-user config root each browser keeps on macOS, under
/// `~/Library/Application Support`.
fn macos_vendor_dir(browser: Browser) -> &'static str {
    match browser {
        Browser::Chrome => "Google/Chrome",
        Browser::Chromium => "Chromium",
        Browser::Brave => "BraveSoftware/Brave-Browser",
        Browser::Edge => "Microsoft Edge",
        Browser::Vivaldi => "Vivaldi",
        Browser::Opera => "com.operasoftware.Opera",
    }
}

/// Chrome's machine-wide `NativeMessagingHosts` directory on macOS (root-relative), from Chrome's
/// native-messaging documentation. Outside `Application Support`, unlike its pointer dir.
const MACOS_CHROME_SYSTEM_DIR: &str = "Library/Google/Chrome/NativeMessagingHosts";

/// The machine-wide `External Extensions` directory on macOS (root-relative): Chromium's path provider
/// spells it with Chrome's name for every branding, so Chromium and Brave read it too, and nothing says a
/// fork re-points it (residual: unverified on Edge, Vivaldi, Opera).
pub const MACOS_SYSTEM_POINTER_DIR: &str =
    "Library/Application Support/Google/Chrome/External Extensions";

/// Chrome's machine-wide `native-messaging-hosts` directory on Linux (root-relative), from the same
/// documentation.
const LINUX_CHROME_SYSTEM_DIR: &str = "etc/opt/chrome/native-messaging-hosts";

/// The machine-wide `NativeMessagingHosts` directory each browser reads on macOS, root-relative, or `None`
/// for a browser that reads Chrome's ([`Lookup::ReadsFrom`]). Chromium's from Chrome's
/// documentation, Edge's from Microsoft's, Vivaldi's from the paths native hosts ship for it, since
/// Vivaldi documents none.
fn macos_system_manifest_dir(browser: Browser) -> Option<&'static str> {
    match browser {
        Browser::Chrome => Some(MACOS_CHROME_SYSTEM_DIR),
        Browser::Chromium => Some("Library/Application Support/Chromium/NativeMessagingHosts"),
        Browser::Edge => Some("Library/Microsoft/Edge/NativeMessagingHosts"),
        Browser::Vivaldi => Some("Library/Application Support/Vivaldi/NativeMessagingHosts"),
        Browser::Brave | Browser::Opera => None,
    }
}

/// The pointer file in an `External Extensions` directory.
fn pointer_file(dir: PathBuf) -> ExtensionPointer {
    ExtensionPointer::File(dir.join(format!("{PINNED_EXTENSION_ID}.json")))
}

/// Each browser's application bundle name on macOS, looked for under `/Applications` and `~/Applications` (the two
/// standard install roots, including Homebrew casks). Two path checks are the dependency-free mechanism; the
/// non-standard-location gap is the named residual on [`BrowserEntry::presence`].
fn macos_app_bundle(browser: Browser) -> &'static str {
    match browser {
        Browser::Chrome => "Google Chrome.app",
        Browser::Chromium => "Chromium.app",
        Browser::Brave => "Brave Browser.app",
        Browser::Edge => "Microsoft Edge.app",
        Browser::Vivaldi => "Vivaldi.app",
        Browser::Opera => "Opera.app",
    }
}

/// The per-user config root each browser keeps on Linux, under
/// `$XDG_CONFIG_HOME` (default `~/.config`).
fn linux_vendor_dir(browser: Browser) -> &'static str {
    match browser {
        Browser::Chrome => "google-chrome",
        Browser::Chromium => "chromium",
        Browser::Brave => "BraveSoftware/Brave-Browser",
        Browser::Edge => "microsoft-edge",
        Browser::Vivaldi => "vivaldi",
        Browser::Opera => "opera",
    }
}

/// The machine-wide `native-messaging-hosts` directory each browser reads on Linux, root-relative, or
/// `None` for a browser that reads Chrome's ([`Lookup::ReadsFrom`]). Chromium's from Chrome's
/// documentation, Edge's from Microsoft's, Vivaldi's from the paths native hosts ship for it.
fn linux_system_manifest_dir(browser: Browser) -> Option<&'static str> {
    match browser {
        Browser::Chrome => Some(LINUX_CHROME_SYSTEM_DIR),
        Browser::Chromium => Some("etc/chromium/native-messaging-hosts"),
        Browser::Edge => Some("etc/opt/edge/native-messaging-hosts"),
        Browser::Vivaldi => Some("etc/vivaldi/native-messaging-hosts"),
        Browser::Brave | Browser::Opera => None,
    }
}

/// Where each vendor's Linux package installs the browser, root-relative: the machine-wide presence signal.
/// The Debian and Fedora layouts both, where they differ.
fn linux_install_dirs(browser: Browser) -> &'static [&'static str] {
    match browser {
        Browser::Chrome => &["opt/google/chrome"],
        Browser::Chromium => &["usr/lib/chromium", "usr/lib/chromium-browser"],
        Browser::Brave => &["opt/brave.com/brave"],
        Browser::Edge => &["opt/microsoft/msedge"],
        Browser::Vivaldi => &["opt/vivaldi"],
        Browser::Opera => &["usr/lib/x86_64-linux-gnu/opera", "usr/lib64/opera"],
    }
}

/// The registry root each browser owns on Windows, under either hive (matches what the
/// retired `install.ps1` registered under). NOTE: derived from documentation
/// and that PowerShell installer; the full Windows flow still needs
/// verification on a real Windows machine (see docs/cli.md).
fn windows_vendor_key(browser: Browser) -> &'static str {
    match browser {
        Browser::Chrome => r"Software\Google\Chrome",
        Browser::Chromium => r"Software\Chromium",
        Browser::Brave => r"Software\BraveSoftware\Brave-Browser",
        Browser::Edge => r"Software\Microsoft\Edge",
        Browser::Vivaldi => r"Software\Vivaldi",
        Browser::Opera => r"Software\Opera Software",
    }
}

/// The per-user profile root each browser keeps on Windows, used only for
/// detection. Most live under `%LOCALAPPDATA%`; Opera roams under `%APPDATA%`.
/// NOTE: derived from vendor documentation, not yet verified on a real
/// Windows machine; Opera's vendor dir is broad (other Opera-family products
/// like Opera GX share `Opera Software`), so detection there can over-match.
fn windows_profile_dir(dirs: &BaseDirs, browser: Browser) -> PathBuf {
    let local = |sub: &str| dirs.local_app_data().join(sub);
    match browser {
        Browser::Chrome => local("Google/Chrome/User Data"),
        Browser::Chromium => local("Chromium/User Data"),
        Browser::Brave => local("BraveSoftware/Brave-Browser/User Data"),
        Browser::Edge => local("Microsoft/Edge/User Data"),
        Browser::Vivaldi => local("Vivaldi/User Data"),
        Browser::Opera => dirs
            .roaming_app_data
            .clone()
            .unwrap_or_else(|| dirs.home.join("AppData/Roaming"))
            .join("Opera Software"),
    }
}

/// Where the installer keeps files it owns (wrapper scripts on Unix, the
/// manifest file on Windows -- Windows manifests live outside the browser's
/// namespace, referenced by the registry value). Per user, the directory the
/// retired shell installers used, so re-registering over a legacy install
/// converges on the same paths; machine-wide, the platform's home for
/// state a package generates after install, which every account's browser
/// must be able to traverse.
pub fn install_dir(os: Os, dirs: &BaseDirs, scope: Scope) -> PathBuf {
    match (os, scope) {
        (Os::MacOs, Scope::User) => dirs.home.join(".chromium-bridge"),
        (Os::MacOs, Scope::System) => dirs
            .system_root
            .join("Library/Application Support/chromium-bridge"),
        (Os::Linux, Scope::User) => dirs.data_home().join("chromium-bridge"),
        (Os::Linux, Scope::System) => dirs.system_root.join("var/lib/chromium-bridge"),
        (Os::Windows, Scope::User) => dirs.local_app_data().join("chromium-bridge"),
        (Os::Windows, Scope::System) => dirs.program_files().join("chromium-bridge"),
    }
}

/// A browser's registry registration and pointer on Windows, in one hive.
fn windows_slot(
    os: Os,
    dirs: &BaseDirs,
    scope: Scope,
    browser: Browser,
) -> (Registration, ExtensionPointer) {
    let hive = Hive::for_scope(scope);
    (
        Registration::Registry {
            hive,
            key: format!(
                r"{}\NativeMessagingHosts\{NATIVE_HOST_ID}",
                windows_vendor_key(browser)
            ),
            manifest_path: install_dir(os, dirs, scope).join(format!("{NATIVE_HOST_ID}.json")),
        },
        ExtensionPointer::Registry {
            hive,
            key: format!(
                r"{}\Extensions\{PINNED_EXTENSION_ID}",
                windows_vendor_key(browser)
            ),
        },
    )
}

/// The per-user config root each browser keeps on macOS; [`Lookup`] says whose `NativeMessagingHosts`
/// under it a browser reads.
fn macos_user_root(dirs: &BaseDirs, browser: Browser) -> PathBuf {
    dirs.home
        .join("Library/Application Support")
        .join(macos_vendor_dir(browser))
}

fn linux_user_root(dirs: &BaseDirs, browser: Browser) -> PathBuf {
    dirs.config_home().join(linux_vendor_dir(browser))
}

/// The per-user registration under a config root: the `NativeMessagingHosts` directory Chromium scans there.
fn user_registration(root: PathBuf) -> Registration {
    Registration::ManifestDir(root.join("NativeMessagingHosts"))
}

/// Chrome's own registration in one scope, total: the per-browser tables say who falls through to it with
/// a `None`, so the fallthrough itself cannot be one of their entries.
fn chrome_registration(os: Os, dirs: &BaseDirs, scope: Scope) -> Registration {
    match (os, scope) {
        (Os::MacOs, Scope::User) => user_registration(macos_user_root(dirs, Browser::Chrome)),
        (Os::MacOs, Scope::System) => {
            Registration::ManifestDir(dirs.system_root.join(MACOS_CHROME_SYSTEM_DIR))
        }
        (Os::Linux, Scope::User) => user_registration(linux_user_root(dirs, Browser::Chrome)),
        (Os::Linux, Scope::System) => {
            Registration::ManifestDir(dirs.system_root.join(LINUX_CHROME_SYSTEM_DIR))
        }
        (Os::Windows, _) => windows_slot(os, dirs, scope, Browser::Chrome).0,
    }
}

/// A browser's own registration in one scope, or `None` where it reads Chrome's ([`Lookup`] says who).
/// Brave's delegate overrides no Windows path, so its keys are its own there.
fn own_registration(
    os: Os,
    dirs: &BaseDirs,
    scope: Scope,
    browser: Browser,
) -> Option<Registration> {
    match (os, scope) {
        (Os::MacOs, Scope::User) => match browser {
            Browser::Brave => None,
            Browser::Chrome
            | Browser::Chromium
            | Browser::Edge
            | Browser::Vivaldi
            | Browser::Opera => Some(user_registration(macos_user_root(dirs, browser))),
        },
        (Os::MacOs, Scope::System) => macos_system_manifest_dir(browser)
            .map(|dir| Registration::ManifestDir(dirs.system_root.join(dir))),
        (Os::Linux, Scope::User) => Some(user_registration(linux_user_root(dirs, browser))),
        (Os::Linux, Scope::System) => linux_system_manifest_dir(browser)
            .map(|dir| Registration::ManifestDir(dirs.system_root.join(dir))),
        (Os::Windows, Scope::User) => Some(windows_slot(os, dirs, scope, browser).0),
        (Os::Windows, Scope::System) => match browser {
            Browser::Opera => None,
            Browser::Chrome
            | Browser::Chromium
            | Browser::Brave
            | Browser::Edge
            | Browser::Vivaldi => Some(windows_slot(os, dirs, scope, browser).0),
        },
    }
}

fn chrome_readers(os: Os, dirs: &BaseDirs, scope: Scope) -> Vec<Browser> {
    Browser::ALL
        .into_iter()
        .filter(|&b| b != Browser::Chrome && own_registration(os, dirs, scope, b).is_none())
        .collect()
}

fn lookup(os: Os, dirs: &BaseDirs, scope: Scope, browser: Browser) -> Lookup {
    match own_registration(os, dirs, scope, browser) {
        Some(registration) => Lookup::Own {
            registration,
            readers: match browser {
                Browser::Chrome => chrome_readers(os, dirs, scope),
                Browser::Chromium
                | Browser::Brave
                | Browser::Edge
                | Browser::Vivaldi
                | Browser::Opera => Vec::new(),
            },
        },
        None => Lookup::ReadsFrom {
            owner: Browser::Chrome,
            registration: chrome_registration(os, dirs, scope),
        },
    }
}

/// The pointer per scope. The per-user one is the browser's own on every OS: Chromium derives it from the
/// user-data directory, which no delegate re-points (Brave's moves the manifest directory alone), so a
/// browser reading Chrome's manifest still prompts from its own pointer. Machine-wide, macOS has the one
/// directory for all and Windows the owner's key.
fn pointers(
    os: Os,
    dirs: &BaseDirs,
    browser: Browser,
    manifest: &Scoped<Lookup>,
) -> Option<Scoped<ExtensionPointer>> {
    match os {
        Os::MacOs => Some(Scoped {
            user: pointer_file(macos_user_root(dirs, browser).join("External Extensions")),
            system: pointer_file(dirs.system_root.join(MACOS_SYSTEM_POINTER_DIR)),
        }),
        Os::Linux => None,
        Os::Windows => Some(Scoped {
            user: windows_slot(os, dirs, Scope::User, browser).1,
            system: windows_slot(
                os,
                dirs,
                Scope::System,
                manifest.system.owner().unwrap_or(browser),
            )
            .1,
        }),
    }
}

/// The paths whose existence says the browser is installed, per scope ([`BrowserEntry::presence`]).
fn presence(os: Os, dirs: &BaseDirs, browser: Browser) -> Scoped<Vec<PathBuf>> {
    match os {
        Os::MacOs => {
            let bundle = macos_app_bundle(browser);
            let machine_bundle = dirs.system_root.join("Applications").join(bundle);
            Scoped {
                user: vec![
                    machine_bundle.clone(),
                    dirs.home.join("Applications").join(bundle),
                ],
                system: vec![machine_bundle],
            }
        }
        Os::Linux => Scoped {
            user: vec![linux_user_root(dirs, browser)],
            system: linux_install_dirs(browser)
                .iter()
                .map(|dir| dirs.system_root.join(dir))
                .collect(),
        },
        Os::Windows => {
            let profile = windows_profile_dir(dirs, browser);
            Scoped {
                user: vec![profile.clone()],
                system: vec![profile],
            }
        }
    }
}

/// Resolve one browser's entry on one OS.
pub fn entry(os: Os, dirs: &BaseDirs, browser: Browser) -> BrowserEntry {
    let manifest = Scoped {
        user: lookup(os, dirs, Scope::User, browser),
        system: lookup(os, dirs, Scope::System, browser),
    };
    BrowserEntry {
        browser,
        presence: presence(os, dirs, browser),
        pointer: pointers(os, dirs, browser, &manifest),
        manifest,
    }
}

/// Resolve every known browser's entry on one OS, in [`Browser::ALL`] order.
pub fn resolve(os: Os, dirs: &BaseDirs) -> Vec<BrowserEntry> {
    Browser::ALL.iter().map(|&b| entry(os, dirs, b)).collect()
}

/// A registration target for an explicit `--manifest-dir PATH`: a Chromium
/// browser we do not know by name. Unix-style directory scanning only; on
/// Windows an unknown browser needs its registry key, and no CLI escape
/// hatch exists for that yet (a follow-up once the Windows flow is verified;
/// see docs/cli.md).
pub fn explicit_dir_registration(dir: &std::path::Path) -> Registration {
    Registration::ManifestDir(dir.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> BaseDirs {
        BaseDirs {
            home: PathBuf::from("/fix/home"),
            xdg_config_home: None,
            xdg_data_home: None,
            local_app_data: None,
            roaming_app_data: None,
            program_files: None,
            system_root: PathBuf::from("/fix/sys"),
        }
    }

    #[test]
    fn keys_round_trip_and_cover_all() {
        for b in Browser::ALL {
            assert_eq!(Browser::from_key(b.key()), Some(b));
        }
        assert_eq!(Browser::from_key("firefox"), None);
        assert_eq!(Browser::from_key(""), None);
    }

    /// Brave's delegate re-points its per-user manifest directory on macOS and nothing else: the row's
    /// user lookup is Chrome's directory while its pointer stays under Brave's own user data root.
    #[test]
    fn macos_layout_brave_reads_chromes_user_manifest_and_prompts_from_its_own_pointer() {
        let e = entry(Os::MacOs, &dirs(), Browser::Brave);
        assert_eq!(
            e.manifest.user,
            Lookup::ReadsFrom {
                owner: Browser::Chrome,
                registration: Registration::ManifestDir(PathBuf::from(
                    "/fix/home/Library/Application Support/Google/Chrome/NativeMessagingHosts"
                )),
            }
        );
        assert_eq!(
            entry(Os::MacOs, &dirs(), Browser::Chrome)
                .manifest
                .user
                .registration()
                .manifest_path(),
            PathBuf::from(
                "/fix/home/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json"
            )
        );
        // App-presence candidates: the two standard install roots per user, the machine's alone for
        // --system, and never the config root.
        assert_eq!(
            e.presence,
            Scoped {
                user: vec![
                    PathBuf::from("/fix/sys/Applications/Brave Browser.app"),
                    PathBuf::from("/fix/home/Applications/Brave Browser.app"),
                ],
                system: vec![PathBuf::from("/fix/sys/Applications/Brave Browser.app")],
            }
        );
        // The per-user pointer file sits under the browser's own user data root; the machine-wide one is
        // Chromium's single hardcoded directory, Chrome's name included.
        assert_eq!(
            e.pointer,
            Some(Scoped {
                user: ExtensionPointer::File(PathBuf::from(
                    "/fix/home/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json"
                )),
                system: ExtensionPointer::File(PathBuf::from(
                    "/fix/sys/Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json"
                )),
            })
        );
        assert_eq!(
            entry(Os::MacOs, &dirs(), Browser::Chromium)
                .pointer
                .map(|p| p.system),
            e.pointer.map(|p| p.system)
        );
        // Opera's macOS dir is the bundle-id one, not "Opera".
        let opera = entry(Os::MacOs, &dirs(), Browser::Opera);
        assert!(opera
            .manifest
            .user
            .registration()
            .manifest_path()
            .starts_with("/fix/home/Library/Application Support/com.operasoftware.Opera"));
        assert!(opera
            .presence
            .user
            .contains(&PathBuf::from("/fix/sys/Applications/Opera.app")));
    }

    /// The machine-wide directories, per browser's own source or documentation: Chrome's sits outside
    /// `Application Support` on macOS while its pointer dir sits inside; Brave and Opera have none of their
    /// own and read Chrome's, so their rows resolve to Chrome's registration and pointer under Chrome's
    /// name; Brave's Windows key is its own. Per user, Brave on macOS alone reads Chrome's.
    #[test]
    fn each_browser_resolves_its_documented_directory_or_chromes_per_scope() {
        let d = dirs();
        let host = "com.vivswan.chromium_bridge.host.json";
        let own = |os: Os, b: Browser| match entry(os, &d, b).manifest.system {
            Lookup::Own { registration, .. } => registration.manifest_path(),
            other @ Lookup::ReadsFrom { .. } => {
                panic!("{b:?} on {os:?} should own its system dir, got {other:?}")
            }
        };
        assert_eq!(
            own(Os::MacOs, Browser::Chrome),
            PathBuf::from(format!(
                "/fix/sys/Library/Google/Chrome/NativeMessagingHosts/{host}"
            ))
        );
        assert_eq!(
            own(Os::MacOs, Browser::Chromium),
            PathBuf::from(format!(
                "/fix/sys/Library/Application Support/Chromium/NativeMessagingHosts/{host}"
            ))
        );
        assert_eq!(
            own(Os::MacOs, Browser::Edge),
            PathBuf::from(format!(
                "/fix/sys/Library/Microsoft/Edge/NativeMessagingHosts/{host}"
            ))
        );
        assert_eq!(
            own(Os::Linux, Browser::Chrome),
            PathBuf::from(format!(
                "/fix/sys/etc/opt/chrome/native-messaging-hosts/{host}"
            ))
        );
        assert_eq!(
            own(Os::Linux, Browser::Chromium),
            PathBuf::from(format!(
                "/fix/sys/etc/chromium/native-messaging-hosts/{host}"
            ))
        );
        assert_eq!(
            own(Os::Linux, Browser::Edge),
            PathBuf::from(format!(
                "/fix/sys/etc/opt/edge/native-messaging-hosts/{host}"
            ))
        );
        assert_eq!(
            own(Os::Linux, Browser::Vivaldi),
            PathBuf::from(format!(
                "/fix/sys/etc/vivaldi/native-messaging-hosts/{host}"
            ))
        );

        let brave = entry(Os::Linux, &d, Browser::Brave);
        assert_eq!(
            brave.manifest.system,
            Lookup::ReadsFrom {
                owner: Browser::Chrome,
                registration: Registration::ManifestDir(PathBuf::from(
                    "/fix/sys/etc/opt/chrome/native-messaging-hosts"
                )),
            }
        );
        // Brave's Linux user directory is its own: the delegate's override there resolves to Brave's
        // default config root.
        assert_eq!(
            brave.manifest.user.registration().manifest_path(),
            PathBuf::from(format!(
                "/fix/home/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/{host}"
            ))
        );
        let opera = entry(Os::MacOs, &d, Browser::Opera);
        assert_eq!(
            opera.manifest.system,
            Lookup::ReadsFrom {
                owner: Browser::Chrome,
                registration: Registration::ManifestDir(PathBuf::from(
                    "/fix/sys/Library/Google/Chrome/NativeMessagingHosts"
                )),
            }
        );
        // A sharer's system pointer is the owner's: Opera on Windows writes into Chrome's HKLM key.
        assert_eq!(
            entry(Os::Windows, &d, Browser::Opera)
                .pointer
                .map(|p| p.system),
            entry(Os::Windows, &d, Browser::Chrome)
                .pointer
                .map(|p| p.system),
        );
        let brave_win = entry(Os::Windows, &d, Browser::Brave);
        assert_eq!(
            brave_win.manifest.system.registration().location(),
            r"HKLM\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.vivswan.chromium_bridge.host"
        );
        assert_eq!(brave_win.manifest.system.owner(), None);
        assert_eq!(
            entry(Os::Windows, &d, Browser::Opera)
                .manifest
                .system
                .owner(),
            Some(Browser::Chrome)
        );
        // Every sharer's owner owns its directory and lists the sharer among its readers (the label
        // decision rests on that list), per OS and scope: Brave and Opera in Unix system directories,
        // Opera alone on Windows, and per user Brave on macOS alone.
        for (os, scope, expected) in [
            (Os::MacOs, Scope::User, vec![Browser::Brave]),
            (
                Os::MacOs,
                Scope::System,
                vec![Browser::Brave, Browser::Opera],
            ),
            (Os::Linux, Scope::User, vec![]),
            (
                Os::Linux,
                Scope::System,
                vec![Browser::Brave, Browser::Opera],
            ),
            (Os::Windows, Scope::User, vec![]),
            (Os::Windows, Scope::System, vec![Browser::Opera]),
        ] {
            let sharers: Vec<Browser> = resolve(os, &d)
                .into_iter()
                .filter(|e| e.manifest.get(scope).owner() == Some(Browser::Chrome))
                .map(|e| e.browser)
                .collect();
            assert_eq!(sharers, expected, "{os:?} {scope:?}");
            let chrome = entry(os, &d, Browser::Chrome);
            let Lookup::Own { readers, .. } = chrome.manifest.get(scope) else {
                panic!("Chrome owns its {scope:?} directory on {os:?}");
            };
            assert_eq!(*readers, expected, "{os:?} {scope:?}");
            for e in resolve(os, &d) {
                if let Some(owner) = e.manifest.get(scope).owner() {
                    assert_eq!(
                        entry(os, &d, owner).manifest.get(scope).owner(),
                        None,
                        "{os:?} {scope:?} {owner:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn linux_layout_defaults_to_dot_config_and_honors_xdg() {
        let e = entry(Os::Linux, &dirs(), Browser::Chrome);
        assert_eq!(
            e.manifest.user.registration().manifest_path(),
            PathBuf::from(
                "/fix/home/.config/google-chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json"
            )
        );
        // No pointer on Linux: Chrome would install from it without asking.
        assert_eq!(e.pointer, None);
        // Presence: the account's config root per user, the vendor package's install dir for --system.
        assert_eq!(
            e.presence,
            Scoped {
                user: vec![PathBuf::from("/fix/home/.config/google-chrome")],
                system: vec![PathBuf::from("/fix/sys/opt/google/chrome")],
            }
        );

        let mut with_xdg = dirs();
        with_xdg.xdg_config_home = Some(PathBuf::from("/fix/xdg-config"));
        let e = entry(Os::Linux, &with_xdg, Browser::Edge);
        assert_eq!(
            e.presence.user[0],
            PathBuf::from("/fix/xdg-config/microsoft-edge")
        );
    }

    #[test]
    fn windows_layout_derives_registry_key_and_store_path_per_hive() {
        let mut d = dirs();
        d.local_app_data = Some(PathBuf::from("/fix/local"));
        d.roaming_app_data = Some(PathBuf::from("/fix/roaming"));
        d.program_files = Some(PathBuf::from("/fix/programfiles"));
        let e = entry(Os::Windows, &d, Browser::Chrome);
        let Registration::Registry {
            hive,
            key,
            manifest_path,
        } = e.manifest.user.registration()
        else {
            panic!(
                "expected a registry registration, got {:?}",
                e.manifest.user
            );
        };
        assert_eq!(*hive, Hive::CurrentUser);
        assert_eq!(
            key,
            r"Software\Google\Chrome\NativeMessagingHosts\com.vivswan.chromium_bridge.host"
        );
        assert_eq!(
            manifest_path,
            &PathBuf::from("/fix/local/chromium-bridge/com.vivswan.chromium_bridge.host.json")
        );
        assert_eq!(
            e.manifest.system,
            Lookup::Own {
                registration: Registration::Registry {
                    hive: Hive::LocalMachine,
                    key: r"Software\Google\Chrome\NativeMessagingHosts\com.vivswan.chromium_bridge.host"
                        .into(),
                    // Under Program Files, which a standard account cannot pre-create a directory in.
                    manifest_path: PathBuf::from(
                        "/fix/programfiles/chromium-bridge/com.vivswan.chromium_bridge.host.json"
                    ),
                },
                readers: vec![Browser::Opera],
            }
        );
        assert_eq!(
            e.pointer,
            Some(Scoped {
                user: ExtensionPointer::Registry {
                    hive: Hive::CurrentUser,
                    key: r"Software\Google\Chrome\Extensions\mkjjlmjbcljpcfkfadfmhblmmddkdihf"
                        .into()
                },
                system: ExtensionPointer::Registry {
                    hive: Hive::LocalMachine,
                    key: r"Software\Google\Chrome\Extensions\mkjjlmjbcljpcfkfadfmhblmmddkdihf"
                        .into()
                },
            })
        );
        assert_eq!(
            e.presence.user,
            vec![PathBuf::from("/fix/local/Google/Chrome/User Data")]
        );
        assert_eq!(e.presence.system, e.presence.user);
        // Opera detects under the roaming profile dir.
        let opera = entry(Os::Windows, &d, Browser::Opera);
        assert_eq!(
            opera.presence.user,
            vec![PathBuf::from("/fix/roaming/Opera Software")]
        );
    }

    /// The per-user install dir is where the retired shell installers put theirs, so re-registering over
    /// a legacy install converges on the same paths.
    #[test]
    fn install_dir_per_os_matches_the_retired_installers() {
        let mut d = dirs();
        assert_eq!(
            install_dir(Os::MacOs, &d, Scope::User),
            PathBuf::from("/fix/home/.chromium-bridge")
        );
        assert_eq!(
            install_dir(Os::Linux, &d, Scope::User),
            PathBuf::from("/fix/home/.local/share/chromium-bridge")
        );
        d.xdg_data_home = Some(PathBuf::from("/fix/xdg-data"));
        assert_eq!(
            install_dir(Os::Linux, &d, Scope::User),
            PathBuf::from("/fix/xdg-data/chromium-bridge")
        );
        d.local_app_data = Some(PathBuf::from("/fix/local"));
        assert_eq!(
            install_dir(Os::Windows, &d, Scope::User),
            PathBuf::from("/fix/local/chromium-bridge")
        );
    }

    #[test]
    fn detection_requires_the_app_on_macos_and_a_config_root_or_package_dir_elsewhere() {
        // Fixture tree in a temp dir; never a real user dir or system root.
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        let d = BaseDirs {
            home: root.join("home"),
            xdg_config_home: None,
            xdg_data_home: None,
            local_app_data: None,
            roaming_app_data: None,
            program_files: None,
            system_root: root.join("sys"),
        };

        // macOS: the app bundle is required; the config root alone is not
        // enough (uninstalled browsers and dev tooling leave those behind).
        let app_support = d.home.join("Library/Application Support");
        // chrome: app in the system folder + config root -> detected.
        std::fs::create_dir_all(root.join("sys/Applications/Google Chrome.app")).unwrap();
        std::fs::create_dir_all(app_support.join("Google/Chrome")).unwrap();
        // brave: app in ~/Applications, config root ABSENT (fresh install
        // before first run) -> still detected.
        std::fs::create_dir_all(d.home.join("Applications/Brave Browser.app")).unwrap();
        // chromium + vivaldi: leftover config roots with no app -> NOT
        // detected (the reported ghost-browser bug).
        std::fs::create_dir_all(app_support.join("Chromium")).unwrap();
        std::fs::create_dir_all(app_support.join("Vivaldi")).unwrap();

        let detected = |os: Os, scope: Scope| -> Vec<&str> {
            resolve(os, &d)
                .iter()
                .filter(|e| e.detected(scope))
                .map(|e| e.browser.key())
                .collect()
        };
        assert_eq!(detected(Os::MacOs, Scope::User), vec!["chrome", "brave"]);
        // A bundle in one account's home is not machine-wide.
        assert_eq!(detected(Os::MacOs, Scope::System), vec!["chrome"]);

        // Linux: the vendor package's install dir (Edge installed for every account, as the .deb's
        // post-install sees it from root) is a --system signal alone, so an account that ran no browser
        // (the registration smoke's isolated XDG roots on a runner that ships Chrome under /opt) detects
        // nothing per user; its own config root (chromium ran here) is the per-user signal.
        std::fs::create_dir_all(root.join("sys/opt/microsoft/msedge")).unwrap();
        assert_eq!(detected(Os::Linux, Scope::User), Vec::<&str>::new());
        assert_eq!(detected(Os::Linux, Scope::System), vec!["edge"]);
        std::fs::create_dir_all(d.home.join(".config/chromium")).unwrap();
        assert_eq!(detected(Os::Linux, Scope::User), vec!["chromium"]);
        assert_eq!(detected(Os::Linux, Scope::System), vec!["edge"]);
    }

    #[test]
    fn resolve_lists_every_browser_once_in_order() {
        let entries = resolve(Os::Linux, &dirs());
        let keys: Vec<&str> = entries.iter().map(|e| e.browser.key()).collect();
        assert_eq!(
            keys,
            vec!["chrome", "chromium", "brave", "edge", "vivaldi", "opera"]
        );
    }
}
