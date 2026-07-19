//! Browser-path resolver: which Chromium-family browsers exist on this
//! machine, and where each one looks for our native-messaging registration.
//!
//! This is the ONE source of per-browser path knowledge, shared by `doctor`
//! (diagnosis and `--fix` repair), `uninstall` (both in
//! `crate::registration`), and the app's browser detection and registration.
//! Everything here is a pure derivation from
//! an [`Os`] and a set of [`BaseDirs`]: no I/O happens in this module, so
//! every layout (macOS, Linux, Windows) is unit-testable from any host and
//! tests never touch a real user directory. Callers do the existence checks
//! against the paths this module hands back.

use std::path::{Path, PathBuf};

// The identity constants this resolver stamps into every registration.
// `crate::identity` is the single definition site (ADR-0028); re-exported
// here under the resolver's vocabulary so registration/doctor keep one
// import for "which host, which extension, which paths".
pub use crate::identity::{NATIVE_HOST_ID as HOST_ID, PINNED_EXTENSION_ID};

/// The Chromium-family browsers we know how to register with by name. Any
/// other Chromium build is reachable through `doctor --fix`'s explicit
/// `--manifest-dir` escape hatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// The per-user base directories every browser path is derived from.
/// Injected (never read from the environment inside the resolver) so tests
/// point them at fixture directories.
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
    /// The system-wide applications folder (`/Applications` on macOS).
    /// Injected like every other root so detection tests scan fixture trees,
    /// never the machine's real one.
    pub system_applications: PathBuf,
}

impl BaseDirs {
    /// Read the base directories from the process environment. Fails (rather
    /// than inventing a root like `/`) when the platform's home variable is
    /// missing or not absolute: writing registrations relative to a guessed
    /// or CWD-relative home would be worse than refusing. Relative XDG
    /// overrides are ignored, as the basedir spec requires.
    pub fn from_env() -> Result<BaseDirs, String> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or("HOME (or USERPROFILE) is not set to an absolute path; cannot resolve per-user browser paths")?;
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
            system_applications: PathBuf::from("/Applications"),
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
}

/// How a browser picks up the native-messaging manifest on this OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// macOS / Linux: the browser scans this `NativeMessagingHosts` directory
    /// for `<HOST_ID>.json`.
    ManifestDir(PathBuf),
    /// Windows: the browser reads this HKCU registry key (path relative to
    /// `HKEY_CURRENT_USER`); its default value must point at the manifest
    /// file, which we keep at `manifest_path`.
    Registry { key: String, manifest_path: PathBuf },
}

impl Registration {
    /// The manifest file this registration writes/reads.
    pub fn manifest_path(&self) -> PathBuf {
        match self {
            Registration::ManifestDir(dir) => dir.join(format!("{HOST_ID}.json")),
            Registration::Registry { manifest_path, .. } => manifest_path.clone(),
        }
    }

    /// Human-oriented description of where the registration lives, for
    /// reports (`doctor`, `install --list`).
    pub fn location(&self) -> String {
        match self {
            Registration::ManifestDir(_) => self.manifest_path().display().to_string(),
            Registration::Registry { key, .. } => format!("HKCU\\{key}"),
        }
    }
}

/// One known browser on one OS: how to detect it and how to register with it.
#[derive(Debug, Clone)]
pub struct BrowserEntry {
    pub browser: Browser,
    /// The browser's per-user config/profile root. On Linux/Windows its
    /// existence is the detection signal; on macOS it is a weak signal on
    /// its own -- an uninstalled browser leaves its config root behind
    /// forever, and dev tooling creates some (a bare `Chromium` folder) --
    /// so detection there requires an application bundle from `app_paths`
    /// instead. Purely a path; the caller checks existence.
    pub config_dir: PathBuf,
    /// Candidate install locations for the application itself (macOS: the
    /// `.app` bundle under `/Applications` or `~/Applications`). Empty on
    /// platforms where we have no equally cheap app-presence signal
    /// (Linux/Windows), which keeps the config-dir heuristic there. Purely
    /// paths; the caller checks existence.
    pub app_paths: Vec<PathBuf>,
    pub registration: Registration,
}

impl BrowserEntry {
    /// Whether the browser looks present for this user. The only I/O in this
    /// module's surface, kept on the entry so `resolve` itself stays pure for
    /// tests.
    ///
    /// When `app_paths` is populated (macOS), the application bundle itself
    /// must exist -- a leftover config root alone must never light the row,
    /// and a freshly installed app that has not created its config root yet
    /// still counts. When `app_paths` is empty (Linux/Windows), the config
    /// root is the best cheap signal we have.
    ///
    /// This is a display/guidance heuristic, not a security gate. Default
    /// `doctor --fix` does use it to pick which browsers to register (fewer
    /// detected browsers means fewer manifests written, never more), and
    /// registration into an undetected browser stays possible through the
    /// explicit register paths. Residual: a macOS app installed outside both
    /// application folders reads as "not detected"; the user can still
    /// register it explicitly.
    pub fn detected(&self) -> bool {
        if self.app_paths.is_empty() {
            return self.config_dir.is_dir();
        }
        self.app_paths.iter().any(|p| p.is_dir())
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

/// Each browser's application bundle name on macOS, looked for under
/// `/Applications` and `~/Applications` (the two standard install roots,
/// including Homebrew casks). A Launch Services lookup by bundle id would
/// also catch non-standard locations, but needs shelling out or an
/// Objective-C bridge; two path checks are the cheap, dependency-free
/// mechanism, and the non-standard-location gap is a named residual on
/// [`BrowserEntry::detected`].
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

/// The HKCU registry root each browser owns on Windows (matches what the
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
    let local = |sub: &str| {
        dirs.local_app_data
            .clone()
            .unwrap_or_else(|| dirs.home.join("AppData/Local"))
            .join(sub)
    };
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
/// namespace, referenced by the registry value). Matches the directory the
/// retired shell installers used, so re-registering over a legacy install
/// converges on the same paths.
pub fn install_dir(os: Os, dirs: &BaseDirs) -> PathBuf {
    match os {
        Os::MacOs => dirs.home.join(".chromium-bridge"),
        Os::Linux => dirs.data_home().join("chromium-bridge"),
        Os::Windows => dirs
            .local_app_data
            .clone()
            .unwrap_or_else(|| dirs.home.join("AppData/Local"))
            .join("chromium-bridge"),
    }
}

/// Resolve one browser's entry on one OS.
pub fn entry(os: Os, dirs: &BaseDirs, browser: Browser) -> BrowserEntry {
    match os {
        Os::MacOs => {
            let root = dirs
                .home
                .join("Library/Application Support")
                .join(macos_vendor_dir(browser));
            let bundle = macos_app_bundle(browser);
            BrowserEntry {
                browser,
                registration: Registration::ManifestDir(root.join("NativeMessagingHosts")),
                config_dir: root,
                app_paths: vec![
                    dirs.system_applications.join(bundle),
                    dirs.home.join("Applications").join(bundle),
                ],
            }
        }
        Os::Linux => {
            let root = dirs.config_home().join(linux_vendor_dir(browser));
            BrowserEntry {
                browser,
                registration: Registration::ManifestDir(root.join("NativeMessagingHosts")),
                config_dir: root,
                app_paths: Vec::new(),
            }
        }
        Os::Windows => BrowserEntry {
            browser,
            config_dir: windows_profile_dir(dirs, browser),
            app_paths: Vec::new(),
            registration: Registration::Registry {
                key: format!(
                    r"{}\NativeMessagingHosts\{HOST_ID}",
                    windows_vendor_key(browser)
                ),
                manifest_path: install_dir(os, dirs).join(format!("{HOST_ID}.json")),
            },
        },
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
pub fn explicit_dir_registration(dir: &Path) -> Registration {
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
            system_applications: PathBuf::from("/fix/Applications"),
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

    #[test]
    fn macos_layout_matches_the_shell_installer() {
        let e = entry(Os::MacOs, &dirs(), Browser::Brave);
        assert_eq!(
            e.config_dir,
            PathBuf::from("/fix/home/Library/Application Support/BraveSoftware/Brave-Browser")
        );
        assert_eq!(
            e.registration.manifest_path(),
            PathBuf::from(
                "/fix/home/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json"
            )
        );
        // App-presence candidates: the two standard install roots.
        assert_eq!(
            e.app_paths,
            vec![
                PathBuf::from("/fix/Applications/Brave Browser.app"),
                PathBuf::from("/fix/home/Applications/Brave Browser.app"),
            ]
        );
        // Opera's macOS dir is the bundle-id one, not "Opera".
        let opera = entry(Os::MacOs, &dirs(), Browser::Opera);
        assert!(opera
            .config_dir
            .ends_with("Library/Application Support/com.operasoftware.Opera"));
        assert!(opera
            .app_paths
            .contains(&PathBuf::from("/fix/Applications/Opera.app")));
    }

    #[test]
    fn linux_layout_defaults_to_dot_config_and_honors_xdg() {
        let e = entry(Os::Linux, &dirs(), Browser::Chrome);
        assert_eq!(
            e.registration.manifest_path(),
            PathBuf::from(
                "/fix/home/.config/google-chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json"
            )
        );

        let mut with_xdg = dirs();
        with_xdg.xdg_config_home = Some(PathBuf::from("/fix/xdg-config"));
        let e = entry(Os::Linux, &with_xdg, Browser::Edge);
        assert_eq!(
            e.config_dir,
            PathBuf::from("/fix/xdg-config/microsoft-edge")
        );
    }

    #[test]
    fn windows_layout_derives_registry_key_and_store_path() {
        let mut d = dirs();
        d.local_app_data = Some(PathBuf::from("/fix/local"));
        d.roaming_app_data = Some(PathBuf::from("/fix/roaming"));
        let e = entry(Os::Windows, &d, Browser::Chrome);
        match &e.registration {
            Registration::Registry { key, manifest_path } => {
                assert_eq!(
                    key,
                    r"Software\Google\Chrome\NativeMessagingHosts\com.vivswan.chromium_bridge.host"
                );
                assert_eq!(
                    manifest_path,
                    &PathBuf::from(
                        "/fix/local/chromium-bridge/com.vivswan.chromium_bridge.host.json"
                    )
                );
            }
            other => panic!("expected a registry registration, got {other:?}"),
        }
        assert_eq!(
            e.config_dir,
            PathBuf::from("/fix/local/Google/Chrome/User Data")
        );
        // Opera detects under the roaming profile dir.
        let opera = entry(Os::Windows, &d, Browser::Opera);
        assert_eq!(
            opera.config_dir,
            PathBuf::from("/fix/roaming/Opera Software")
        );
    }

    #[test]
    fn install_dir_per_os() {
        let mut d = dirs();
        assert_eq!(
            install_dir(Os::MacOs, &d),
            PathBuf::from("/fix/home/.chromium-bridge")
        );
        assert_eq!(
            install_dir(Os::Linux, &d),
            PathBuf::from("/fix/home/.local/share/chromium-bridge")
        );
        d.xdg_data_home = Some(PathBuf::from("/fix/xdg-data"));
        assert_eq!(
            install_dir(Os::Linux, &d),
            PathBuf::from("/fix/xdg-data/chromium-bridge")
        );
        d.local_app_data = Some(PathBuf::from("/fix/local"));
        assert_eq!(
            install_dir(Os::Windows, &d),
            PathBuf::from("/fix/local/chromium-bridge")
        );
    }

    #[test]
    fn detection_requires_the_app_on_macos_and_the_config_root_elsewhere() {
        // Fixture tree in a temp dir; never a real user dir.
        let root = std::env::temp_dir().join(format!("bb-browsers-detect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let d = BaseDirs {
            home: root.join("home"),
            xdg_config_home: None,
            xdg_data_home: None,
            local_app_data: None,
            roaming_app_data: None,
            system_applications: root.join("Applications"),
        };

        // macOS: the app bundle is required; the config root alone is not
        // enough (uninstalled browsers and dev tooling leave those behind).
        let app_support = d.home.join("Library/Application Support");
        // chrome: app in the system folder + config root -> detected.
        std::fs::create_dir_all(root.join("Applications/Google Chrome.app")).unwrap();
        std::fs::create_dir_all(app_support.join("Google/Chrome")).unwrap();
        // brave: app in ~/Applications, config root ABSENT (fresh install
        // before first run) -> still detected.
        std::fs::create_dir_all(d.home.join("Applications/Brave Browser.app")).unwrap();
        // chromium + vivaldi: leftover config roots with no app -> NOT
        // detected (the reported ghost-browser bug).
        std::fs::create_dir_all(app_support.join("Chromium")).unwrap();
        std::fs::create_dir_all(app_support.join("Vivaldi")).unwrap();

        let entries = resolve(Os::MacOs, &d);
        let detected: Vec<&str> = entries
            .iter()
            .filter(|e| e.detected())
            .map(|e| e.browser.key())
            .collect();
        assert_eq!(detected, vec!["chrome", "brave"]);

        // Linux keeps the config-dir heuristic: no app-presence signal is
        // resolved there, so the same fixture home detects via ~/.config.
        std::fs::create_dir_all(d.home.join(".config/chromium")).unwrap();
        let entries = resolve(Os::Linux, &d);
        let detected: Vec<&str> = entries
            .iter()
            .filter(|e| e.detected())
            .map(|e| e.browser.key())
            .collect();
        assert_eq!(detected, vec!["chromium"]);
        for e in resolve(Os::Linux, &d) {
            assert!(e.app_paths.is_empty(), "{:?}", e.browser);
        }
        for e in resolve(Os::Windows, &d) {
            assert!(e.app_paths.is_empty(), "{:?}", e.browser);
        }

        std::fs::remove_dir_all(&root).unwrap();
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
