# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2026-10-10)


### ⚠ BREAKING CHANGES

* relicense to the Individual and Small Organization License 1.0.0
* the justfile is gone - use moon run <task> (moon run help lists everything); local checkouts need proto (proto install) since moon is no longer an npm devDependency.

### Features

* add host-owned policy core, signing domain, and control frames (ADR-0032 phase 1) ([9de69e4](https://github.com/Vivswan/genkan/commit/9de69e4a6323af1759510c0cf2ee3586854d4b03))
* answer policy frames, gate dispatch, add policy CLI (ADR-0032 phase 2) ([a1354ce](https://github.com/Vivswan/genkan/commit/a1354ce847c3af8e0293be4e7d41d8d47413067d))
* **app:** first-run legacy import, unenrolled floor, and language sync (ADR-0032 phase 4) ([b3b9d1a](https://github.com/Vivswan/genkan/commit/b3b9d1a6585ff39458b44aa3c6a97d91c9536ddd))
* **build:** adopt moon as the task orchestrator under the justfile (phase one) ([e74e656](https://github.com/Vivswan/genkan/commit/e74e65628415ba0e507b37b8bf689d91f3f3414a))
* **ci:** add SSoT parity gates for docs, adversarial tests, fuzz seeds, and the browser job ([#28](https://github.com/Vivswan/genkan/issues/28)) ([efc32c8](https://github.com/Vivswan/genkan/commit/efc32c88f093cef0a71475e82d63b262ce15720b))
* **ci:** persist and minimize the fuzz corpus nightly ([d24e214](https://github.com/Vivswan/genkan/commit/d24e2145d1ec0b3061f356d697f0581ab0f68a34))
* **cli:** doctor --fix + uninstall on a shared browser-path resolver ([53776ed](https://github.com/Vivswan/genkan/commit/53776edfe25dbd8b26a650b82837373e2e2815c9))
* **cli:** parse the command line once with clap into a typed Command ([#142](https://github.com/Vivswan/genkan/issues/142)) ([29b26e9](https://github.com/Vivswan/genkan/commit/29b26e90c0901384fa11e9314fabc557623a38e8))
* **cli:** revoke takes a target, one browser or --all, and a bare revoke is refused ([#226](https://github.com/Vivswan/genkan/issues/226)) ([1cb3583](https://github.com/Vivswan/genkan/commit/1cb3583be97283bcbaffff9211b65048aa2db0f0))
* **contract:** emit audit forwarding, writer frame types, and the MCP version from the core ([#29](https://github.com/Vivswan/genkan/issues/29)) ([00495ae](https://github.com/Vivswan/genkan/commit/00495ae7d88b0f5b86314f59d8f1e8e15595ca35))
* **contract:** generate the envelope wire validators from the Rust schemas ([dc3b4c5](https://github.com/Vivswan/genkan/commit/dc3b4c58b9a1c65a85e32e05bae3d1ea98b13edd))
* **core:** emit the enclave contract and golden vectors to the shared TS package ([#30](https://github.com/Vivswan/genkan/issues/30)) ([afa07d9](https://github.com/Vivswan/genkan/commit/afa07d95ec9f19227a3eb8a6bee105b83ff7c256))
* **core:** one trust record and an owning admission snapshot replace clients.json and revocation.json ([#155](https://github.com/Vivswan/genkan/issues/155)) ([a41978e](https://github.com/Vivswan/genkan/commit/a41978e844d8858d5c0a3144c98d9c0f1a86b9c5))
* **core:** runtime-record loader with a migration ladder for every runtime-dir JSON record ([#138](https://github.com/Vivswan/genkan/issues/138)) ([4b0cec8](https://github.com/Vivswan/genkan/commit/4b0cec804a20e4f99b3cf4d30863ea4fa0c426e5))
* **core:** typed BridgeCommand and one tool record replace four hand-kept tables ([#140](https://github.com/Vivswan/genkan/issues/140)) ([26cc941](https://github.com/Vivswan/genkan/commit/26cc9412c79226173398510ab2647a1c94a8f4b5))
* **cutover:** retire install scripts, consolidate docs, add zh docs + docs site ([40fed60](https://github.com/Vivswan/genkan/commit/40fed600eab370eaf072b35d67ee98e2ab233006))
* desktop app policy editor and signed grant lane (ADR-0032 phase 2) ([8d68aba](https://github.com/Vivswan/genkan/commit/8d68aba2320b092363a5f3bccb6b72d5c63ea3bd))
* **desktop:** app-confirm dialogs and phase8 presence-contract alignment ([06c3d77](https://github.com/Vivswan/genkan/commit/06c3d7702f661c66914e3870f37e2b1afe7c382f))
* **desktop:** control-panel app UI over the core management engines (ADR-0029) ([d088d10](https://github.com/Vivswan/genkan/commit/d088d100f867eeca995a7cdf5df910bb79bdec3c))
* **desktop:** generate the UI's Tauri command types from Rust via ts-rs ([d60343a](https://github.com/Vivswan/genkan/commit/d60343acaa5172e1fc08a9b61307008263226558))
* **desktop:** overview lifecycle states per the first-run spec ([5037e3d](https://github.com/Vivswan/genkan/commit/5037e3daaec9049537111b84600d75c50b8508d0))
* **desktop:** prove the signed-host entitlement chain (Tauri v2 spike) ([f6a8552](https://github.com/Vivswan/genkan/commit/f6a85529f5a521ad25698d0f6da620281e35c121))
* **desktop:** rebuild UI to the Control Tower design ([4e5cc2a](https://github.com/Vivswan/genkan/commit/4e5cc2a43819f1b13293a8b0e3794c60ae9fd9c4))
* **desktop:** wire the presence gates onto the landed phase8 API (Floor::AppConfirm) ([e6c1112](https://github.com/Vivswan/genkan/commit/e6c111210d5637e359b42682a2536e4dfdfdd020))
* **dev:** docs tab + pinned toolbar icon in the WXT dev browser, enforced fresh-profile isolation ([b4b8c34](https://github.com/Vivswan/genkan/commit/b4b8c34f07bda821d50ea4be0d41ace05925c7c6))
* **dev:** just dev also runs the desktop app; cut just --list to 12 top-level verbs ([94434f7](https://github.com/Vivswan/genkan/commit/94434f714ba3ebdb57de849ec0e89c9e2416c80f))
* **dev:** just dev runs the extension and site together; build includes the site ([b2bd354](https://github.com/Vivswan/genkan/commit/b2bd354a408548b403e7563bf75269dc0882f249))
* **ext:** bundle JetBrains Mono for identity material ([07ac483](https://github.com/Vivswan/genkan/commit/07ac4838c021dd2acf4014aff2106adff6902cdc))
* extension policy consumption core (ADR-0032 phase 3) ([bb48ad4](https://github.com/Vivswan/genkan/commit/bb48ad4779199490ed1ff87e49bdd6ce091cf055))
* **extension:** apply and emit language sync per ADR-0032 decision 7 (phase 4) ([748a2a2](https://github.com/Vivswan/genkan/commit/748a2a2989a0b8b7477876285497d49784812d4d))
* **extension:** compact engage-only kill control in the confirm window ([9968ee7](https://github.com/Vivswan/genkan/commit/9968ee7fd3e813a9ab19e6abee4fedf760b9b55c))
* **extension:** enforce host policy at every capability site via state-typed snapshots (ADR-0032 phase 3) ([ea21e50](https://github.com/Vivswan/genkan/commit/ea21e504945e0b016e1fca336b364c1a8ab82427))
* **extension:** localize tool labels through the i18n bundle ([4d33fa5](https://github.com/Vivswan/genkan/commit/4d33fa5e961a919696988ddbce0b47f8ac12d592))
* **extension:** retire the migrated legacy settings surface (ADR-0032 phase 5) ([dbb5b87](https://github.com/Vivswan/genkan/commit/dbb5b87d2204e205f63731858b8dfc3791e1896b))
* **extension:** send the legacy settings bag once to a pinned host that proved key possession (ADR-0032 phase 4) ([341cbaf](https://github.com/Vivswan/genkan/commit/341cbaf387706d699a9193cc271e2b3a025b26e1))
* **extension:** unpinned-window policy approval lane with anchor-preserving commit (ADR-0032 phase 3 lane U) ([4d25e6e](https://github.com/Vivswan/genkan/commit/4d25e6ea6ad3456aa4e1ac0ed92133f71e75ed35))
* **ext:** first-run popup pairing state per the first-run spec ([874627b](https://github.com/Vivswan/genkan/commit/874627b0efa62591584a2db54c12276b5ee688f2))
* **ext:** rebuild popup, options, and confirm on the Control Tower design ([6248ac4](https://github.com/Vivswan/genkan/commit/6248ac4132ce3fd05cbcd47eddf0c0084ef0998c))
* **ext:** restyle the in-page info toast to the Control Tower layout ([1695192](https://github.com/Vivswan/genkan/commit/16951929f6a7f6961f56dc2209644595809f7b10))
* **ext:** restyle the shared UI primitives to Control Tower motifs ([8d8f3d3](https://github.com/Vivswan/genkan/commit/8d8f3d395285ea1b14c7bce1f44429cb1eb0d119))
* file nightly fuzz crashes as tracking issues with seeded replay ([588e342](https://github.com/Vivswan/genkan/commit/588e342460667cacbe10811aee3536ec167350b7))
* **fuzz:** add classify_frame, enclave, and manifest targets ([7efa002](https://github.com/Vivswan/genkan/commit/7efa002a39a5e390633bbcc60e6ced8e5f43d1b8))
* **fuzz:** add fuzzing feature and handshake_verify target ([7c7b66a](https://github.com/Vivswan/genkan/commit/7c7b66a1a4a80cd88b734643c77db0d8873f2342))
* **fuzz:** seed corpora and dictionaries ([194b433](https://github.com/Vivswan/genkan/commit/194b4338773b745f2def3bd128a0fc3f20d56fe2))
* **gen:** the asymmetry table generates the enforced validators; the parity diff and the normalizer go ([#150](https://github.com/Vivswan/genkan/issues/150)) ([0c49fc9](https://github.com/Vivswan/genkan/commit/0c49fc9a2384c2528b1a6e12f40bc841773f68f0))
* **host:** pending-import store and structured policy reason for legacy migration (ADR-0032 phase 4 host) ([aaa3c38](https://github.com/Vivswan/genkan/commit/aaa3c38d983b8830da747062e43fb71863e133f9))
* **icons:** generate Gatedeck icon assets from SVG sources at build time ([5796d4d](https://github.com/Vivswan/genkan/commit/5796d4dd90dd0492d27c19d0e4d1390b0f7acda1))
* **installers:** the .deb registers system-wide, and doctor --fix learns a --system scope ([#203](https://github.com/Vivswan/genkan/issues/203)) ([0fd3189](https://github.com/Vivswan/genkan/commit/0fd3189f1e4122fca6888e64654bc165ac8737ca))
* **install:** post-install writes the browser pointer files, and releases ship .pkg, .msi, .deb and a brew bump ([#178](https://github.com/Vivswan/genkan/issues/178)) ([7c20382](https://github.com/Vivswan/genkan/commit/7c2038220c0ea5fa8a70b7e2757689e5a0c1b06c))
* **ipc:** named-pipe bridge with an attested client on Windows ([#151](https://github.com/Vivswan/genkan/issues/151)) ([834471a](https://github.com/Vivswan/genkan/commit/834471a51eaeae70d4e97cbd0b8961ad737d4b77))
* migrate .repo-platform.yml to the modules schema ([#12](https://github.com/Vivswan/genkan/issues/12)) ([03aef09](https://github.com/Vivswan/genkan/commit/03aef095c0b2d853d194b69e99f1c3936b0b1d3c))
* migrate MCP server to spec 2026-07-28 on the official rmcp SDK ([5fc968b](https://github.com/Vivswan/genkan/commit/5fc968b790624e97606d2b273d20306432cb8b54))
* **options:** registration status with repair, and the policy editor, in the options page ([#171](https://github.com/Vivswan/genkan/issues/171)) ([69bc16e](https://github.com/Vivswan/genkan/commit/69bc16ef9640603abb301b2593d4d51dd5e1b3e9))
* **options:** the grant lane reaches the options page: policy set, rollback, history, and pair-client behind the presence tap ([#236](https://github.com/Vivswan/genkan/issues/236)) ([eaeea92](https://github.com/Vivswan/genkan/commit/eaeea922df855fdf8459c9e5d5032e8413c22843))
* **options:** the options page enrolls this browser's authenticator and releases the kill switch behind a tap ([#192](https://github.com/Vivswan/genkan/issues/192)) ([0940bef](https://github.com/Vivswan/genkan/commit/0940bef10082f09a22afbebff6b2b7ad664d0da8))
* **options:** the page reads the host's audit trail through an audit_read frame, with the CLI's words ([#227](https://github.com/Vivswan/genkan/issues/227)) ([f020072](https://github.com/Vivswan/genkan/commit/f020072fac3e0a866f353eac50b8f8d7787ed748))
* **options:** the refusal roster is generated from the host, and the popup speaks the WebAuthn posture ([#209](https://github.com/Vivswan/genkan/issues/209)) ([660fc36](https://github.com/Vivswan/genkan/commit/660fc369a691cafab347c34bc4198b32d613df25))
* **presence:** enrollment and presence move to WebAuthn, replacing the Secure Enclave ceremony ([#188](https://github.com/Vivswan/genkan/issues/188)) ([53cfd2a](https://github.com/Vivswan/genkan/commit/53cfd2a2c52e6361995d8438a9aaf7551bbe0495))
* **presence:** page_eval and page_upload confirm on the enrolled authenticator through a presence_begin frame ([#221](https://github.com/Vivswan/genkan/issues/221)) ([b58b9a0](https://github.com/Vivswan/genkan/commit/b58b9a06dbc2d90d45db3213cda7f9d35939c0a2))
* **presence:** webauthn assertion verifier, presence frames, and the extension ceremony ([#167](https://github.com/Vivswan/genkan/issues/167)) ([71d66e3](https://github.com/Vivswan/genkan/commit/71d66e3f2c4baf4c85b0bc0109894ad176f696eb))
* **protocol:** a dropped request guard sends cancel, and the deadline is the caller's ([#174](https://github.com/Vivswan/genkan/issues/174)) ([ffebaa0](https://github.com/Vivswan/genkan/commit/ffebaa0310bf9bc99ba296c7cd84ac6e37e4b203))
* **release:** branded DMG with Gatedeck identity ([127d978](https://github.com/Vivswan/genkan/commit/127d9786684e89d07bb8c9c2ad5c4077fdeab938))
* **release:** build, verify, and publish the signed desktop .dmg ([6a7d51c](https://github.com/Vivswan/genkan/commit/6a7d51cc1bd4d9a3f79657547b05d84798882490))
* **security:** any-side revocation epoch (ADR-0025) ([8ae50c7](https://github.com/Vivswan/genkan/commit/8ae50c7d869b1cde9afa89f9ed776c798849ec7f))
* **security:** global kill switch, audit trail, and presence-gated unkill (ADR-0030) ([240abbc](https://github.com/Vivswan/genkan/commit/240abbc18252a7fc918bb1dea3556306cac69195))
* **security:** Touch ID presence gates for crown-jewel tools and capability grants (ADR-0031) ([905c5aa](https://github.com/Vivswan/genkan/commit/905c5aa96ee414283ba8b0f8a8a4c925532b7597))
* **shared:** parser asymmetries declare their direction and reason, enforced by the envelope gate ([#146](https://github.com/Vivswan/genkan/issues/146)) ([6b0042f](https://github.com/Vivswan/genkan/commit/6b0042fb47801735a4aeccd3c44798ea830f46ba))
* **site:** Control Tower landing page ([f12cb93](https://github.com/Vivswan/genkan/commit/f12cb935ba55fe57a95f429051e6fe7a3828b183))
* **ui:** adopt Control Tower design tokens in both apps ([873d557](https://github.com/Vivswan/genkan/commit/873d55727f39f99b83eda089935c2c5f2a5e3471))
* wire policy and language frames into the envelope gate (ADR-0032 phase 3) ([3c93d2d](https://github.com/Vivswan/genkan/commit/3c93d2dfaee8e09e76b849032a919c4e33b5abeb))


### Bug Fixes

* **audit:** correlate confirmation rows by a per-confirmation id ([37e2914](https://github.com/Vivswan/genkan/commit/37e29140db006e43dd4ac5728cc332d3e2478bcc))
* **build:** tauri hooks run from the frontend dir; restore bun run dev/build ([3d92976](https://github.com/Vivswan/genkan/commit/3d9297670e0c8b2a24d329154f8706ef3b8ee7c3))
* **ci:** check out full history so moon can resolve the PR base ref ([b492c8f](https://github.com/Vivswan/genkan/commit/b492c8fb07f6549999af1a1df64790804e74f8db))
* **ci:** drop the retired issue-templates module from the registration ([#76](https://github.com/Vivswan/genkan/issues/76)) ([1145bf4](https://github.com/Vivswan/genkan/commit/1145bf4d895370380262e5e135c8df43f098d5a8))
* **ci:** scope fuzz deny relaxations to a fuzz-only config ([dd8c5ad](https://github.com/Vivswan/genkan/commit/dd8c5ad0819b38c64384fe578b0a7d491f5097ef))
* **ci:** unbreak the first nightly run (fuzz musl target, mutants exit 3) ([3077647](https://github.com/Vivswan/genkan/commit/3077647291f99c37ad54289604ee204ca917405b))
* **contracts:** gate enclave/admin/client wire types in the envelope parity check ([f5ef9dd](https://github.com/Vivswan/genkan/commit/f5ef9dd3c7d062e4aa258ffe37cc4f29d1ebca3a))
* **core:** a runtime dir whose socket path cannot fit sun_path is refused once, by name ([#197](https://github.com/Vivswan/genkan/issues/197)) ([72abf14](https://github.com/Vivswan/genkan/commit/72abf14b5ad6ebbeb2842383430b3adbe6b8b6aa))
* **core:** a superseded connection under the same label is closed, so a worker restart cannot strand the extension ([#205](https://github.com/Vivswan/genkan/issues/205)) ([86dc51d](https://github.com/Vivswan/genkan/commit/86dc51d6ad6416a409fe74f837d359a275017111))
* **core:** audit lines refuse missing fields and fall under the record tripwire ([#148](https://github.com/Vivswan/genkan/issues/148)) ([4237947](https://github.com/Vivswan/genkan/commit/423794738e30de353813a9e43f04c5e46e9235f9))
* **core:** centralize secure file permissions in fsguard ([fc837cc](https://github.com/Vivswan/genkan/commit/fc837ccc17184e2b6ca6e28ec4ac47cff2932f55))
* **core:** doctor --paths resolves the runtime dir without creating it, and the harness probe uses it ([#177](https://github.com/Vivswan/genkan/issues/177)) ([a817d12](https://github.com/Vivswan/genkan/commit/a817d1235495a38e9df2b75f1ad34177b1b7f2e4))
* **core:** drop the Windows delete-before-rename on security files ([172304a](https://github.com/Vivswan/genkan/commit/172304abff43bebfcec04673849490141feef67b))
* **core:** emit revocation audit record inside Allowlist::revoke ([20df4a5](https://github.com/Vivswan/genkan/commit/20df4a55444eb18b6bf987fd6c899b8c685fd96a))
* **core:** enforce trust-store preconditions and anchor validity in types ([#24](https://github.com/Vivswan/genkan/issues/24)) ([0e24ed2](https://github.com/Vivswan/genkan/commit/0e24ed269dbbcde1353b13084106012660c8afb8))
* **core:** harden the unsafe FFI quarantine per audit findings ([23044b9](https://github.com/Vivswan/genkan/commit/23044b91a97a322b8af5504fb239940941b61c94))
* **core:** pending-import bag numbers read back as the f64 they wrote ([#102](https://github.com/Vivswan/genkan/issues/102)) ([c534efc](https://github.com/Vivswan/genkan/commit/c534efc1abdada9fea50f1a07cdede5b0675e097))
* **core:** the loom refcount model builds under its own feature and runs in CI ([#154](https://github.com/Vivswan/genkan/issues/154)) ([63fc6f0](https://github.com/Vivswan/genkan/commit/63fc6f0f15147ef0273cdfc379203816554cc19a))
* **core:** write config.json via the hardened write_private_atomic ([cff0af5](https://github.com/Vivswan/genkan/commit/cff0af5dab9087837486cbd53d531b361c62e665))
* cover desktop ui package.json in release-please and guard version sync ([#23](https://github.com/Vivswan/genkan/issues/23)) ([a3ff292](https://github.com/Vivswan/genkan/commit/a3ff292fa9de7d1123a301282e4dcd354e1f888e))
* **deps:** bump devalue to 5.9.4 for the four HIGH advisories against 5.9.2 ([#122](https://github.com/Vivswan/genkan/issues/122)) ([12aaa4a](https://github.com/Vivswan/genkan/commit/12aaa4af4f08a6f0ec0b7d6da7d8095c80383405))
* **desktop:** a11y and interaction polish from the design gauntlet ([d3deb91](https://github.com/Vivswan/genkan/commit/d3deb91fa7db5e495c1c9eceb4355c9f25e67058))
* **desktop:** box the AuditLine::Record variant after cid grew AuditRecord ([33b68a6](https://github.com/Vivswan/genkan/commit/33b68a624b02e39806fd13f03f576ff6ba2930bd))
* **desktop:** correlate confirm rows and keep green out of the audit ledger ([043ec75](https://github.com/Vivswan/genkan/commit/043ec7588a29b0caded195e8a25765267d9e5696))
* **desktop:** green means live+attested only; fail closed on stale status ([7401d5a](https://github.com/Vivswan/genkan/commit/7401d5a258d808ddbb31211d075b62c2cb719204))
* **desktop:** make first-launch registration opt-in and browser actions truthful ([8e48e88](https://github.com/Vivswan/genkan/commit/8e48e88e8a275fbc05687b07861b47bf98669b53))
* **desktop:** render the enclave fingerprint in the extension's lowercase form ([6a55a23](https://github.com/Vivswan/genkan/commit/6a55a23742d1560a2f2a152accef0bb785f50244))
* **desktop:** render unreadable kill and rejected key honestly on Overview ([c98a59e](https://github.com/Vivswan/genkan/commit/c98a59ee37d57b2cfdaefc210ebd5fbe47b70a26))
* **desktop:** wrap long paths and commands on the Setup page ([6f5c479](https://github.com/Vivswan/genkan/commit/6f5c4791556e86faa60d11cc9e7e3fb3a3481fb7))
* **dev:** fail closed on the two dev-browser ownership gaps the gate found ([90e2549](https://github.com/Vivswan/genkan/commit/90e2549eb0b7dfd9a3ec22a30b5cd503dc349e24))
* **dev:** pin the astro dev server lifecycle: stop stale servers, no auto-daemonization ([8a3c814](https://github.com/Vivswan/genkan/commit/8a3c814f9c295536291e16bd79402dad85bd8c50))
* **dev:** sweep the tauri process group when its leader dies; docs match the 12-verb list ([3fb0556](https://github.com/Vivswan/genkan/commit/3fb0556b75a651a3335662b67fd4dd3a59ce4d31))
* **doctor:** require the app bundle for macOS browser detection ([cfb7e0d](https://github.com/Vivswan/genkan/commit/cfb7e0d629a5c6ee2669ddb75333574079612ebb))
* drop retired options-page release from messages and docs ([829d7bf](https://github.com/Vivswan/genkan/commit/829d7bf7ed4d4e3fec49cbcb69b44c65f1caf1bc))
* **extension:** announce, localize, and animate the in-page notice ([7ea5879](https://github.com/Vivswan/genkan/commit/7ea5879038c89c189fdfa3fd91a9781787022888))
* **extension:** bind confirmed ops to their origin and parse reply envelopes fail-closed ([#25](https://github.com/Vivswan/genkan/issues/25)) ([7bb7be1](https://github.com/Vivswan/genkan/commit/7bb7be1da4a6297252a5bb06b455c81b6328081b))
* **extension:** disarm pending-origin Allow unless kill state reads alive ([2c122a7](https://github.com/Vivswan/genkan/commit/2c122a72c9628bb9eca696088cd69c6f698f7bd4))
* **extension:** fail-closed popup kill display and pairing-first hierarchy ([abd50f4](https://github.com/Vivswan/genkan/commit/abd50f424653f176a7d5d4d6eb04d62687e0434f))
* **extension:** gate every runtime message behind an extension-page sender ([#32](https://github.com/Vivswan/genkan/issues/32)) ([df31d9c](https://github.com/Vivswan/genkan/commit/df31d9cec8e24fed4213ebca1831fda49fa52caa))
* **extension:** gauntlet copy pass across all three locales ([3b9ea0b](https://github.com/Vivswan/genkan/commit/3b9ea0ba987fbc7b0d582ac919cbc63b775d5d2f))
* **extension:** harden policy consumption core against replay, pin-transition, and recovery races (ADR-0032 phase 3) ([fcc6d37](https://github.com/Vivswan/genkan/commit/fcc6d37daf59a3e546b2831705910e878f6afc1b))
* **extension:** harden the confirm window's content honesty ([e01f7ab](https://github.com/Vivswan/genkan/commit/e01f7ab939a6c825a38044fe51f70c4cb6fa6c2c))
* **extension:** keep confirm decision controls on screen under long payloads ([2de5f41](https://github.com/Vivswan/genkan/commit/2de5f41308a335b183ced21806a09bb4ff356550))
* **extension:** options honesty, hierarchy, and a11y ([f7d2b3c](https://github.com/Vivswan/genkan/commit/f7d2b3cc2a8f8ad58247f3a027a0d3e6902b0658))
* **extension:** parse enclave_error frames with their declared schema ([f361109](https://github.com/Vivswan/genkan/commit/f36110957f4304c942107745992d82c9a10f81f3))
* **extension:** pinned fresh pairing supersedes a stale host-key revoke ([13a44cc](https://github.com/Vivswan/genkan/commit/13a44ccf535beb4c2bf670f91d0af994656471b2))
* **extension:** the in-life cell moves to lib/shared, so the locale cache draws no background edge ([#194](https://github.com/Vivswan/genkan/issues/194)) ([63cf5f0](https://github.com/Vivswan/genkan/commit/63cf5f01270af450ff52c0c13a6c55c6d7690b2c))
* **fsguard:** compile warning-free on windows ([c9294ea](https://github.com/Vivswan/genkan/commit/c9294ea6e584b5218b1babe34e2ee48b8e8b43bd))
* **fuzz:** pin the fuzz workspace lock and check it with --locked ([#93](https://github.com/Vivswan/genkan/issues/93)) ([4ece34a](https://github.com/Vivswan/genkan/commit/4ece34ac024ded79607a996a1870901bce224980))
* **fuzz:** the seed writer creates the dictionary directory it writes into ([#210](https://github.com/Vivswan/genkan/issues/210)) ([2db6db3](https://github.com/Vivswan/genkan/commit/2db6db3df9deba9452f87dddb8bb7ada39c1ee85))
* **gen:** harden union handling and the adversarial harness per cross-model review ([0aff9e4](https://github.com/Vivswan/genkan/commit/0aff9e455d923f2bf63bab9ab1a0f9a7ec1d6e07))
* **harness:** the protocol suites remove their runtime dirs on every exit path and sweep their own stale ones ([#207](https://github.com/Vivswan/genkan/issues/207)) ([e20e686](https://github.com/Vivswan/genkan/commit/e20e68633fe230901df9c93814755dd25f6443ce))
* **host:** surface and audit legacy-import receipts so an arriving bag is never silently lost (ADR-0032 phase 4) ([e4be020](https://github.com/Vivswan/genkan/commit/e4be020a2e2db9d622e4c694b70dc0ae1d8e1ed4))
* **host:** sync the consumed tombstone through a writable handle for Windows (ADR-0032 phase 4) ([ebaf587](https://github.com/Vivswan/genkan/commit/ebaf58779b0d689d2cdf54435f78e6380db20160))
* **i18n:** English as the canonical language on every surface ([94bb64e](https://github.com/Vivswan/genkan/commit/94bb64ef03962087e99d5488515aaa7d710f08dc))
* **just:** restore ci's one-line doc string in just --list ([27fc787](https://github.com/Vivswan/genkan/commit/27fc7874780ad39eb3e176114e964a71c9047aa4))
* **kill:** drain and clear the browser registry in the sweep itself, not via reader wakeup ([bdb4fae](https://github.com/Vivswan/genkan/commit/bdb4fae578756625930b1f315a5daaaaf631840f))
* **kill:** harden the confirm-window panic-latch release lifecycle ([c6fb844](https://github.com/Vivswan/genkan/commit/c6fb8446e02ae26a384611250605ef9a38bab619))
* **kill:** require an authoritative killed frame for panic-latch refusal proof ([c32f065](https://github.com/Vivswan/genkan/commit/c32f06508961665d86ad710a209aefcf463bd74f))
* **mcp:** keep invalid-opener refusals off the wire under rmcp 3.2 ([e7ebe34](https://github.com/Vivswan/genkan/commit/e7ebe34ee8cf3ec0ba639b9fafb93983d6449b3a))
* point extension tsconfig at jest-dom 7's vitest types entry ([06a8279](https://github.com/Vivswan/genkan/commit/06a8279106943826dde2da02da619d5014a7f93d))
* **registration:** brave on macOS reads Chrome's per-user manifest directory, so its row points there ([#206](https://github.com/Vivswan/genkan/issues/206)) ([236aea8](https://github.com/Vivswan/genkan/commit/236aea8d3ffd986e8c9921d17b4e8064e1798a61))
* **release:** DMG art speaks the Gatedeck deck language ([faca827](https://github.com/Vivswan/genkan/commit/faca827455d0b256fa85d8469b426be38a6cfd67))
* **release:** publish the extension zip from an explicit macos-only step ([b33a7ab](https://github.com/Vivswan/genkan/commit/b33a7aba625bd19aa0b3619c090888774f856e76))
* **release:** the homebrew job reads the draft release, so the tap bump can open ([#187](https://github.com/Vivswan/genkan/issues/187)) ([0a9ebe1](https://github.com/Vivswan/genkan/commit/0a9ebe1416262ce749d14abe24b4648cbabec116))
* **runbook:** phase8-touchid-proof must use the signed bundle host ([d8d5d24](https://github.com/Vivswan/genkan/commit/d8d5d24a3ed3bff29997ad7e751c85dc6968d492))
* **runbook:** touchid-gates prints the CLI capability-grant steps ([5244855](https://github.com/Vivswan/genkan/commit/5244855cd66713d6064d531afc6aa2fee6958ce0))
* **scripts:** parse hasher.ignorePatterns with Bun.YAML instead of a regex line scan ([acad61b](https://github.com/Vivswan/genkan/commit/acad61b1499b6062fd5d81f42f96484c70305260))
* **site:** correct security claims and install steps to match the docs ([f19b5da](https://github.com/Vivswan/genkan/commit/f19b5da8943efdad21d13266f1a60afb3f377931))
* **site:** scope the Enclave and enrollment claims to what the docs support ([585f779](https://github.com/Vivswan/genkan/commit/585f779682704bf778cc7678f9403def9d744142))
* **site:** send relative directory links to the GitHub tree instead of 404 routes ([03af2b0](https://github.com/Vivswan/genkan/commit/03af2b0b0e9e7e76b708dad6d02b36326efe07da))
* **site:** the bridge has no silent enrollment path (scope to what ADR-0031 claims) ([bc95e62](https://github.com/Vivswan/genkan/commit/bc95e627e92a00161f3413842b5ccc445a70d3f8))
* teach both cargo-deny license gates about the source-available relicense ([9a21046](https://github.com/Vivswan/genkan/commit/9a2104688cb42ea040a0f1a620e779e0d9e83a25))
* **test:** make cli and registration path fixtures Windows-correct ([8097948](https://github.com/Vivswan/genkan/commit/80979484f84dd88a78558893395aa9a38f7d29d9))
* **tests:** await Page.loadEventFired in the CDP client instead of fixed sleeps ([8af6420](https://github.com/Vivswan/genkan/commit/8af6420a9d26f051b3ce4320b56277ab8082ea76))
* **tests:** bound every browser-harness await and give CI jobs timeouts ([8db90f1](https://github.com/Vivswan/genkan/commit/8db90f12f3dc33e7970c0980f5bab5119d3ac841))
* **tests:** browser suites wait for the DevTools page target instead of reading the list once ([#134](https://github.com/Vivswan/genkan/issues/134)) ([969b78c](https://github.com/Vivswan/genkan/commit/969b78cf1faf1713de928c92e720f627089793d8))
* **tests:** make server_stderr non-blocking on a live server; drop the duplicate accessor ([72d3f8e](https://github.com/Vivswan/genkan/commit/72d3f8eb656b80146c7c755ae20fb2fd11acbf4e))
* **tests:** point the options-page browser assertions at the slimmed surface (ADR-0032 phase 5) ([06b377f](https://github.com/Vivswan/genkan/commit/06b377fc363b86bc3967808a6f27dfd6089235d3))
* **tests:** state the true native-messaging gap (no host registration) and probe it ([7baf389](https://github.com/Vivswan/genkan/commit/7baf389454c07222b35cd992fb204c49e574faf1))
* **typography:** replace look-alike punctuation in Rust sources with ASCII ([9f2164a](https://github.com/Vivswan/genkan/commit/9f2164a00914ad5cfe246ef6eeff1cee6c696b0b))
* **typography:** replace stray em-dashes/ellipses with ASCII; shrink .typography-allow to exact paths ([89bd345](https://github.com/Vivswan/genkan/commit/89bd345128c4828862a8bccb439462008249dade))
* **web:** allowlist the rendered root docs instead of denylisting scratch notes ([a1eaa99](https://github.com/Vivswan/genkan/commit/a1eaa993dca727a68d0d4be35cdf42f22d1e5005))
* **web:** fail the build on a trailing-slash md link to a non-directory ([71c444c](https://github.com/Vivswan/genkan/commit/71c444c3756174304c2a8bea366d41f4a0737336))
* **web:** send every relative repo link to GitHub and keep ASCII punctuation ([#60](https://github.com/Vivswan/genkan/issues/60)) ([d02623b](https://github.com/Vivswan/genkan/commit/d02623bd39d83f31b714004d7a540522da05b72d))
* **web:** size the confirmation screenshot to its own width ([#133](https://github.com/Vivswan/genkan/issues/133)) ([7d4e608](https://github.com/Vivswan/genkan/commit/7d4e608b8edcdcb09f0ff6c65cc77daa2712fd83))


### Miscellaneous Chores

* relicense to the Individual and Small Organization License 1.0.0 ([d4731c1](https://github.com/Vivswan/genkan/commit/d4731c1a16a97a18d24c1fe6f491ea64ad1dbeeb))


### Build System

* make moon the canonical command interface and adopt proto ([adb5995](https://github.com/Vivswan/genkan/commit/adb5995864af10c3760103b53c41045064ad04f2))

## [Unreleased]

Engineering-standardization overhaul, plus a round of extension features and UX
polish: an opt-in CDP execution mode, per-action confirmation toggles, an
extension-ID self-check, restyled confirmations, and dark mode.

### Added
- Unified `Makefile` task runner (`build`, `fmt`, `lint`, `test`, `ci`,
  `ext-*`, `install`).
- Rust unit tests for the protocol framing, bridge envelope, lock file, tool
  schemas, and error display.
- Leveled stderr logging gated by `BB_LOG` (`error|warn|info|debug`, default
  `info`).
- TypeScript + esbuild build pipeline for the extension (`extension/src/*.ts`
  → `extension/dist/`), with `@types/chrome`, ESLint (flat config), and
  Prettier.
- GitHub Actions CI (`rust`, `extension`, `version-consistency`, `e2e`,
  `browser` jobs).
- `scripts/check-version.sh` and `scripts/sync-version.sh` to keep the crate
  and extension versions in lockstep (Cargo.toml is the source of truth).
- `LICENSE` (Apache-2.0), `CONTRIBUTING.md`, `docs/development.md`,
  `.editorconfig`.
- **Prebuilt release tarballs** - tagging `v*` triggers a GitHub Actions release
  build (macOS Apple Silicon) that publishes a binary + built extension +
  installer. `install.sh` auto-detects a prebuilt tarball and installs with no
  Rust/Node toolchain. The matrix also builds Linux x64 and Windows x64, each
  with a `.sha256` checksum and SLSA build-provenance attestation, plus a
  standalone extension zip; a decoupled workflow attaches a CycloneDX SBOM.
- **Opt-in CDP execution mode** (`cdpMode`, off by default) - routes every page
  op through `chrome.debugger` (CDP) in the page's main world instead of the
  content script, which **bypasses page CSP** so `page_eval` works on strict-CSP
  sites (e.g. Bing). Keeps every confirmation/allowlist/masking gate. A
  persistent debugger attach shows Chrome's "Started debugging this browser"
  banner while enabled. (ADR-0017)
- **`confirmPageEval` / `confirmTabClose` settings** - opt out of the per-call
  confirmation for `page_eval` / `tab_close` for hands-off automation. Both
  default on, so behavior is unchanged unless you turn them off.
- **Extension-ID self-check** - the service worker logs a loud `[bb]` error at
  startup when the running extension ID ≠ the pinned ID, the most common
  "won't connect" cause (native-messaging `allowed_origins` mismatch).
- **Dark mode** for the options and popup pages (`prefers-color-scheme`).
- **macOS Gatekeeper**: the installer clears the `com.apple.quarantine`
  attribute on the installed binary so a browser-downloaded build isn't silently
  blocked when Chrome spawns the native host.
- Docs: a Chrome Web Store publication checklist (`docs/chrome-web-store.md`) and
  a privacy policy.

### Changed
- **Installers moved to `install/`** (`install/install.sh`, `install/install.ps1`,
  `install/mcp-config.example.json`) to slim the repository root. Release archives
  are unchanged - they still ship the installer flat at the archive root, so the
  extract-and-run flow (`./install.sh`) is the same. From a source checkout, run
  `./install/install.sh`. Each installer auto-detects whether it sits beside
  `extension/` (release archive) or one level up (source tree).
- **Extension ID is now pinned** via a public `key` in the manifest
  (`mkjjlmjbcljpcfkfadfmhblmmddkdihf`), so it's the same for everyone
  regardless of load path. `install.sh` writes the host manifest with that ID
  directly - **no more "copy the extension ID and re-run with --extension-id"**.
  (`--extension-id` remains as an override.)
- **Decoupled from ZCode - now generic across MCP clients** (Claude Code, Codex,
  any MCP client). The server already spoke standard MCP; this is a naming/docs
  change plus two identifier renames:
  - **Native host id `com.zcode.browser_bridge` → `com.browser_bridge.host`**
    (breaking: reinstall the host manifest via `install.sh`, and the manifest
    file is now `com.browser_bridge.host.json`).
  - Example config `zcode-mcp-config.json` → `mcp-config.example.json` (generic
    `mcpServers` shape); README documents Claude Code / Codex / generic setup.
- **Load-unpacked target moved from `extension/` to `extension/dist/`** (the
  build output). `install.sh` now builds the bundle; update your unpacked
  extension path accordingly.
- Rust errors on the tool-call path are now typed (`thiserror`) instead of
  strings.
- Signal handling: `SIGTERM`/`SIGINT` now trigger a graceful shutdown that
  removes the lock file (via a `libc` `sigwait` thread); scattered hand-rolled
  `extern "C"` shims collapsed onto `libc`.
- **README redesigned** - security-first intro, a prebuilt-first 60-second
  quickstart, the accurate 15-tool catalogue grouped by risk, plus
  configuration and troubleshooting sections.
- **Confirmation toasts restyled** - one consistent size (360px) across all of
  them; high-risk confirmations (submit/navigate click, `tab_close`, `page_eval`)
  now use a red danger theme, while the informational toast stays blue.
- **Installer UX** - prints the fully-resolved `claude mcp add ...` command and
  can auto-register with Claude Code when its CLI is present.
- Repository tidy: `deny.toml` moved to `ci/deny.toml`; the remaining root files
  are documented in `GOVERNANCE.md` as reference-locked (required at root by a
  tool or convention).

### Fixed
- The core's JSON stores read back exactly the number they wrote: serde_json
  now parses floats correctly rounded (`float_roundtrip`), closing a one-ulp
  drift the nightly fuzzer found on an integer literal past i64.
- `page_fill` no longer sends a bogus "masked" copy of the value alongside the
  real one; a single `value` key is sent.
- The bridge session clears its writer on disconnect so the next tool call
  waits for a fresh host to reconnect instead of writing into a dead socket.
- Removed dead code (`is_connected`, an empty reserved `SENSITIVE_HOSTS`, a
  duplicate unused `STORAGE_KEY`).
- **Release workflow** pins `actions/checkout` to the released tag, so a manual
  `workflow_dispatch` run builds (and signs/labels) the tag rather than `main`.

### Dependencies
- Added `libc` and `thiserror` (Rust); esbuild/TypeScript/ESLint/Prettier
  toolchain (extension dev-dependencies).

## [0.1.0]

Initial implementation: Rust single-binary MCP server + `--native-host` bridge,
MV3 extension, and the v0.1 tool set (tab management, page snapshot/click/fill/
text/screenshot/scroll/wait, `page_eval`, `page_snapshot_precise`, `cookie_get`,
`storage_get`). See `docs/` for the requirements, architecture, and ADRs.
