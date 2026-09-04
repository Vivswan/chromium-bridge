# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2026-09-04)


### ⚠ BREAKING CHANGES

* relicense to the Individual and Small Organization License 1.0.0
* the justfile is gone - use moon run <task> (moon run help lists everything); local checkouts need proto (proto install) since moon is no longer an npm devDependency.
* **extension:** off-DOM confirmations on an extension-owned surface + single page-API source
* **extension:** rebuild on WXT with a generated, contract-pinned manifest
* carve out a cargo workspace and rebrand to chromium-bridge

### Features

* add cookie_get + storage_get (read-only) ([2f8d526](https://github.com/Vivswan/chromium-bridge/commit/2f8d526c6f0b8124fa5ec0f5a2bd18db4c68a960))
* add host-owned policy core, signing domain, and control frames (ADR-0032 phase 1) ([9de69e4](https://github.com/Vivswan/chromium-bridge/commit/9de69e4a6323af1759510c0cf2ee3586854d4b03))
* add Linux and WSL support ([#13](https://github.com/Vivswan/chromium-bridge/issues/13)) ([516348b](https://github.com/Vivswan/chromium-bridge/commit/516348b2235c3580e03198199bdf16d0b25a0ff9))
* add native Windows support ([ec60efd](https://github.com/Vivswan/chromium-bridge/commit/ec60efd8ce5e4746cb17516de1d7143004c90108))
* add Options page for centralized settings management ([03d5541](https://github.com/Vivswan/chromium-bridge/commit/03d554136d51d5cf810347a3ff0bee5b43ea6585))
* add page_eval high-risk confirmation channel ([7401462](https://github.com/Vivswan/chromium-bridge/commit/740146289c9eddcc8fd095dca0a1c1e974049199))
* add page_snapshot_precise via chrome.debugger (CDP) ([91d94c1](https://github.com/Vivswan/chromium-bridge/commit/91d94c196c1cb6f80e8898bdf46eeeceeb37adca))
* answer policy frames, gate dispatch, add policy CLI (ADR-0032 phase 2) ([a1354ce](https://github.com/Vivswan/chromium-bridge/commit/a1354ce847c3af8e0293be4e7d41d8d47413067d))
* **app:** first-run legacy import, unenrolled floor, and language sync (ADR-0032 phase 4) ([b3b9d1a](https://github.com/Vivswan/chromium-bridge/commit/b3b9d1a6585ff39458b44aa3c6a97d91c9536ddd))
* **broker:** concurrent multi-client pairing with a ref-counted attested broker ([d885caf](https://github.com/Vivswan/chromium-bridge/commit/d885cafa41eea6939d5192a17c0e32935a029b8c))
* **build:** adopt moon as the task orchestrator under the justfile (phase one) ([e74e656](https://github.com/Vivswan/chromium-bridge/commit/e74e65628415ba0e507b37b8bf689d91f3f3414a))
* **ci:** add SSoT parity gates for docs, adversarial tests, fuzz seeds, and the browser job ([#28](https://github.com/Vivswan/chromium-bridge/issues/28)) ([efc32c8](https://github.com/Vivswan/chromium-bridge/commit/efc32c88f093cef0a71475e82d63b262ce15720b))
* **ci:** persist and minimize the fuzz corpus nightly ([d24e214](https://github.com/Vivswan/chromium-bridge/commit/d24e2145d1ec0b3061f356d697f0581ab0f68a34))
* **cli:** doctor --fix + uninstall on a shared browser-path resolver ([53776ed](https://github.com/Vivswan/chromium-bridge/commit/53776edfe25dbd8b26a650b82837373e2e2815c9))
* **cli:** read-only doctor/status subcommand ([70ee7bb](https://github.com/Vivswan/chromium-bridge/commit/70ee7bb99401d3591109206cfa09909f91f7bc3e))
* **contract:** emit audit forwarding, writer frame types, and the MCP version from the core ([#29](https://github.com/Vivswan/chromium-bridge/issues/29)) ([00495ae](https://github.com/Vivswan/chromium-bridge/commit/00495ae7d88b0f5b86314f59d8f1e8e15595ca35))
* **contract:** generate the envelope wire validators from the Rust schemas ([dc3b4c5](https://github.com/Vivswan/chromium-bridge/commit/dc3b4c58b9a1c65a85e32e05bae3d1ea98b13edd))
* contracts/tools.json as the single source for the tool catalogue (P1) ([93bc70c](https://github.com/Vivswan/chromium-bridge/commit/93bc70cadfae49d847a70746f807df34f2f115a8))
* **contracts:** Zod boundary validation and codegen/parity backbone ([b016a9e](https://github.com/Vivswan/chromium-bridge/commit/b016a9e9d7d893af7d9a73326a78de8432363846))
* **core:** emit the enclave contract and golden vectors to the shared TS package ([#30](https://github.com/Vivswan/chromium-bridge/issues/30)) ([afa07d9](https://github.com/Vivswan/chromium-bridge/commit/afa07d95ec9f19227a3eb8a6bee105b83ff7c256))
* **cutover:** retire install scripts, consolidate docs, add zh docs + docs site ([40fed60](https://github.com/Vivswan/chromium-bridge/commit/40fed600eab370eaf072b35d67ee98e2ab233006))
* desktop app policy editor and signed grant lane (ADR-0032 phase 2) ([8d68aba](https://github.com/Vivswan/chromium-bridge/commit/8d68aba2320b092363a5f3bccb6b72d5c63ea3bd))
* **desktop:** app-confirm dialogs and phase8 presence-contract alignment ([06c3d77](https://github.com/Vivswan/chromium-bridge/commit/06c3d7702f661c66914e3870f37e2b1afe7c382f))
* **desktop:** control-panel app UI over the core management engines (ADR-0029) ([d088d10](https://github.com/Vivswan/chromium-bridge/commit/d088d100f867eeca995a7cdf5df910bb79bdec3c))
* **desktop:** generate the UI's Tauri command types from Rust via ts-rs ([d60343a](https://github.com/Vivswan/chromium-bridge/commit/d60343acaa5172e1fc08a9b61307008263226558))
* **desktop:** overview lifecycle states per the first-run spec ([5037e3d](https://github.com/Vivswan/chromium-bridge/commit/5037e3daaec9049537111b84600d75c50b8508d0))
* **desktop:** prove the signed-host entitlement chain (Tauri v2 spike) ([f6a8552](https://github.com/Vivswan/chromium-bridge/commit/f6a85529f5a521ad25698d0f6da620281e35c121))
* **desktop:** rebuild UI to the Control Tower design ([4e5cc2a](https://github.com/Vivswan/chromium-bridge/commit/4e5cc2a43819f1b13293a8b0e3794c60ae9fd9c4))
* **desktop:** wire the presence gates onto the landed phase8 API (Floor::AppConfirm) ([e6c1112](https://github.com/Vivswan/chromium-bridge/commit/e6c111210d5637e359b42682a2536e4dfdfdd020))
* **dev:** docs tab + pinned toolbar icon in the WXT dev browser, enforced fresh-profile isolation ([b4b8c34](https://github.com/Vivswan/chromium-bridge/commit/b4b8c34f07bda821d50ea4be0d41ace05925c7c6))
* **dev:** just dev also runs the desktop app; cut just --list to 12 top-level verbs ([94434f7](https://github.com/Vivswan/chromium-bridge/commit/94434f714ba3ebdb57de849ec0e89c9e2416c80f))
* **dev:** just dev runs the extension and site together; build includes the site ([b2bd354](https://github.com/Vivswan/chromium-bridge/commit/b2bd354a408548b403e7563bf75269dc0882f249))
* **dispatch:** route disable-gate through policy.decide ([c61d1de](https://github.com/Vivswan/chromium-bridge/commit/c61d1de4b33fa9f151cbc546b65316ec754b4825))
* **doctor:** note that green checks don't confirm the extension connected ([#34](https://github.com/Vivswan/chromium-bridge/issues/34)) ([f2710ab](https://github.com/Vivswan/chromium-bridge/commit/f2710ab98eeefe6943ab5059fd0cf1b6e97e941b))
* **enclave:** add the Secure Enclave enrollment ceremony (host side) ([cccc7d2](https://github.com/Vivswan/chromium-bridge/commit/cccc7d2dd7fceb83d6beb0486e07e72fccf819ef))
* **error:** map CallError to contracts/errors.json codes ([e900d41](https://github.com/Vivswan/chromium-bridge/commit/e900d4136698bf8c714499cf89b6c1ae8ddddf2d))
* **ext:** bundle JetBrains Mono for identity material ([07ac483](https://github.com/Vivswan/chromium-bridge/commit/07ac4838c021dd2acf4014aff2106adff6902cdc))
* extension policy consumption core (ADR-0032 phase 3) ([bb48ad4](https://github.com/Vivswan/chromium-bridge/commit/bb48ad4779199490ed1ff87e49bdd6ce091cf055))
* **extension:** add confirmPageEval / confirmTabClose toggles ([#39](https://github.com/Vivswan/chromium-bridge/issues/39)) ([ed13d55](https://github.com/Vivswan/chromium-bridge/commit/ed13d55bb810424d291b86f802d6661cbbbda019))
* **extension:** add opt-in CDP mode for all page ops ([#37](https://github.com/Vivswan/chromium-bridge/issues/37)) ([ec6d380](https://github.com/Vivswan/chromium-bridge/commit/ec6d3809335817e8d1732ec68aeb3a6ce3e875a5))
* **extension:** add opt-in lazy host re-verification interval ([eb5e1f0](https://github.com/Vivswan/chromium-bridge/commit/eb5e1f0af440b94e244a6f1952f80f9269689a3e))
* **extension:** apply and emit language sync per ADR-0032 decision 7 (phase 4) ([748a2a2](https://github.com/Vivswan/chromium-bridge/commit/748a2a2989a0b8b7477876285497d49784812d4d))
* **extension:** compact engage-only kill control in the confirm window ([9968ee7](https://github.com/Vivswan/chromium-bridge/commit/9968ee7fd3e813a9ab19e6abee4fedf760b9b55c))
* **extension:** enforce host policy at every capability site via state-typed snapshots (ADR-0032 phase 3) ([ea21e50](https://github.com/Vivswan/chromium-bridge/commit/ea21e504945e0b016e1fca336b364c1a8ab82427))
* **extension:** group AI-opened tabs into a "Browser Bridge" workspace ([#44](https://github.com/Vivswan/chromium-bridge/issues/44)) ([a06387f](https://github.com/Vivswan/chromium-bridge/commit/a06387f2614fbe128d5c3882d2b43b01071c569e))
* **extension:** isolate trust state from content scripts ([#32](https://github.com/Vivswan/chromium-bridge/issues/32)) ([a4cf49a](https://github.com/Vivswan/chromium-bridge/commit/a4cf49a063259f09637d6ee6f179ff3eace9968d))
* **extension:** localize tool labels through the i18n bundle ([4d33fa5](https://github.com/Vivswan/chromium-bridge/commit/4d33fa5e961a919696988ddbce0b47f8ac12d592))
* **extension:** log a loud warning when the running ID ≠ pinned ID ([#38](https://github.com/Vivswan/chromium-bridge/issues/38)) ([04ca518](https://github.com/Vivswan/chromium-bridge/commit/04ca5182fccb8c0bb712f3fe1c17e4f857292bf3))
* **extension:** mask long opaque tokens in eval/cookie/storage output ([0502a2b](https://github.com/Vivswan/chromium-bridge/commit/0502a2bff48aa16f457a05597d2cd8e5303c316b))
* **extension:** off-DOM confirmations on an extension-owned surface + single page-API source ([749fb19](https://github.com/Vivswan/chromium-bridge/commit/749fb1981ffe732202d88d890143a8da3b067ae8))
* **extension:** pin the enrollment key and fail closed until paired (ADR-0021) ([bde3f6d](https://github.com/Vivswan/chromium-bridge/commit/bde3f6daebab0a5758e3fdd5bdf5158c8c71b827))
* **extension:** rebuild on WXT with a generated, contract-pinned manifest ([fb4b8fc](https://github.com/Vivswan/chromium-bridge/commit/fb4b8fcc1620b07a073d812f876b6d0ba0c1c0b1))
* **extension:** retire the migrated legacy settings surface (ADR-0032 phase 5) ([dbb5b87](https://github.com/Vivswan/chromium-bridge/commit/dbb5b87d2204e205f63731858b8dfc3791e1896b))
* **extension:** send the legacy settings bag once to a pinned host that proved key possession (ADR-0032 phase 4) ([341cbaf](https://github.com/Vivswan/chromium-bridge/commit/341cbaf387706d699a9193cc271e2b3a025b26e1))
* **extension:** trilingual runtime i18n + React/Radix/Tailwind UI rehaul ([d11c3f9](https://github.com/Vivswan/chromium-bridge/commit/d11c3f9fc65f53926f945b87d7ac09a529ca248c))
* **extension:** unpinned-window policy approval lane with anchor-preserving commit (ADR-0032 phase 3 lane U) ([4d25e6e](https://github.com/Vivswan/chromium-bridge/commit/4d25e6ea6ad3456aa4e1ac0ed92133f71e75ed35))
* **ext:** first-run popup pairing state per the first-run spec ([874627b](https://github.com/Vivswan/chromium-bridge/commit/874627b0efa62591584a2db54c12276b5ee688f2))
* **ext:** rebuild popup, options, and confirm on the Control Tower design ([6248ac4](https://github.com/Vivswan/chromium-bridge/commit/6248ac4132ce3fd05cbcd47eddf0c0084ef0998c))
* **ext:** restyle the in-page info toast to the Control Tower layout ([1695192](https://github.com/Vivswan/chromium-bridge/commit/16951929f6a7f6961f56dc2209644595809f7b10))
* **ext:** restyle the shared UI primitives to Control Tower motifs ([8d8f3d3](https://github.com/Vivswan/chromium-bridge/commit/8d8f3d395285ea1b14c7bce1f44429cb1eb0d119))
* file nightly fuzz crashes as tracking issues with seeded replay ([588e342](https://github.com/Vivswan/chromium-bridge/commit/588e342460667cacbe10811aee3536ec167350b7))
* **fuzz:** add classify_frame, enclave, and manifest targets ([7efa002](https://github.com/Vivswan/chromium-bridge/commit/7efa002a39a5e390633bbcc60e6ced8e5f43d1b8))
* **fuzz:** add fuzzing feature and handshake_verify target ([7c7b66a](https://github.com/Vivswan/chromium-bridge/commit/7c7b66a1a4a80cd88b734643c77db0d8873f2342))
* **fuzz:** seed corpora and dictionaries ([194b433](https://github.com/Vivswan/chromium-bridge/commit/194b4338773b745f2def3bd128a0fc3f20d56fe2))
* **host:** pending-import store and structured policy reason for legacy migration (ADR-0032 phase 4 host) ([aaa3c38](https://github.com/Vivswan/chromium-bridge/commit/aaa3c38d983b8830da747062e43fb71863e133f9))
* **icons:** generate Gatedeck icon assets from SVG sources at build time ([5796d4d](https://github.com/Vivswan/chromium-bridge/commit/5796d4dd90dd0492d27c19d0e4d1390b0f7acda1))
* implement browser-bridge v0.1 (Rust + MV3 extension) ([1871420](https://github.com/Vivswan/chromium-bridge/commit/187142090a4db6807bc5a0222ce8343a7eb8a21a))
* **install:** clear macOS Gatekeeper quarantine on the installed binary ([#31](https://github.com/Vivswan/chromium-bridge/issues/31)) ([6a8f7b6](https://github.com/Vivswan/chromium-bridge/commit/6a8f7b6d2ddc509bc5fde068c576b14851ddb1a6))
* **install:** per-browser run-host wrappers carrying --label ([a5ea816](https://github.com/Vivswan/chromium-bridge/commit/a5ea816851530c5254670430a2c7627eb7e6216e))
* **install:** print resolved client config and optional Claude Code auto-register ([#33](https://github.com/Vivswan/chromium-bridge/issues/33)) ([096a9c5](https://github.com/Vivswan/chromium-bridge/commit/096a9c589da8043e5f06be5a228a0cb814327258))
* **install:** support any Chromium browser via a native-messaging host table ([7797e17](https://github.com/Vivswan/chromium-bridge/commit/7797e17deced709fdbb4f7846341843e6ab22808))
* **install:** verify the prebuilt binary against the published checksum before install ([47be997](https://github.com/Vivswan/chromium-bridge/commit/47be9976d60e1cee23a5d464b05477ca41d593b5))
* **ipc:** attest bridge peers by kernel-verified executable identity ([2d6c08d](https://github.com/Vivswan/chromium-bridge/commit/2d6c08d4446b1d5be6285cf3ae9989c0953a1531))
* **ipc:** attest macOS bridge peers by audit-token SecCode cdhash ([9e8fa23](https://github.com/Vivswan/chromium-bridge/commit/9e8fa234732cc5b44de998a5f78db2762394f37b))
* **ipc:** authenticate the bridge with an HMAC challenge-response ([f2db5f0](https://github.com/Vivswan/chromium-bridge/commit/f2db5f06237248ed267462c7c60ae33a99f796e2))
* **ipc:** reject cross-user peers via SO_PEERCRED/getpeereid ([f518803](https://github.com/Vivswan/chromium-bridge/commit/f5188035093129ded5e17f974fc631e75a9e984a))
* **ipc:** switch bridge transport to a 0600 unix domain socket ([289e033](https://github.com/Vivswan/chromium-bridge/commit/289e0336ba04860e133028c2378fa437f2b0fc40))
* **mcp:** warn loudly at startup that Windows bridge security is best-effort ([9005c29](https://github.com/Vivswan/chromium-bridge/commit/9005c294b8aa546aa44ec1e7b12dee0097c80227))
* migrate .repo-platform.yml to the modules schema ([#12](https://github.com/Vivswan/chromium-bridge/issues/12)) ([03aef09](https://github.com/Vivswan/chromium-bridge/commit/03aef095c0b2d853d194b69e99f1c3936b0b1d3c))
* migrate MCP server to spec 2026-07-28 on the official rmcp SDK ([5fc968b](https://github.com/Vivswan/chromium-bridge/commit/5fc968b790624e97606d2b273d20306432cb8b54))
* **observability:** per-call request ids + structured audit events ([edda161](https://github.com/Vivswan/chromium-bridge/commit/edda16132aa5863fdc50930a39c6da64251a8175))
* pin the extension ID (manifest key) — no more copy-ID install step ([4085c0a](https://github.com/Vivswan/chromium-bridge/commit/4085c0a756100d1d1e2858860c01e757318a57d2))
* **policy:** additive policy-layer foundation from tool contract ([f7c5985](https://github.com/Vivswan/chromium-bridge/commit/f7c5985c882d927cb0d81f47d15524eb6a52d567))
* prebuilt release pipeline — install without Rust/Node ([5b91bff](https://github.com/Vivswan/chromium-bridge/commit/5b91bff04f023f8fce0249bf93dd096307939ec9))
* **protocol:** reject unknown fields on all bridge wire types (fail closed) ([6935b87](https://github.com/Vivswan/chromium-bridge/commit/6935b8742aeada3e36e5fc9de9f4d9ba2caef80f))
* refine tool descriptions, protocol layer, and tab_close confirmation ([a9270e0](https://github.com/Vivswan/chromium-bridge/commit/a9270e0fa2ceeeebaed12b69017342876990d8fb))
* **release:** branded DMG with Gatedeck identity ([127d978](https://github.com/Vivswan/chromium-bridge/commit/127d9786684e89d07bb8c9c2ad5c4077fdeab938))
* **release:** build, verify, and publish the signed desktop .dmg ([6a7d51c](https://github.com/Vivswan/chromium-bridge/commit/6a7d51cc1bd4d9a3f79657547b05d84798882490))
* **security:** any-side revocation epoch (ADR-0025) ([8ae50c7](https://github.com/Vivswan/chromium-bridge/commit/8ae50c7d869b1cde9afa89f9ed776c798849ec7f))
* **security:** global kill switch, audit trail, and presence-gated unkill (ADR-0030) ([240abbc](https://github.com/Vivswan/chromium-bridge/commit/240abbc18252a7fc918bb1dea3556306cac69195))
* **security:** Touch ID presence gates for crown-jewel tools and capability grants (ADR-0031) ([905c5aa](https://github.com/Vivswan/chromium-bridge/commit/905c5aa96ee414283ba8b0f8a8a4c925532b7597))
* **session:** generation-guarded connection (RFC-0001) ([7701bf2](https://github.com/Vivswan/chromium-bridge/commit/7701bf2807deaa3ae88e059704a5af064eaf2108))
* **session:** hold multiple authenticated browser connections, routed by label ([82c6603](https://github.com/Vivswan/chromium-bridge/commit/82c66037fc66fdefe4e11d44c6245e10a09874bb))
* **site:** Control Tower landing page ([f12cb93](https://github.com/Vivswan/chromium-bridge/commit/f12cb935ba55fe57a95f429051e6fe7a3828b183))
* **tools:** add navigation, keyboard, hover, select, console, dialog, and file-upload tools ([22dcfaf](https://github.com/Vivswan/chromium-bridge/commit/22dcfafa4335bd6df7e99b87af13a2441b1a0852))
* **ui:** adopt Control Tower design tokens in both apps ([873d557](https://github.com/Vivswan/chromium-bridge/commit/873d55727f39f99b83eda089935c2c5f2a5e3471))
* wire policy and language frames into the envelope gate (ADR-0032 phase 3) ([3c93d2d](https://github.com/Vivswan/chromium-bridge/commit/3c93d2dfaee8e09e76b849032a919c4e33b5abeb))


### Bug Fixes

* **audit:** correlate confirmation rows by a per-confirmation id ([37e2914](https://github.com/Vivswan/chromium-bridge/commit/37e29140db006e43dd4ac5728cc332d3e2478bcc))
* **build:** tauri hooks run from the frontend dir; restore bun run dev/build ([3d92976](https://github.com/Vivswan/chromium-bridge/commit/3d9297670e0c8b2a24d329154f8706ef3b8ee7c3))
* **ci:** check out full history so moon can resolve the PR base ref ([b492c8f](https://github.com/Vivswan/chromium-bridge/commit/b492c8fb07f6549999af1a1df64790804e74f8db))
* **ci:** scope fuzz deny relaxations to a fuzz-only config ([dd8c5ad](https://github.com/Vivswan/chromium-bridge/commit/dd8c5ad0819b38c64384fe578b0a7d491f5097ef))
* **ci:** unbreak the first nightly run (fuzz musl target, mutants exit 3) ([3077647](https://github.com/Vivswan/chromium-bridge/commit/3077647291f99c37ad54289604ee204ca917405b))
* **contracts:** gate enclave/admin/client wire types in the envelope parity check ([f5ef9dd](https://github.com/Vivswan/chromium-bridge/commit/f5ef9dd3c7d062e4aa258ffe37cc4f29d1ebca3a))
* **core:** centralize secure file permissions in fsguard ([fc837cc](https://github.com/Vivswan/chromium-bridge/commit/fc837ccc17184e2b6ca6e28ec4ac47cff2932f55))
* **core:** drop the Windows delete-before-rename on security files ([172304a](https://github.com/Vivswan/chromium-bridge/commit/172304abff43bebfcec04673849490141feef67b))
* **core:** emit revocation audit record inside Allowlist::revoke ([20df4a5](https://github.com/Vivswan/chromium-bridge/commit/20df4a55444eb18b6bf987fd6c899b8c685fd96a))
* **core:** enforce trust-store preconditions and anchor validity in types ([#24](https://github.com/Vivswan/chromium-bridge/issues/24)) ([0e24ed2](https://github.com/Vivswan/chromium-bridge/commit/0e24ed269dbbcde1353b13084106012660c8afb8))
* **core:** gate Unix-only imports so Windows clippy is clean, and gate it in CI ([a346a45](https://github.com/Vivswan/chromium-bridge/commit/a346a453015d116061bb1549be245e27542055e4))
* **core:** harden the unsafe FFI quarantine per audit findings ([23044b9](https://github.com/Vivswan/chromium-bridge/commit/23044b91a97a322b8af5504fb239940941b61c94))
* **core:** write config.json via the hardened write_private_atomic ([cff0af5](https://github.com/Vivswan/chromium-bridge/commit/cff0af5dab9087837486cbd53d531b361c62e665))
* correctness + robustness hardening (Phase 0) ([04bde1a](https://github.com/Vivswan/chromium-bridge/commit/04bde1ab5ded544818f709e2f53e494d09a7bc69))
* cover desktop ui package.json in release-please and guard version sync ([#23](https://github.com/Vivswan/chromium-bridge/issues/23)) ([a3ff292](https://github.com/Vivswan/chromium-bridge/commit/a3ff292fa9de7d1123a301282e4dcd354e1f888e))
* **desktop:** a11y and interaction polish from the design gauntlet ([d3deb91](https://github.com/Vivswan/chromium-bridge/commit/d3deb91fa7db5e495c1c9eceb4355c9f25e67058))
* **desktop:** box the AuditLine::Record variant after cid grew AuditRecord ([33b68a6](https://github.com/Vivswan/chromium-bridge/commit/33b68a624b02e39806fd13f03f576ff6ba2930bd))
* **desktop:** correlate confirm rows and keep green out of the audit ledger ([043ec75](https://github.com/Vivswan/chromium-bridge/commit/043ec7588a29b0caded195e8a25765267d9e5696))
* **desktop:** green means live+attested only; fail closed on stale status ([7401d5a](https://github.com/Vivswan/chromium-bridge/commit/7401d5a258d808ddbb31211d075b62c2cb719204))
* **desktop:** make first-launch registration opt-in and browser actions truthful ([8e48e88](https://github.com/Vivswan/chromium-bridge/commit/8e48e88e8a275fbc05687b07861b47bf98669b53))
* **desktop:** render the enclave fingerprint in the extension's lowercase form ([6a55a23](https://github.com/Vivswan/chromium-bridge/commit/6a55a23742d1560a2f2a152accef0bb785f50244))
* **desktop:** render unreadable kill and rejected key honestly on Overview ([c98a59e](https://github.com/Vivswan/chromium-bridge/commit/c98a59ee37d57b2cfdaefc210ebd5fbe47b70a26))
* **desktop:** wrap long paths and commands on the Setup page ([6f5c479](https://github.com/Vivswan/chromium-bridge/commit/6f5c4791556e86faa60d11cc9e7e3fb3a3481fb7))
* **dev:** fail closed on the two dev-browser ownership gaps the gate found ([90e2549](https://github.com/Vivswan/chromium-bridge/commit/90e2549eb0b7dfd9a3ec22a30b5cd503dc349e24))
* **dev:** pin the astro dev server lifecycle: stop stale servers, no auto-daemonization ([8a3c814](https://github.com/Vivswan/chromium-bridge/commit/8a3c814f9c295536291e16bd79402dad85bd8c50))
* **dev:** sweep the tauri process group when its leader dies; docs match the 12-verb list ([3fb0556](https://github.com/Vivswan/chromium-bridge/commit/3fb0556b75a651a3335662b67fd4dd3a59ce4d31))
* **doctor:** require the app bundle for macOS browser detection ([cfb7e0d](https://github.com/Vivswan/chromium-bridge/commit/cfb7e0d629a5c6ee2669ddb75333574079612ebb))
* drop retired options-page release from messages and docs ([829d7bf](https://github.com/Vivswan/chromium-bridge/commit/829d7bf7ed4d4e3fec49cbcb69b44c65f1caf1bc))
* **extension:** announce, localize, and animate the in-page notice ([7ea5879](https://github.com/Vivswan/chromium-bridge/commit/7ea5879038c89c189fdfa3fd91a9781787022888))
* **extension:** bind confirmed ops to their origin and parse reply envelopes fail-closed ([#25](https://github.com/Vivswan/chromium-bridge/issues/25)) ([7bb7be1](https://github.com/Vivswan/chromium-bridge/commit/7bb7be1da4a6297252a5bb06b455c81b6328081b))
* **extension:** confirm the enrollment gate inside the transition queue ([8a09e0b](https://github.com/Vivswan/chromium-bridge/commit/8a09e0b1ffc9dc98df2d49b00ed313b1ca23493b))
* **extension:** disarm pending-origin Allow unless kill state reads alive ([2c122a7](https://github.com/Vivswan/chromium-bridge/commit/2c122a72c9628bb9eca696088cd69c6f698f7bd4))
* **extension:** fail-closed popup kill display and pairing-first hierarchy ([abd50f4](https://github.com/Vivswan/chromium-bridge/commit/abd50f424653f176a7d5d4d6eb04d62687e0434f))
* **extension:** gate every runtime message behind an extension-page sender ([#32](https://github.com/Vivswan/chromium-bridge/issues/32)) ([df31d9c](https://github.com/Vivswan/chromium-bridge/commit/df31d9cec8e24fed4213ebca1831fda49fa52caa))
* **extension:** gauntlet copy pass across all three locales ([3b9ea0b](https://github.com/Vivswan/chromium-bridge/commit/3b9ea0ba987fbc7b0d582ac919cbc63b775d5d2f))
* **extension:** harden policy consumption core against replay, pin-transition, and recovery races (ADR-0032 phase 3) ([fcc6d37](https://github.com/Vivswan/chromium-bridge/commit/fcc6d37daf59a3e546b2831705910e878f6afc1b))
* **extension:** harden the confirm window's content honesty ([e01f7ab](https://github.com/Vivswan/chromium-bridge/commit/e01f7ab939a6c825a38044fe51f70c4cb6fa6c2c))
* **extension:** keep confirm decision controls on screen under long payloads ([2de5f41](https://github.com/Vivswan/chromium-bridge/commit/2de5f41308a335b183ced21806a09bb4ff356550))
* **extension:** mask every page_eval egress, not just the success value ([db66568](https://github.com/Vivswan/chromium-bridge/commit/db66568a40e97e6122d8cc3aef6bc47746dd5ea3))
* **extension:** options honesty, hierarchy, and a11y ([f7d2b3c](https://github.com/Vivswan/chromium-bridge/commit/f7d2b3cc2a8f8ad58247f3a027a0d3e6902b0658))
* **extension:** parse enclave_error frames with their declared schema ([f361109](https://github.com/Vivswan/chromium-bridge/commit/f36110957f4304c942107745992d82c9a10f81f3))
* **extension:** pinned fresh pairing supersedes a stale host-key revoke ([13a44cc](https://github.com/Vivswan/chromium-bridge/commit/13a44ccf535beb4c2bf670f91d0af994656471b2))
* **extension:** reconfirm every page_eval by excluding it from the grace window ([da1ace4](https://github.com/Vivswan/chromium-bridge/commit/da1ace49d78cf672332d55d7049bbe8f5579a141))
* **extension:** scope enrollment enforcement to Enclave-capable platforms ([eb89be4](https://github.com/Vivswan/chromium-bridge/commit/eb89be4cbb8852dd8c4442f516f63e4f441af743))
* **fsguard:** compile warning-free on windows ([c9294ea](https://github.com/Vivswan/chromium-bridge/commit/c9294ea6e584b5218b1babe34e2ee48b8e8b43bd))
* **gen:** harden union handling and the adversarial harness per cross-model review ([0aff9e4](https://github.com/Vivswan/chromium-bridge/commit/0aff9e455d923f2bf63bab9ab1a0f9a7ec1d6e07))
* **host:** surface and audit legacy-import receipts so an arriving bag is never silently lost (ADR-0032 phase 4) ([e4be020](https://github.com/Vivswan/chromium-bridge/commit/e4be020a2e2db9d622e4c694b70dc0ae1d8e1ed4))
* **host:** sync the consumed tombstone through a writable handle for Windows (ADR-0032 phase 4) ([ebaf587](https://github.com/Vivswan/chromium-bridge/commit/ebaf58779b0d689d2cdf54435f78e6380db20160))
* **i18n:** English as the canonical language on every surface ([94bb64e](https://github.com/Vivswan/chromium-bridge/commit/94bb64ef03962087e99d5488515aaa7d710f08dc))
* **install:** require build-provenance attestation on the online verify path ([f21150a](https://github.com/Vivswan/chromium-bridge/commit/f21150a990fd57ef373c7e9aab0938fe623ea2d1))
* **install:** restrict install dir to owner-only (0700) ([37bf5d9](https://github.com/Vivswan/chromium-bridge/commit/37bf5d90b32ed1f11fa912c3288ecaed9ed28c01))
* **ipc:** cap the lock read and create the lock tmp exclusively ([2209966](https://github.com/Vivswan/chromium-bridge/commit/2209966d8840b93cf80d6397c454d9e09f773716))
* **ipc:** fail closed if the OS CSPRNG is unavailable ([0125d0b](https://github.com/Vivswan/chromium-bridge/commit/0125d0b6f94cf920e2eed5771fd73d33d05047e2))
* **ipc:** keep the new server's socket alive across takeover ([7978e77](https://github.com/Vivswan/chromium-bridge/commit/7978e771663c3b0f22eea7616ea4699e08f8b346))
* **ipc:** reject non-hex handshake MAC without panicking ([582e3c4](https://github.com/Vivswan/chromium-bridge/commit/582e3c410e6dd64ede750e92241483e86bc2d054))
* **just:** restore ci's one-line doc string in just --list ([27fc787](https://github.com/Vivswan/chromium-bridge/commit/27fc7874780ad39eb3e176114e964a71c9047aa4))
* **kill:** drain and clear the browser registry in the sweep itself, not via reader wakeup ([bdb4fae](https://github.com/Vivswan/chromium-bridge/commit/bdb4fae578756625930b1f315a5daaaaf631840f))
* **kill:** harden the confirm-window panic-latch release lifecycle ([c6fb844](https://github.com/Vivswan/chromium-bridge/commit/c6fb8446e02ae26a384611250605ef9a38bab619))
* **kill:** require an authoritative killed frame for panic-latch refusal proof ([c32f065](https://github.com/Vivswan/chromium-bridge/commit/c32f06508961665d86ad710a209aefcf463bd74f))
* MCP server supplants stale instances; tool calls wait for host connect ([0217ba0](https://github.com/Vivswan/chromium-bridge/commit/0217ba01e62285015651e26a9fa01ecdcaa2ef41))
* **mcp:** attest lock-file pid identity before takeover SIGTERM ([08d6561](https://github.com/Vivswan/chromium-bridge/commit/08d65617cf92d800cbc784231b9a35ae189d2c13))
* **mcp:** keep invalid-opener refusals off the wire under rmcp 3.2 ([e7ebe34](https://github.com/Vivswan/chromium-bridge/commit/e7ebe34ee8cf3ec0ba639b9fafb93983d6449b3a))
* native host no longer zombies when MCP server is supplanted ([26c16f5](https://github.com/Vivswan/chromium-bridge/commit/26c16f5e2af383108a21cad9494a93a86e2cc0fb))
* **native-host:** cap the socket receive leg ([b498ea3](https://github.com/Vivswan/chromium-bridge/commit/b498ea351992fe5d9833e68d420629441963cc76))
* **native-host:** drop server-injected enclave frames on the socket leg ([661a94f](https://github.com/Vivswan/chromium-bridge/commit/661a94fe325bc58b33981c3ac741ac4745d704c2))
* point extension tsconfig at jest-dom 7's vitest types entry ([06a8279](https://github.com/Vivswan/chromium-bridge/commit/06a8279106943826dde2da02da619d5014a7f93d))
* **protocol:** bound and de-recurse mcp_read on the client leg ([4ccbbab](https://github.com/Vivswan/chromium-bridge/commit/4ccbbab475a7e9769e7e8057e211abfa544bc963))
* **protocol:** bound bridge_read to prevent unbounded allocation ([e739959](https://github.com/Vivswan/chromium-bridge/commit/e7399596c0eaedc2289a150b3d5d8be9443a4e38))
* **release:** adapt release automation and code owners to the workspace ([957da5d](https://github.com/Vivswan/chromium-bridge/commit/957da5df6ea0cb6dcd09606719c5641d22767aff))
* **release:** DMG art speaks the Gatedeck deck language ([faca827](https://github.com/Vivswan/chromium-bridge/commit/faca827455d0b256fa85d8469b426be38a6cfd67))
* **release:** publish the extension zip from an explicit macos-only step ([b33a7ab](https://github.com/Vivswan/chromium-bridge/commit/b33a7aba625bd19aa0b3619c090888774f856e76))
* **release:** route Intel Macs to build-from-source, not Rosetta ([05bd898](https://github.com/Vivswan/chromium-bridge/commit/05bd8982f894d872d01b3fc500d77e768c671c55))
* **runbook:** phase8-touchid-proof must use the signed bundle host ([d8d5d24](https://github.com/Vivswan/chromium-bridge/commit/d8d5d24a3ed3bff29997ad7e751c85dc6968d492))
* **runbook:** touchid-gates prints the CLI capability-grant steps ([5244855](https://github.com/Vivswan/chromium-bridge/commit/5244855cd66713d6064d531afc6aa2fee6958ce0))
* **scripts:** parse hasher.ignorePatterns with Bun.YAML instead of a regex line scan ([acad61b](https://github.com/Vivswan/chromium-bridge/commit/acad61b1499b6062fd5d81f42f96484c70305260))
* **site:** correct security claims and install steps to match the docs ([f19b5da](https://github.com/Vivswan/chromium-bridge/commit/f19b5da8943efdad21d13266f1a60afb3f377931))
* **site:** scope the Enclave and enrollment claims to what the docs support ([585f779](https://github.com/Vivswan/chromium-bridge/commit/585f779682704bf778cc7678f9403def9d744142))
* **site:** send relative directory links to the GitHub tree instead of 404 routes ([03af2b0](https://github.com/Vivswan/chromium-bridge/commit/03af2b0b0e9e7e76b708dad6d02b36326efe07da))
* **site:** the bridge has no silent enrollment path (scope to what ADR-0031 claims) ([bc95e62](https://github.com/Vivswan/chromium-bridge/commit/bc95e627e92a00161f3413842b5ccc445a70d3f8))
* teach both cargo-deny license gates about the source-available relicense ([9a21046](https://github.com/Vivswan/chromium-bridge/commit/9a2104688cb42ea040a0f1a620e779e0d9e83a25))
* **test:** make cli and registration path fixtures Windows-correct ([8097948](https://github.com/Vivswan/chromium-bridge/commit/80979484f84dd88a78558893395aa9a38f7d29d9))
* **tests:** await Page.loadEventFired in the CDP client instead of fixed sleeps ([8af6420](https://github.com/Vivswan/chromium-bridge/commit/8af6420a9d26f051b3ce4320b56277ab8082ea76))
* **tests:** bound every browser-harness await and give CI jobs timeouts ([8db90f1](https://github.com/Vivswan/chromium-bridge/commit/8db90f12f3dc33e7970c0980f5bab5119d3ac841))
* **tests:** make server_stderr non-blocking on a live server; drop the duplicate accessor ([72d3f8e](https://github.com/Vivswan/chromium-bridge/commit/72d3f8eb656b80146c7c755ae20fb2fd11acbf4e))
* **tests:** point the options-page browser assertions at the slimmed surface (ADR-0032 phase 5) ([06b377f](https://github.com/Vivswan/chromium-bridge/commit/06b377fc363b86bc3967808a6f27dfd6089235d3))
* **tests:** state the true native-messaging gap (no host registration) and probe it ([7baf389](https://github.com/Vivswan/chromium-bridge/commit/7baf389454c07222b35cd992fb204c49e574faf1))
* **tools:** reconcile page_eval description with reconfirm-every-call behavior ([788aa4f](https://github.com/Vivswan/chromium-bridge/commit/788aa4f1ba751c78d7862d4bc82af567da94f833))
* **typography:** replace look-alike punctuation in Rust sources with ASCII ([9f2164a](https://github.com/Vivswan/chromium-bridge/commit/9f2164a00914ad5cfe246ef6eeff1cee6c696b0b))
* **typography:** replace stray em-dashes/ellipses with ASCII; shrink .typography-allow to exact paths ([89bd345](https://github.com/Vivswan/chromium-bridge/commit/89bd345128c4828862a8bccb439462008249dade))
* **web:** allowlist the rendered root docs instead of denylisting scratch notes ([a1eaa99](https://github.com/Vivswan/chromium-bridge/commit/a1eaa993dca727a68d0d4be35cdf42f22d1e5005))
* **web:** fail the build on a trailing-slash md link to a non-directory ([71c444c](https://github.com/Vivswan/chromium-bridge/commit/71c444c3756174304c2a8bea366d41f4a0737336))


### Miscellaneous Chores

* relicense to the Individual and Small Organization License 1.0.0 ([d4731c1](https://github.com/Vivswan/chromium-bridge/commit/d4731c1a16a97a18d24c1fe6f491ea64ad1dbeeb))


### Code Refactoring

* carve out a cargo workspace and rebrand to chromium-bridge ([43f5a7f](https://github.com/Vivswan/chromium-bridge/commit/43f5a7f5fb255332ccf330d7bd65b701e6b8f586))


### Build System

* make moon the canonical command interface and adopt proto ([adb5995](https://github.com/Vivswan/chromium-bridge/commit/adb5995864af10c3760103b53c41045064ad04f2))

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
