# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2026-07-20)


### ⚠ BREAKING CHANGES

* the justfile is gone - use moon run <task> (moon run help lists everything); local checkouts need proto (proto install) since moon is no longer an npm devDependency.
* **extension:** off-DOM confirmations on an extension-owned surface + single page-API source
* **extension:** rebuild on WXT with a generated, contract-pinned manifest
* carve out a cargo workspace and rebrand to chromium-bridge

### Features

* add cookie_get + storage_get (read-only) ([2f8d526](https://github.com/Vivswan/chromium-bridge/commit/2f8d526c6f0b8124fa5ec0f5a2bd18db4c68a960))
* add Linux and WSL support ([#13](https://github.com/Vivswan/chromium-bridge/issues/13)) ([516348b](https://github.com/Vivswan/chromium-bridge/commit/516348b2235c3580e03198199bdf16d0b25a0ff9))
* add native Windows support ([ec60efd](https://github.com/Vivswan/chromium-bridge/commit/ec60efd8ce5e4746cb17516de1d7143004c90108))
* add Options page for centralized settings management ([03d5541](https://github.com/Vivswan/chromium-bridge/commit/03d554136d51d5cf810347a3ff0bee5b43ea6585))
* add page_eval high-risk confirmation channel ([7401462](https://github.com/Vivswan/chromium-bridge/commit/740146289c9eddcc8fd095dca0a1c1e974049199))
* add page_snapshot_precise via chrome.debugger (CDP) ([91d94c1](https://github.com/Vivswan/chromium-bridge/commit/91d94c196c1cb6f80e8898bdf46eeeceeb37adca))
* **broker:** concurrent multi-client pairing with a ref-counted attested broker ([cc1df94](https://github.com/Vivswan/chromium-bridge/commit/cc1df9456e6e99ef1a3ee202a934f17fd3dbcda3))
* **build:** adopt moon as the task orchestrator under the justfile (phase one) ([86d8098](https://github.com/Vivswan/chromium-bridge/commit/86d8098e12469b62eba88d78c94dc987a21188f7))
* **cli:** doctor --fix + uninstall on a shared browser-path resolver ([78f32fc](https://github.com/Vivswan/chromium-bridge/commit/78f32fc21f43126ba46b7267af945d979bbd4432))
* **cli:** read-only doctor/status subcommand ([70ee7bb](https://github.com/Vivswan/chromium-bridge/commit/70ee7bb99401d3591109206cfa09909f91f7bc3e))
* **contract:** generate the envelope wire validators from the Rust schemas ([fb24ba0](https://github.com/Vivswan/chromium-bridge/commit/fb24ba03c6c788b0d37bf9b17c8a32cab77b00b8))
* contracts/tools.json as the single source for the tool catalogue (P1) ([93bc70c](https://github.com/Vivswan/chromium-bridge/commit/93bc70cadfae49d847a70746f807df34f2f115a8))
* **contracts:** Zod boundary validation and codegen/parity backbone ([d550eea](https://github.com/Vivswan/chromium-bridge/commit/d550eea53fbef8639405927d48ab3b37520fa31b))
* **cutover:** retire install scripts, consolidate docs, add zh docs + docs site ([c43f18d](https://github.com/Vivswan/chromium-bridge/commit/c43f18dc1eaf9fb722f4559ccb3dd02e2e3ce291))
* **desktop:** app-confirm dialogs and phase8 presence-contract alignment ([b97a2a9](https://github.com/Vivswan/chromium-bridge/commit/b97a2a90827da3179ca85b45532160ba5ff932e5))
* **desktop:** control-panel app UI over the core management engines (ADR-0029) ([b6a3b13](https://github.com/Vivswan/chromium-bridge/commit/b6a3b13c4f50aa4c08fe62aa42eb165689ffb70c))
* **desktop:** generate the UI's Tauri command types from Rust via ts-rs ([897e228](https://github.com/Vivswan/chromium-bridge/commit/897e2280b9bf711b04ccaae98080efc59c9cbd5b))
* **desktop:** overview lifecycle states per the first-run spec ([6f68118](https://github.com/Vivswan/chromium-bridge/commit/6f681187973b08564a5a02f56bc8dd12a02f7c37))
* **desktop:** prove the signed-host entitlement chain (Tauri v2 spike) ([c3676d8](https://github.com/Vivswan/chromium-bridge/commit/c3676d8e55a2d49a86ffa1fca1582a29545599d2))
* **desktop:** rebuild UI to the Control Tower design ([95b550e](https://github.com/Vivswan/chromium-bridge/commit/95b550ecfbcdf4150dd7dd58514e62fa0f1a2813))
* **desktop:** wire the presence gates onto the landed phase8 API (Floor::AppConfirm) ([ddb7ff6](https://github.com/Vivswan/chromium-bridge/commit/ddb7ff6c76aa106fb597fa3ee89906af74a7e934))
* **dev:** docs tab + pinned toolbar icon in the WXT dev browser, enforced fresh-profile isolation ([e1e4e20](https://github.com/Vivswan/chromium-bridge/commit/e1e4e20a2f3b731cbef7606f6b37ac4b0096f862))
* **dev:** just dev also runs the desktop app; cut just --list to 12 top-level verbs ([cac5367](https://github.com/Vivswan/chromium-bridge/commit/cac5367954bee7b1670127677f853549ac1ea335))
* **dev:** just dev runs the extension and site together; build includes the site ([ebec222](https://github.com/Vivswan/chromium-bridge/commit/ebec22285c61e627b8db10797cea09759e790384))
* **dispatch:** route disable-gate through policy.decide ([c61d1de](https://github.com/Vivswan/chromium-bridge/commit/c61d1de4b33fa9f151cbc546b65316ec754b4825))
* **doctor:** note that green checks don't confirm the extension connected ([#34](https://github.com/Vivswan/chromium-bridge/issues/34)) ([f2710ab](https://github.com/Vivswan/chromium-bridge/commit/f2710ab98eeefe6943ab5059fd0cf1b6e97e941b))
* **enclave:** add the Secure Enclave enrollment ceremony (host side) ([271511c](https://github.com/Vivswan/chromium-bridge/commit/271511c6e786560e725ec749ec521be569431707))
* **error:** map CallError to contracts/errors.json codes ([e900d41](https://github.com/Vivswan/chromium-bridge/commit/e900d4136698bf8c714499cf89b6c1ae8ddddf2d))
* **ext:** bundle JetBrains Mono for identity material ([9602d96](https://github.com/Vivswan/chromium-bridge/commit/9602d96cae8542aefb884721c7c25a9716b287dc))
* **extension:** add confirmPageEval / confirmTabClose toggles ([#39](https://github.com/Vivswan/chromium-bridge/issues/39)) ([ed13d55](https://github.com/Vivswan/chromium-bridge/commit/ed13d55bb810424d291b86f802d6661cbbbda019))
* **extension:** add opt-in CDP mode for all page ops ([#37](https://github.com/Vivswan/chromium-bridge/issues/37)) ([ec6d380](https://github.com/Vivswan/chromium-bridge/commit/ec6d3809335817e8d1732ec68aeb3a6ce3e875a5))
* **extension:** add opt-in lazy host re-verification interval ([3a4929d](https://github.com/Vivswan/chromium-bridge/commit/3a4929d4ee05f67c55b2e68480195df7d5e8a1cc))
* **extension:** compact engage-only kill control in the confirm window ([ba0a294](https://github.com/Vivswan/chromium-bridge/commit/ba0a294da5adc770af6f1f0eaacc959f0b43a0ff))
* **extension:** group AI-opened tabs into a "Browser Bridge" workspace ([#44](https://github.com/Vivswan/chromium-bridge/issues/44)) ([a06387f](https://github.com/Vivswan/chromium-bridge/commit/a06387f2614fbe128d5c3882d2b43b01071c569e))
* **extension:** isolate trust state from content scripts ([#32](https://github.com/Vivswan/chromium-bridge/issues/32)) ([2c61432](https://github.com/Vivswan/chromium-bridge/commit/2c614321828d08e63466ce777e55e159ea4ea721))
* **extension:** localize tool labels through the i18n bundle ([15f9135](https://github.com/Vivswan/chromium-bridge/commit/15f9135e6c9ac1294827334ad8b1e233eed0a58b))
* **extension:** log a loud warning when the running ID ≠ pinned ID ([#38](https://github.com/Vivswan/chromium-bridge/issues/38)) ([04ca518](https://github.com/Vivswan/chromium-bridge/commit/04ca5182fccb8c0bb712f3fe1c17e4f857292bf3))
* **extension:** mask long opaque tokens in eval/cookie/storage output ([c88f56f](https://github.com/Vivswan/chromium-bridge/commit/c88f56fbfc351b3785d4e3cba2cc19a7de6d821c))
* **extension:** off-DOM confirmations on an extension-owned surface + single page-API source ([d326317](https://github.com/Vivswan/chromium-bridge/commit/d326317e763bd4b6c4ff55209ecb3400f9a7ae06))
* **extension:** pin the enrollment key and fail closed until paired (ADR-0021) ([893b70e](https://github.com/Vivswan/chromium-bridge/commit/893b70e6048fa155f7ed5bd87786842a50cdf313))
* **extension:** rebuild on WXT with a generated, contract-pinned manifest ([b7a7d24](https://github.com/Vivswan/chromium-bridge/commit/b7a7d24654535039ed493502730d0409432bce49))
* **extension:** trilingual runtime i18n + React/Radix/Tailwind UI rehaul ([aaaf763](https://github.com/Vivswan/chromium-bridge/commit/aaaf763d274a42a7eaed1aac36734d5f03b824bd))
* **ext:** first-run popup pairing state per the first-run spec ([6384bc5](https://github.com/Vivswan/chromium-bridge/commit/6384bc58ba17e160ef728950d5263738bb76186f))
* **ext:** rebuild popup, options, and confirm on the Control Tower design ([6d6cc25](https://github.com/Vivswan/chromium-bridge/commit/6d6cc25a8ddd47f3aafd98f8adb16ad855e91d6b))
* **ext:** restyle the in-page info toast to the Control Tower layout ([a298c3c](https://github.com/Vivswan/chromium-bridge/commit/a298c3cb2a6fa365242578afa34e5e5b748baad9))
* **ext:** restyle the shared UI primitives to Control Tower motifs ([2660af4](https://github.com/Vivswan/chromium-bridge/commit/2660af4f7d863f1517e539382e6a9d4c84fa9401))
* **icons:** generate Gatedeck icon assets from SVG sources at build time ([f9b2b63](https://github.com/Vivswan/chromium-bridge/commit/f9b2b63c5b10485ede2c33138fe9a5e0aedf958f))
* implement browser-bridge v0.1 (Rust + MV3 extension) ([1871420](https://github.com/Vivswan/chromium-bridge/commit/187142090a4db6807bc5a0222ce8343a7eb8a21a))
* **install:** clear macOS Gatekeeper quarantine on the installed binary ([#31](https://github.com/Vivswan/chromium-bridge/issues/31)) ([6a8f7b6](https://github.com/Vivswan/chromium-bridge/commit/6a8f7b6d2ddc509bc5fde068c576b14851ddb1a6))
* **install:** per-browser run-host wrappers carrying --label ([794b5ef](https://github.com/Vivswan/chromium-bridge/commit/794b5ef5b4d1cb149105aaa41ff90eedecd2849d))
* **install:** print resolved client config and optional Claude Code auto-register ([#33](https://github.com/Vivswan/chromium-bridge/issues/33)) ([096a9c5](https://github.com/Vivswan/chromium-bridge/commit/096a9c589da8043e5f06be5a228a0cb814327258))
* **install:** support any Chromium browser via a native-messaging host table ([71a4887](https://github.com/Vivswan/chromium-bridge/commit/71a48876e2f766c513db6897b2a2d3f491c164d9))
* **install:** verify the prebuilt binary against the published checksum before install ([d63fd86](https://github.com/Vivswan/chromium-bridge/commit/d63fd868a0fef7927bb1dca7cc3164358b4f5660))
* **ipc:** attest bridge peers by kernel-verified executable identity ([54b4244](https://github.com/Vivswan/chromium-bridge/commit/54b4244aefdabdc770a0f5e5b8cc09b2adda357f))
* **ipc:** attest macOS bridge peers by audit-token SecCode cdhash ([a698fdd](https://github.com/Vivswan/chromium-bridge/commit/a698fdd31704dcf625dc13f3e840c343ea534fc9))
* **ipc:** authenticate the bridge with an HMAC challenge-response ([9aecbcb](https://github.com/Vivswan/chromium-bridge/commit/9aecbcb6bda4de7b05e087dd547ffe6a76729a7a))
* **ipc:** reject cross-user peers via SO_PEERCRED/getpeereid ([c5ae301](https://github.com/Vivswan/chromium-bridge/commit/c5ae30186b52e7e5da8c6529105880caca230808))
* **ipc:** switch bridge transport to a 0600 unix domain socket ([5b79c9a](https://github.com/Vivswan/chromium-bridge/commit/5b79c9a2b79095e6a7d7021fcc707499782ead92))
* **mcp:** warn loudly at startup that Windows bridge security is best-effort ([8405b96](https://github.com/Vivswan/chromium-bridge/commit/8405b96135bada04dd602751022da5d9c2096326))
* **observability:** per-call request ids + structured audit events ([edda161](https://github.com/Vivswan/chromium-bridge/commit/edda16132aa5863fdc50930a39c6da64251a8175))
* pin the extension ID (manifest key) - no more copy-ID install step ([4085c0a](https://github.com/Vivswan/chromium-bridge/commit/4085c0a756100d1d1e2858860c01e757318a57d2))
* **policy:** additive policy-layer foundation from tool contract ([f7c5985](https://github.com/Vivswan/chromium-bridge/commit/f7c5985c882d927cb0d81f47d15524eb6a52d567))
* prebuilt release pipeline - install without Rust/Node ([5b91bff](https://github.com/Vivswan/chromium-bridge/commit/5b91bff04f023f8fce0249bf93dd096307939ec9))
* **protocol:** reject unknown fields on all bridge wire types (fail closed) ([2ce454a](https://github.com/Vivswan/chromium-bridge/commit/2ce454a28165a854855dbf8db40215034325c405))
* refine tool descriptions, protocol layer, and tab_close confirmation ([a9270e0](https://github.com/Vivswan/chromium-bridge/commit/a9270e0fa2ceeeebaed12b69017342876990d8fb))
* **release:** branded DMG with Gatedeck identity ([4ef223d](https://github.com/Vivswan/chromium-bridge/commit/4ef223d889f27a8a425547fe960c5fc9070bbf6c))
* **release:** build, verify, and publish the signed desktop .dmg ([1108b5b](https://github.com/Vivswan/chromium-bridge/commit/1108b5b076033c966da3452617f555703e2e71fe))
* **security:** any-side revocation epoch (ADR-0025) ([41fb56d](https://github.com/Vivswan/chromium-bridge/commit/41fb56d7d8b2ea036cc4bde63912f3cc5bc87180))
* **security:** global kill switch, audit trail, and presence-gated unkill (ADR-0030) ([51bb2b5](https://github.com/Vivswan/chromium-bridge/commit/51bb2b52a4032981814a79c75939613affb30755))
* **security:** Touch ID presence gates for crown-jewel tools and capability grants (ADR-0031) ([57f17f9](https://github.com/Vivswan/chromium-bridge/commit/57f17f942c497778ce6c4df145a20ebe5e65a2f8))
* **session:** generation-guarded connection (RFC-0001) ([7701bf2](https://github.com/Vivswan/chromium-bridge/commit/7701bf2807deaa3ae88e059704a5af064eaf2108))
* **session:** hold multiple authenticated browser connections, routed by label ([c26f7b6](https://github.com/Vivswan/chromium-bridge/commit/c26f7b62099ddf0d7c8fe0ce295ed610b4df3a21))
* **site:** Control Tower landing page ([180ad2c](https://github.com/Vivswan/chromium-bridge/commit/180ad2c12c420d44b8fb20214a10857e368dbaa9))
* **tools:** add navigation, keyboard, hover, select, console, dialog, and file-upload tools ([7183c46](https://github.com/Vivswan/chromium-bridge/commit/7183c462405592dabe6351ad9d6a2443ee898d1e))
* **ui:** adopt Control Tower design tokens in both apps ([9db5dfc](https://github.com/Vivswan/chromium-bridge/commit/9db5dfc189461e9bd124a4b33c88f697df63ad3f))


### Bug Fixes

* **audit:** correlate confirmation rows by a per-confirmation id ([77fb274](https://github.com/Vivswan/chromium-bridge/commit/77fb274411bb8165ac86a635b045768856885a82))
* **build:** tauri hooks run from the frontend dir; restore bun run dev/build ([127a7d2](https://github.com/Vivswan/chromium-bridge/commit/127a7d2a3f222dd2f68983cd2738e59a9f0aefe2))
* **ci:** check out full history so moon can resolve the PR base ref ([fe4dcef](https://github.com/Vivswan/chromium-bridge/commit/fe4dcef4538099ab1b183a3d24979d4b1c4021e3))
* **contracts:** gate enclave/admin/client wire types in the envelope parity check ([ecb4d89](https://github.com/Vivswan/chromium-bridge/commit/ecb4d899804f85cb1dda98ef3e1c21767ded3967))
* **core:** centralize secure file permissions in fsguard ([52b5fe0](https://github.com/Vivswan/chromium-bridge/commit/52b5fe0d3b8b058a2d2521f35bc3e71a22db843c))
* **core:** drop the Windows delete-before-rename on security files ([1af39bd](https://github.com/Vivswan/chromium-bridge/commit/1af39bd97a323725732272fa4cca200ada7b8cc4))
* **core:** emit revocation audit record inside Allowlist::revoke ([6e4b80f](https://github.com/Vivswan/chromium-bridge/commit/6e4b80fbd12bd5d1a7c7048c70c485cd7c1db962))
* **core:** gate Unix-only imports so Windows clippy is clean, and gate it in CI ([3206998](https://github.com/Vivswan/chromium-bridge/commit/3206998570fcb36f44110e8d9e1809885db6fb2e))
* **core:** harden the unsafe FFI quarantine per audit findings ([8906e02](https://github.com/Vivswan/chromium-bridge/commit/8906e021c2b8b19dc8f424e18f62807dcb75e071))
* **core:** write config.json via the hardened write_private_atomic ([5e067eb](https://github.com/Vivswan/chromium-bridge/commit/5e067eb8a8f20ddde5520ad2ef472c9a0ec1ee90))
* correctness + robustness hardening (Phase 0) ([04bde1a](https://github.com/Vivswan/chromium-bridge/commit/04bde1ab5ded544818f709e2f53e494d09a7bc69))
* **desktop:** a11y and interaction polish from the design gauntlet ([d2f5d82](https://github.com/Vivswan/chromium-bridge/commit/d2f5d82d318b5fb3521f2fb4dbbe8ad1ca464584))
* **desktop:** box the AuditLine::Record variant after cid grew AuditRecord ([a5e2ca4](https://github.com/Vivswan/chromium-bridge/commit/a5e2ca4a130d296e932c1924235692a72631066a))
* **desktop:** correlate confirm rows and keep green out of the audit ledger ([510a007](https://github.com/Vivswan/chromium-bridge/commit/510a00709e913e692ed1c48e7f7d63dd9566e02a))
* **desktop:** green means live+attested only; fail closed on stale status ([68df645](https://github.com/Vivswan/chromium-bridge/commit/68df6455fc43ed0c56839d599557f71452ad5b14))
* **desktop:** make first-launch registration opt-in and browser actions truthful ([f2128fd](https://github.com/Vivswan/chromium-bridge/commit/f2128fd5f4c20dc0ae497daae04a595e07efb937))
* **desktop:** render the enclave fingerprint in the extension's lowercase form ([94f836c](https://github.com/Vivswan/chromium-bridge/commit/94f836c29ebb089d2f676fbbfbab7e13548866bf))
* **desktop:** render unreadable kill and rejected key honestly on Overview ([2c6c26d](https://github.com/Vivswan/chromium-bridge/commit/2c6c26d865a783722ca13ee48d5bc417dcd31d7a))
* **desktop:** wrap long paths and commands on the Setup page ([4b893f7](https://github.com/Vivswan/chromium-bridge/commit/4b893f77d66a0847c4a579722922a1eef75d6864))
* **dev:** fail closed on the two dev-browser ownership gaps the gate found ([82fd049](https://github.com/Vivswan/chromium-bridge/commit/82fd049e6226bfb6c72c163b69c62db9564e1fe6))
* **dev:** pin the astro dev server lifecycle: stop stale servers, no auto-daemonization ([abd1094](https://github.com/Vivswan/chromium-bridge/commit/abd109487acb6b24d0d9bcffa82afbc03f2b2fe7))
* **dev:** sweep the tauri process group when its leader dies; docs match the 12-verb list ([d0e43b6](https://github.com/Vivswan/chromium-bridge/commit/d0e43b6d7041d9c36266afb6150758fb6c68d3c9))
* **doctor:** require the app bundle for macOS browser detection ([5f38d4c](https://github.com/Vivswan/chromium-bridge/commit/5f38d4c0b22970acf8b8cc2cce9ec064097c5881))
* **extension:** announce, localize, and animate the in-page notice ([4df53c5](https://github.com/Vivswan/chromium-bridge/commit/4df53c54a9f3bd6bc29ca4e8ed6e80f64969db8e))
* **extension:** confirm the enrollment gate inside the transition queue ([00b5240](https://github.com/Vivswan/chromium-bridge/commit/00b52406dbfafb57b89b1ccc66bf7a17919fd556))
* **extension:** disarm pending-origin Allow unless kill state reads alive ([49bdcbe](https://github.com/Vivswan/chromium-bridge/commit/49bdcbe2d150ff5a36d3258c4464c1db6b168b7a))
* **extension:** fail-closed popup kill display and pairing-first hierarchy ([7e3a451](https://github.com/Vivswan/chromium-bridge/commit/7e3a4513e337dfdd64c3b79c85feade07d34259f))
* **extension:** gate every runtime message behind an extension-page sender ([#32](https://github.com/Vivswan/chromium-bridge/issues/32)) ([c8715af](https://github.com/Vivswan/chromium-bridge/commit/c8715aff8c08474faad54f153b2828c5d48c09b6))
* **extension:** gauntlet copy pass across all three locales ([3dc69bc](https://github.com/Vivswan/chromium-bridge/commit/3dc69bcef30777e6600cbfea747e5f4e04d2b675))
* **extension:** harden the confirm window's content honesty ([230626f](https://github.com/Vivswan/chromium-bridge/commit/230626ff5b24ff051fff2f9f5bf291cde9a142d5))
* **extension:** keep confirm decision controls on screen under long payloads ([8c9e687](https://github.com/Vivswan/chromium-bridge/commit/8c9e687707a7a6a814fb181613cfe3e93c64f7cd))
* **extension:** mask every page_eval egress, not just the success value ([430a720](https://github.com/Vivswan/chromium-bridge/commit/430a7204bc482443759bd92fc401f0d4688207dc))
* **extension:** options honesty, hierarchy, and a11y ([e997aba](https://github.com/Vivswan/chromium-bridge/commit/e997aba56baaa0d1743bc7d301024096710da61c))
* **extension:** parse enclave_error frames with their declared schema ([7ab39d0](https://github.com/Vivswan/chromium-bridge/commit/7ab39d03f0b525ad97f33dcaf48b6ee5820adedb))
* **extension:** pinned fresh pairing supersedes a stale host-key revoke ([fd85735](https://github.com/Vivswan/chromium-bridge/commit/fd8573593a1e7ea44d0c447439a715e4f17028a9))
* **extension:** reconfirm every page_eval by excluding it from the grace window ([934a4b7](https://github.com/Vivswan/chromium-bridge/commit/934a4b7b024f0a6a0a9dafc24e97835a9c3b43ff))
* **extension:** scope enrollment enforcement to Enclave-capable platforms ([56a0c57](https://github.com/Vivswan/chromium-bridge/commit/56a0c57c03706cf459d60f12c9edfdee9ef2ac8b))
* **fsguard:** compile warning-free on windows ([70f5d06](https://github.com/Vivswan/chromium-bridge/commit/70f5d067670f97825f4f4c9e1c46cdbae2f51d33))
* **gen:** harden union handling and the adversarial harness per cross-model review ([d3af7af](https://github.com/Vivswan/chromium-bridge/commit/d3af7afc7ea3a085cb5428e33551e3f7d6678da0))
* **i18n:** English as the canonical language on every surface ([1cc9460](https://github.com/Vivswan/chromium-bridge/commit/1cc94602ec3309e2e5968d54c6b27d715f821555))
* **install:** require build-provenance attestation on the online verify path ([86f5cee](https://github.com/Vivswan/chromium-bridge/commit/86f5cee62de5bc1c85266c37fa10e836db87423b))
* **install:** restrict install dir to owner-only (0700) ([4993423](https://github.com/Vivswan/chromium-bridge/commit/4993423a8b78852b82ebdf965af577a52e6fec3a))
* **ipc:** cap the lock read and create the lock tmp exclusively ([b676a81](https://github.com/Vivswan/chromium-bridge/commit/b676a8105c000bf1adcc03126d0bfc02ae4a32a3))
* **ipc:** fail closed if the OS CSPRNG is unavailable ([651455a](https://github.com/Vivswan/chromium-bridge/commit/651455ae6dd9a1efe9ae95947718373de034038b))
* **ipc:** keep the new server's socket alive across takeover ([d6455f7](https://github.com/Vivswan/chromium-bridge/commit/d6455f71faeae6ac5d629880893500f8d67d2461))
* **ipc:** reject non-hex handshake MAC without panicking ([11706f7](https://github.com/Vivswan/chromium-bridge/commit/11706f7b995f3acde90ddfb20098a045fc2494e8))
* **just:** restore ci's one-line doc string in just --list ([fa75749](https://github.com/Vivswan/chromium-bridge/commit/fa757496b8a42a99d4467ea1efe24aa0107a7f95))
* **kill:** drain and clear the browser registry in the sweep itself, not via reader wakeup ([fd435ff](https://github.com/Vivswan/chromium-bridge/commit/fd435ffa05b864b85e5820ba25b6bcb7ed2d566b))
* **kill:** harden the confirm-window panic-latch release lifecycle ([dbfcff4](https://github.com/Vivswan/chromium-bridge/commit/dbfcff44e71a7ec753ca11a8412a83119c10e844))
* **kill:** require an authoritative killed frame for panic-latch refusal proof ([30cd62d](https://github.com/Vivswan/chromium-bridge/commit/30cd62db59b1821725cb2840203bda531a893b1c))
* MCP server supplants stale instances; tool calls wait for host connect ([0217ba0](https://github.com/Vivswan/chromium-bridge/commit/0217ba01e62285015651e26a9fa01ecdcaa2ef41))
* **mcp:** attest lock-file pid identity before takeover SIGTERM ([b313e23](https://github.com/Vivswan/chromium-bridge/commit/b313e23e882648c85b9acae1486911206f33335c))
* native host no longer zombies when MCP server is supplanted ([26c16f5](https://github.com/Vivswan/chromium-bridge/commit/26c16f5e2af383108a21cad9494a93a86e2cc0fb))
* **native-host:** cap the socket receive leg ([f5ca289](https://github.com/Vivswan/chromium-bridge/commit/f5ca289b3b7c70601a12362c88d8a0e13bf4d5cc))
* **native-host:** drop server-injected enclave frames on the socket leg ([e804c7c](https://github.com/Vivswan/chromium-bridge/commit/e804c7c571b1e3ba034d41a9ed58a34bb714aeb0))
* **protocol:** bound and de-recurse mcp_read on the client leg ([6625820](https://github.com/Vivswan/chromium-bridge/commit/66258200c94cac2753b1337681f89b1decc18bdf))
* **protocol:** bound bridge_read to prevent unbounded allocation ([e445ad3](https://github.com/Vivswan/chromium-bridge/commit/e445ad33b628389cf8adaf6631ae8ad32fa0b682))
* **release:** adapt release automation and code owners to the workspace ([7c7ff17](https://github.com/Vivswan/chromium-bridge/commit/7c7ff177c22df35d3c2d3fc0082d5606592901bf))
* **release:** DMG art speaks the Gatedeck deck language ([9dae348](https://github.com/Vivswan/chromium-bridge/commit/9dae348fd3defad6bd9f34b5d4ef64b1ab97eca7))
* **release:** publish the extension zip from an explicit macos-only step ([6596fc0](https://github.com/Vivswan/chromium-bridge/commit/6596fc0c384e04775dbdfb3b896347c3730fa84a))
* **release:** route Intel Macs to build-from-source, not Rosetta ([39fc09a](https://github.com/Vivswan/chromium-bridge/commit/39fc09a2f4f6b5d1d5e12c6596e15ef806f9200e))
* **runbook:** phase8-touchid-proof must use the signed bundle host ([a2fa1ec](https://github.com/Vivswan/chromium-bridge/commit/a2fa1ec7e9a97ff22950850cc0a834be16489671))
* **runbook:** touchid-gates prints the CLI capability-grant steps ([f10fd38](https://github.com/Vivswan/chromium-bridge/commit/f10fd384004f658d01ed30c670a6218762f469fd))
* **scripts:** parse hasher.ignorePatterns with Bun.YAML instead of a regex line scan ([a345b26](https://github.com/Vivswan/chromium-bridge/commit/a345b26bf9721968280b0b2fe350a1372e9e48f6))
* **site:** correct security claims and install steps to match the docs ([75b4f1c](https://github.com/Vivswan/chromium-bridge/commit/75b4f1c4cdb8a6b9eee9ebbf5792830f3f7b84b5))
* **site:** scope the Enclave and enrollment claims to what the docs support ([f1396b5](https://github.com/Vivswan/chromium-bridge/commit/f1396b5697b26252da6bb548ddc62af57644d523))
* **site:** send relative directory links to the GitHub tree instead of 404 routes ([04733e9](https://github.com/Vivswan/chromium-bridge/commit/04733e91d1c7e04e8bccf91780140568071004f2))
* **site:** the bridge has no silent enrollment path (scope to what ADR-0031 claims) ([410580a](https://github.com/Vivswan/chromium-bridge/commit/410580aeb111c6f9dda59a4430a5a5af47b3f2b0))
* **test:** make cli and registration path fixtures Windows-correct ([630ad15](https://github.com/Vivswan/chromium-bridge/commit/630ad1574a3a13a73fb8af11d5e31ab59c7a80a8))
* **tests:** await Page.loadEventFired in the CDP client instead of fixed sleeps ([c3a4765](https://github.com/Vivswan/chromium-bridge/commit/c3a4765354e6c3ebb9bf890f4f5908ce8bc5aec0))
* **tests:** make server_stderr non-blocking on a live server; drop the duplicate accessor ([e8fa2e2](https://github.com/Vivswan/chromium-bridge/commit/e8fa2e26386ef2a13889b5dbfc12fe2f2d64a6d2))
* **tests:** state the true native-messaging gap (no host registration) and probe it ([2f5e40f](https://github.com/Vivswan/chromium-bridge/commit/2f5e40fc940c636103e94c83eeceea4cb0071c6c))
* **tools:** reconcile page_eval description with reconfirm-every-call behavior ([a6f80f5](https://github.com/Vivswan/chromium-bridge/commit/a6f80f5a7502979726dfe971de3f01275410629f))
* **typography:** replace look-alike punctuation in Rust sources with ASCII ([a36284d](https://github.com/Vivswan/chromium-bridge/commit/a36284dc20f053378cdc005d38ef85dcaa03c3f8))
* **typography:** replace stray em-dashes/ellipses with ASCII; shrink .typography-allow to exact paths ([5f140d3](https://github.com/Vivswan/chromium-bridge/commit/5f140d3099dc05638bc6710ec077c0d3bace4ee6))
* **web:** allowlist the rendered root docs instead of denylisting scratch notes ([71660ba](https://github.com/Vivswan/chromium-bridge/commit/71660baed67d4f777827cf72102fce37fad44e46))
* **web:** fail the build on a trailing-slash md link to a non-directory ([6a3de85](https://github.com/Vivswan/chromium-bridge/commit/6a3de858bdd12df32b7befc610d6f27f7ef681ae))


### Code Refactoring

* carve out a cargo workspace and rebrand to chromium-bridge ([351d12a](https://github.com/Vivswan/chromium-bridge/commit/351d12a785c21afee51b00a76fb71be91fd730be))


### Build System

* make moon the canonical command interface and adopt proto ([d3cf5e4](https://github.com/Vivswan/chromium-bridge/commit/d3cf5e40a9b724989d3c5c9ee1cfd207974af381))

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
