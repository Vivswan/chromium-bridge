# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2026-08-09)


### ⚠ BREAKING CHANGES

* relicense to the Individual and Small Organization License 1.0.0
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
* **broker:** concurrent multi-client pairing with a ref-counted attested broker ([cc65391](https://github.com/Vivswan/chromium-bridge/commit/cc653914caec182b471073c4c1787f7c12e687e6))
* **build:** adopt moon as the task orchestrator under the justfile (phase one) ([2f935ff](https://github.com/Vivswan/chromium-bridge/commit/2f935ff6a6a7b3e48fe263fc4dbedea70b04fdd3))
* **ci:** add SSoT parity gates for docs, adversarial tests, fuzz seeds, and the browser job ([#28](https://github.com/Vivswan/chromium-bridge/issues/28)) ([2fce233](https://github.com/Vivswan/chromium-bridge/commit/2fce233ca89d43f1ede8baf1fd295634d92b52d5))
* **ci:** persist and minimize the fuzz corpus nightly ([9e7a777](https://github.com/Vivswan/chromium-bridge/commit/9e7a777b906df930969e12fb94420800911ffac3))
* **cli:** doctor --fix + uninstall on a shared browser-path resolver ([dab09dd](https://github.com/Vivswan/chromium-bridge/commit/dab09dd7a4fba082a22e68de6b39a869d5f4eed3))
* **cli:** read-only doctor/status subcommand ([70ee7bb](https://github.com/Vivswan/chromium-bridge/commit/70ee7bb99401d3591109206cfa09909f91f7bc3e))
* **contract:** emit audit forwarding, writer frame types, and the MCP version from the core ([#29](https://github.com/Vivswan/chromium-bridge/issues/29)) ([420c814](https://github.com/Vivswan/chromium-bridge/commit/420c8147969192d7b2e95e95401ce34a6d18538e))
* **contract:** generate the envelope wire validators from the Rust schemas ([622e6b3](https://github.com/Vivswan/chromium-bridge/commit/622e6b3ca1b8138cf60257149ce03641f3ee119a))
* contracts/tools.json as the single source for the tool catalogue (P1) ([93bc70c](https://github.com/Vivswan/chromium-bridge/commit/93bc70cadfae49d847a70746f807df34f2f115a8))
* **contracts:** Zod boundary validation and codegen/parity backbone ([3851eba](https://github.com/Vivswan/chromium-bridge/commit/3851eba46734f4033f27bb2b2475ed777bb06434))
* **core:** emit the enclave contract and golden vectors to the shared TS package ([#30](https://github.com/Vivswan/chromium-bridge/issues/30)) ([91bb172](https://github.com/Vivswan/chromium-bridge/commit/91bb1729b19a527db4fb9f1e2fe9febe002b0503))
* **cutover:** retire install scripts, consolidate docs, add zh docs + docs site ([af33c72](https://github.com/Vivswan/chromium-bridge/commit/af33c7244cabf34894e8f57206875f0ce33290ff))
* **desktop:** app-confirm dialogs and phase8 presence-contract alignment ([b9d7bce](https://github.com/Vivswan/chromium-bridge/commit/b9d7bce702ef3e182aabd4eb1abe63f9ba96facc))
* **desktop:** control-panel app UI over the core management engines (ADR-0029) ([4f249fd](https://github.com/Vivswan/chromium-bridge/commit/4f249fd2c1d8736d3baf3108c04043ca59471db0))
* **desktop:** generate the UI's Tauri command types from Rust via ts-rs ([1ca5c25](https://github.com/Vivswan/chromium-bridge/commit/1ca5c251a688066716e4da95ca80df8e4271d6e6))
* **desktop:** overview lifecycle states per the first-run spec ([c19fa80](https://github.com/Vivswan/chromium-bridge/commit/c19fa80908844772716f692e71357683818643c2))
* **desktop:** prove the signed-host entitlement chain (Tauri v2 spike) ([157d479](https://github.com/Vivswan/chromium-bridge/commit/157d479dc787eb7592d9ed72e268302f8d6471cf))
* **desktop:** rebuild UI to the Control Tower design ([ae64937](https://github.com/Vivswan/chromium-bridge/commit/ae649373a3ef64b4f0135522735d9e00495941f2))
* **desktop:** wire the presence gates onto the landed phase8 API (Floor::AppConfirm) ([cbb0e8f](https://github.com/Vivswan/chromium-bridge/commit/cbb0e8fe491e315e63d10323284ccc910eabe7b7))
* **dev:** docs tab + pinned toolbar icon in the WXT dev browser, enforced fresh-profile isolation ([a747253](https://github.com/Vivswan/chromium-bridge/commit/a7472537f09684221b8a1d8941bc4e01545ed4ca))
* **dev:** just dev also runs the desktop app; cut just --list to 12 top-level verbs ([2083014](https://github.com/Vivswan/chromium-bridge/commit/20830144ef4e6e78fc8240574af9a6500fefe6e5))
* **dev:** just dev runs the extension and site together; build includes the site ([6b306a3](https://github.com/Vivswan/chromium-bridge/commit/6b306a3099703902fe09d7c0cebfb0e37e369464))
* **dispatch:** route disable-gate through policy.decide ([c61d1de](https://github.com/Vivswan/chromium-bridge/commit/c61d1de4b33fa9f151cbc546b65316ec754b4825))
* **doctor:** note that green checks don't confirm the extension connected ([#34](https://github.com/Vivswan/chromium-bridge/issues/34)) ([f2710ab](https://github.com/Vivswan/chromium-bridge/commit/f2710ab98eeefe6943ab5059fd0cf1b6e97e941b))
* **enclave:** add the Secure Enclave enrollment ceremony (host side) ([7f0545f](https://github.com/Vivswan/chromium-bridge/commit/7f0545fcde9499ad5536452223f2d201a1606794))
* **error:** map CallError to contracts/errors.json codes ([e900d41](https://github.com/Vivswan/chromium-bridge/commit/e900d4136698bf8c714499cf89b6c1ae8ddddf2d))
* **ext:** bundle JetBrains Mono for identity material ([3c1a53e](https://github.com/Vivswan/chromium-bridge/commit/3c1a53ed1512777b11c17a4b8014f13884905004))
* **extension:** add confirmPageEval / confirmTabClose toggles ([#39](https://github.com/Vivswan/chromium-bridge/issues/39)) ([ed13d55](https://github.com/Vivswan/chromium-bridge/commit/ed13d55bb810424d291b86f802d6661cbbbda019))
* **extension:** add opt-in CDP mode for all page ops ([#37](https://github.com/Vivswan/chromium-bridge/issues/37)) ([ec6d380](https://github.com/Vivswan/chromium-bridge/commit/ec6d3809335817e8d1732ec68aeb3a6ce3e875a5))
* **extension:** add opt-in lazy host re-verification interval ([67ee151](https://github.com/Vivswan/chromium-bridge/commit/67ee15195ceca61b6fdac0ee7f3aad3c5e5a9d2b))
* **extension:** compact engage-only kill control in the confirm window ([9785ff6](https://github.com/Vivswan/chromium-bridge/commit/9785ff6c195c964af5acd11ce4b2e16450798efb))
* **extension:** group AI-opened tabs into a "Browser Bridge" workspace ([#44](https://github.com/Vivswan/chromium-bridge/issues/44)) ([a06387f](https://github.com/Vivswan/chromium-bridge/commit/a06387f2614fbe128d5c3882d2b43b01071c569e))
* **extension:** isolate trust state from content scripts ([#32](https://github.com/Vivswan/chromium-bridge/issues/32)) ([68f31a6](https://github.com/Vivswan/chromium-bridge/commit/68f31a6d23c04bbefb990e34fca0b9bb070d90b0))
* **extension:** localize tool labels through the i18n bundle ([56b56af](https://github.com/Vivswan/chromium-bridge/commit/56b56afae8118480d6b35138997314210ad27f1b))
* **extension:** log a loud warning when the running ID ≠ pinned ID ([#38](https://github.com/Vivswan/chromium-bridge/issues/38)) ([04ca518](https://github.com/Vivswan/chromium-bridge/commit/04ca5182fccb8c0bb712f3fe1c17e4f857292bf3))
* **extension:** mask long opaque tokens in eval/cookie/storage output ([ab0e525](https://github.com/Vivswan/chromium-bridge/commit/ab0e525a77cd1b0bea963c41c03fb21e79b0bc79))
* **extension:** off-DOM confirmations on an extension-owned surface + single page-API source ([9071067](https://github.com/Vivswan/chromium-bridge/commit/907106726ea75712a39f4ee28141a4373504fbe5))
* **extension:** pin the enrollment key and fail closed until paired (ADR-0021) ([3cf06f9](https://github.com/Vivswan/chromium-bridge/commit/3cf06f971026eadabd0eb3d08035bab060c99e5a))
* **extension:** rebuild on WXT with a generated, contract-pinned manifest ([9824b44](https://github.com/Vivswan/chromium-bridge/commit/9824b44fe8a2dc267605b78c63063202015c10a9))
* **extension:** trilingual runtime i18n + React/Radix/Tailwind UI rehaul ([534e5e2](https://github.com/Vivswan/chromium-bridge/commit/534e5e2fe7da59899e64f44965ee721989f0298c))
* **ext:** first-run popup pairing state per the first-run spec ([a7ec8fe](https://github.com/Vivswan/chromium-bridge/commit/a7ec8fe5de8249ab915bb790681733a81c39a73d))
* **ext:** rebuild popup, options, and confirm on the Control Tower design ([f42261d](https://github.com/Vivswan/chromium-bridge/commit/f42261dcb571099ba90be8685a220836880e325d))
* **ext:** restyle the in-page info toast to the Control Tower layout ([2b67727](https://github.com/Vivswan/chromium-bridge/commit/2b677270c4e285ee84744f121200f7409fa7b6e4))
* **ext:** restyle the shared UI primitives to Control Tower motifs ([f2f64ce](https://github.com/Vivswan/chromium-bridge/commit/f2f64ce7c620639bc2f489dea3f2b617d1722a9a))
* file nightly fuzz crashes as tracking issues with seeded replay ([a0c9e75](https://github.com/Vivswan/chromium-bridge/commit/a0c9e752506468b807551872701d542214f69881))
* **fuzz:** add classify_frame, enclave, and manifest targets ([6fe1367](https://github.com/Vivswan/chromium-bridge/commit/6fe136770c46ff8d4e395130892cd3d834dfb9af))
* **fuzz:** add fuzzing feature and handshake_verify target ([d0ea3e3](https://github.com/Vivswan/chromium-bridge/commit/d0ea3e3e1301640421c734f758aecceba82fb56c))
* **fuzz:** seed corpora and dictionaries ([7237fd9](https://github.com/Vivswan/chromium-bridge/commit/7237fd99f71c0e821182861a8b7943da0f41607d))
* **icons:** generate Gatedeck icon assets from SVG sources at build time ([f013928](https://github.com/Vivswan/chromium-bridge/commit/f01392853c62395167936aeca416f6463a21d417))
* implement browser-bridge v0.1 (Rust + MV3 extension) ([1871420](https://github.com/Vivswan/chromium-bridge/commit/187142090a4db6807bc5a0222ce8343a7eb8a21a))
* **install:** clear macOS Gatekeeper quarantine on the installed binary ([#31](https://github.com/Vivswan/chromium-bridge/issues/31)) ([6a8f7b6](https://github.com/Vivswan/chromium-bridge/commit/6a8f7b6d2ddc509bc5fde068c576b14851ddb1a6))
* **install:** per-browser run-host wrappers carrying --label ([bd8fcfc](https://github.com/Vivswan/chromium-bridge/commit/bd8fcfc0bcba406fd08b76352f726b499d737a9d))
* **install:** print resolved client config and optional Claude Code auto-register ([#33](https://github.com/Vivswan/chromium-bridge/issues/33)) ([096a9c5](https://github.com/Vivswan/chromium-bridge/commit/096a9c589da8043e5f06be5a228a0cb814327258))
* **install:** support any Chromium browser via a native-messaging host table ([c8de02f](https://github.com/Vivswan/chromium-bridge/commit/c8de02f014d7cd5bf5c4cf9b59ed7be316e3e1b7))
* **install:** verify the prebuilt binary against the published checksum before install ([c545e60](https://github.com/Vivswan/chromium-bridge/commit/c545e6046ef3e76737554e06a2904b610a4cf034))
* **ipc:** attest bridge peers by kernel-verified executable identity ([13caa7b](https://github.com/Vivswan/chromium-bridge/commit/13caa7b34a2b215185bf373c9301d3ae68a2291c))
* **ipc:** attest macOS bridge peers by audit-token SecCode cdhash ([34c2d64](https://github.com/Vivswan/chromium-bridge/commit/34c2d641b9a3e0644222104a0d52d5a51b1103d3))
* **ipc:** authenticate the bridge with an HMAC challenge-response ([5e5381b](https://github.com/Vivswan/chromium-bridge/commit/5e5381bc799fa2b73de1c64510b63cbccd86ae3f))
* **ipc:** reject cross-user peers via SO_PEERCRED/getpeereid ([73c0e90](https://github.com/Vivswan/chromium-bridge/commit/73c0e90c599a62d83b13d26ae579aa2413a89b0d))
* **ipc:** switch bridge transport to a 0600 unix domain socket ([1ed5dd0](https://github.com/Vivswan/chromium-bridge/commit/1ed5dd06424b2c8e99b53bcd0b0fb91c89704962))
* **mcp:** warn loudly at startup that Windows bridge security is best-effort ([be05afe](https://github.com/Vivswan/chromium-bridge/commit/be05afe9221c81984873c540d148431e05473892))
* migrate .repo-platform.yml to the modules schema ([#12](https://github.com/Vivswan/chromium-bridge/issues/12)) ([1eb4ea0](https://github.com/Vivswan/chromium-bridge/commit/1eb4ea0130ac8c1cd66a2ed2f373e7ec414d6ff0))
* migrate MCP server to spec 2026-07-28 on the official rmcp SDK ([52566aa](https://github.com/Vivswan/chromium-bridge/commit/52566aa9c659e5477b1075cc4e79af39d1c4809f))
* **observability:** per-call request ids + structured audit events ([edda161](https://github.com/Vivswan/chromium-bridge/commit/edda16132aa5863fdc50930a39c6da64251a8175))
* pin the extension ID (manifest key) — no more copy-ID install step ([4085c0a](https://github.com/Vivswan/chromium-bridge/commit/4085c0a756100d1d1e2858860c01e757318a57d2))
* **policy:** additive policy-layer foundation from tool contract ([f7c5985](https://github.com/Vivswan/chromium-bridge/commit/f7c5985c882d927cb0d81f47d15524eb6a52d567))
* prebuilt release pipeline — install without Rust/Node ([5b91bff](https://github.com/Vivswan/chromium-bridge/commit/5b91bff04f023f8fce0249bf93dd096307939ec9))
* **protocol:** reject unknown fields on all bridge wire types (fail closed) ([067e2d9](https://github.com/Vivswan/chromium-bridge/commit/067e2d9dd7fd8f270a8b694a8149cb155feb492f))
* refine tool descriptions, protocol layer, and tab_close confirmation ([a9270e0](https://github.com/Vivswan/chromium-bridge/commit/a9270e0fa2ceeeebaed12b69017342876990d8fb))
* **release:** branded DMG with Gatedeck identity ([5a0e9d2](https://github.com/Vivswan/chromium-bridge/commit/5a0e9d27427a18568b7ce8f226d37359fa59f519))
* **release:** build, verify, and publish the signed desktop .dmg ([31aac97](https://github.com/Vivswan/chromium-bridge/commit/31aac9718b89bd5927728613ce0225b716832a7b))
* **security:** any-side revocation epoch (ADR-0025) ([441b683](https://github.com/Vivswan/chromium-bridge/commit/441b683cfb4ac1dfc0407377829ca16b78bde64e))
* **security:** global kill switch, audit trail, and presence-gated unkill (ADR-0030) ([35340cc](https://github.com/Vivswan/chromium-bridge/commit/35340cc69f255b6d36fda0c0cc254fcf5d331bd8))
* **security:** Touch ID presence gates for crown-jewel tools and capability grants (ADR-0031) ([afababa](https://github.com/Vivswan/chromium-bridge/commit/afababa7d615cf92fcb03dcd278f5a8318eb356e))
* **session:** generation-guarded connection (RFC-0001) ([7701bf2](https://github.com/Vivswan/chromium-bridge/commit/7701bf2807deaa3ae88e059704a5af064eaf2108))
* **session:** hold multiple authenticated browser connections, routed by label ([8fc9260](https://github.com/Vivswan/chromium-bridge/commit/8fc9260c25ed9c5d9d05c2cefa22175c3ea0240f))
* **site:** Control Tower landing page ([f2efe2d](https://github.com/Vivswan/chromium-bridge/commit/f2efe2def3de5302641dea1ba4424ac75a3f8971))
* **tools:** add navigation, keyboard, hover, select, console, dialog, and file-upload tools ([167c753](https://github.com/Vivswan/chromium-bridge/commit/167c753d4c206b0c39be66e81d7141a57bd341a1))
* **ui:** adopt Control Tower design tokens in both apps ([e8a75a0](https://github.com/Vivswan/chromium-bridge/commit/e8a75a0bdf52bbe644193cb97bd3edeee1d4bd84))


### Bug Fixes

* **audit:** correlate confirmation rows by a per-confirmation id ([d6f5578](https://github.com/Vivswan/chromium-bridge/commit/d6f5578c87dac0fb6ba068fee29a5a9da4ea34f7))
* **build:** tauri hooks run from the frontend dir; restore bun run dev/build ([52825cf](https://github.com/Vivswan/chromium-bridge/commit/52825cf885b1cdcb8b4c41de5ab16e8277d4b1d3))
* **ci:** check out full history so moon can resolve the PR base ref ([377b96b](https://github.com/Vivswan/chromium-bridge/commit/377b96b757eedb9a5a9355214773c091b3ab195e))
* **ci:** scope fuzz deny relaxations to a fuzz-only config ([395e6ea](https://github.com/Vivswan/chromium-bridge/commit/395e6eaf3655054c7f4923080e312ce80c6c2236))
* **ci:** unbreak the first nightly run (fuzz musl target, mutants exit 3) ([3f505af](https://github.com/Vivswan/chromium-bridge/commit/3f505af7b273ed3d5795de81a840aa3489df4cdb))
* **contracts:** gate enclave/admin/client wire types in the envelope parity check ([b0bbfb8](https://github.com/Vivswan/chromium-bridge/commit/b0bbfb8933ca7b99308ee4a2f055f6e01a3546a5))
* **core:** centralize secure file permissions in fsguard ([dec75eb](https://github.com/Vivswan/chromium-bridge/commit/dec75eb5bb044a9a56b57811099235ba7bd92fcb))
* **core:** drop the Windows delete-before-rename on security files ([9de977e](https://github.com/Vivswan/chromium-bridge/commit/9de977e47361a71f34a98fc4bea47742f172aa64))
* **core:** emit revocation audit record inside Allowlist::revoke ([badc9bb](https://github.com/Vivswan/chromium-bridge/commit/badc9bbabf30609681c269bc8e37ba48e8df5827))
* **core:** enforce trust-store preconditions and anchor validity in types ([#24](https://github.com/Vivswan/chromium-bridge/issues/24)) ([397b0f1](https://github.com/Vivswan/chromium-bridge/commit/397b0f1e63509c4833317f21aeeade17520e6589))
* **core:** gate Unix-only imports so Windows clippy is clean, and gate it in CI ([fcf121f](https://github.com/Vivswan/chromium-bridge/commit/fcf121f4e0a406f37b04856c533d506e0777be17))
* **core:** harden the unsafe FFI quarantine per audit findings ([ff1a798](https://github.com/Vivswan/chromium-bridge/commit/ff1a7988c166f1dbbaf3012e1d235b91b1b6eaf2))
* **core:** write config.json via the hardened write_private_atomic ([caf683e](https://github.com/Vivswan/chromium-bridge/commit/caf683e77dd87024ea772f71a711f1424cef6562))
* correctness + robustness hardening (Phase 0) ([04bde1a](https://github.com/Vivswan/chromium-bridge/commit/04bde1ab5ded544818f709e2f53e494d09a7bc69))
* cover desktop ui package.json in release-please and guard version sync ([#23](https://github.com/Vivswan/chromium-bridge/issues/23)) ([ee78f46](https://github.com/Vivswan/chromium-bridge/commit/ee78f46eadaa712fbd1b196bfbd715cbb0d1fc58))
* **desktop:** a11y and interaction polish from the design gauntlet ([c4f7077](https://github.com/Vivswan/chromium-bridge/commit/c4f7077c9bda6be6b94df421f3923460788be381))
* **desktop:** box the AuditLine::Record variant after cid grew AuditRecord ([f6dc08b](https://github.com/Vivswan/chromium-bridge/commit/f6dc08bf5338423444f65623d56619498e6c3743))
* **desktop:** correlate confirm rows and keep green out of the audit ledger ([48ae379](https://github.com/Vivswan/chromium-bridge/commit/48ae37913a22b241366db6e51ac2523e9b5588b0))
* **desktop:** green means live+attested only; fail closed on stale status ([996ff59](https://github.com/Vivswan/chromium-bridge/commit/996ff59492e7f3cf20161420d0e45e9335ec2c2f))
* **desktop:** make first-launch registration opt-in and browser actions truthful ([86a6293](https://github.com/Vivswan/chromium-bridge/commit/86a629325aa5909f56c7d03bd460785968b9136e))
* **desktop:** render the enclave fingerprint in the extension's lowercase form ([1db2e0a](https://github.com/Vivswan/chromium-bridge/commit/1db2e0a654c5c759a83dc33c6f7e521ff081abaa))
* **desktop:** render unreadable kill and rejected key honestly on Overview ([a7fd0ef](https://github.com/Vivswan/chromium-bridge/commit/a7fd0efc237cbddac2f5ee740042b3fea34d6f0c))
* **desktop:** wrap long paths and commands on the Setup page ([6cab4d5](https://github.com/Vivswan/chromium-bridge/commit/6cab4d51deac07cdf0df2a5769c4b28e9e68e98c))
* **dev:** fail closed on the two dev-browser ownership gaps the gate found ([8b03cb8](https://github.com/Vivswan/chromium-bridge/commit/8b03cb86a95909d788021b3fa60b2e48686ddcd0))
* **dev:** pin the astro dev server lifecycle: stop stale servers, no auto-daemonization ([1c06fff](https://github.com/Vivswan/chromium-bridge/commit/1c06fff3206a8164e5ab8ea13e9f92d68c741ec7))
* **dev:** sweep the tauri process group when its leader dies; docs match the 12-verb list ([b2523ad](https://github.com/Vivswan/chromium-bridge/commit/b2523adf7515b4e84eeb8c1935fe7d2b08907493))
* **doctor:** require the app bundle for macOS browser detection ([400cc73](https://github.com/Vivswan/chromium-bridge/commit/400cc73cb5e95e86352d4261a54fa863960a7cbe))
* **extension:** announce, localize, and animate the in-page notice ([d91c819](https://github.com/Vivswan/chromium-bridge/commit/d91c81901979aa879c7782de6c981768ce5b0c7e))
* **extension:** bind confirmed ops to their origin and parse reply envelopes fail-closed ([#25](https://github.com/Vivswan/chromium-bridge/issues/25)) ([46f0ff0](https://github.com/Vivswan/chromium-bridge/commit/46f0ff0eb41e43ae6446584549823692c756804e))
* **extension:** confirm the enrollment gate inside the transition queue ([cda362c](https://github.com/Vivswan/chromium-bridge/commit/cda362c44ac36677ae11ddaa92b915a1e2f36999))
* **extension:** disarm pending-origin Allow unless kill state reads alive ([30a366b](https://github.com/Vivswan/chromium-bridge/commit/30a366b91c365af2da7373301f1151bd7c9f8274))
* **extension:** fail-closed popup kill display and pairing-first hierarchy ([08614b4](https://github.com/Vivswan/chromium-bridge/commit/08614b4643662e2224b8266b3a376f831ed31b6a))
* **extension:** gate every runtime message behind an extension-page sender ([#32](https://github.com/Vivswan/chromium-bridge/issues/32)) ([75a057c](https://github.com/Vivswan/chromium-bridge/commit/75a057c13fbfcf776fb0750e3e6a196a01552d3b))
* **extension:** gauntlet copy pass across all three locales ([3d1f196](https://github.com/Vivswan/chromium-bridge/commit/3d1f196067fa38e2064dde33e4900d3c17696524))
* **extension:** harden the confirm window's content honesty ([828d25b](https://github.com/Vivswan/chromium-bridge/commit/828d25bfa8177c9255c2d41d43e44b99660f2984))
* **extension:** keep confirm decision controls on screen under long payloads ([082050f](https://github.com/Vivswan/chromium-bridge/commit/082050f197e791ff5d9fc06f8a891b6b434047fc))
* **extension:** mask every page_eval egress, not just the success value ([37a65b0](https://github.com/Vivswan/chromium-bridge/commit/37a65b022692b3d917bdc2d4f14841daa1a21c43))
* **extension:** options honesty, hierarchy, and a11y ([d4dbbec](https://github.com/Vivswan/chromium-bridge/commit/d4dbbec002c6952fa206959787f7296d1cd62269))
* **extension:** parse enclave_error frames with their declared schema ([6ed4c63](https://github.com/Vivswan/chromium-bridge/commit/6ed4c63923712da05ebec07f7cebc2bdcb76c872))
* **extension:** pinned fresh pairing supersedes a stale host-key revoke ([7307fd1](https://github.com/Vivswan/chromium-bridge/commit/7307fd157413606187d864c6accca5b015d03701))
* **extension:** reconfirm every page_eval by excluding it from the grace window ([c760b4a](https://github.com/Vivswan/chromium-bridge/commit/c760b4a727e3ef1a67f811c4f381808fd867597b))
* **extension:** scope enrollment enforcement to Enclave-capable platforms ([bff9e22](https://github.com/Vivswan/chromium-bridge/commit/bff9e2221bfa2ce8d4c37f32d78689746419071d))
* **fsguard:** compile warning-free on windows ([a634abe](https://github.com/Vivswan/chromium-bridge/commit/a634abe94b8cbf8a3b9e1fb3475cc69e97eedbcd))
* **gen:** harden union handling and the adversarial harness per cross-model review ([d7801a3](https://github.com/Vivswan/chromium-bridge/commit/d7801a32d60074472ca64727c3a38aa97f38721c))
* **i18n:** English as the canonical language on every surface ([b40e8d2](https://github.com/Vivswan/chromium-bridge/commit/b40e8d2477e302bcd14a30896324b4d670eddbd0))
* **install:** require build-provenance attestation on the online verify path ([a34fb79](https://github.com/Vivswan/chromium-bridge/commit/a34fb7914d75b8a5cfcbc966164ca368fe8300f2))
* **install:** restrict install dir to owner-only (0700) ([8d54093](https://github.com/Vivswan/chromium-bridge/commit/8d54093d7e7f9407c7fa4b65806f70349d5701a2))
* **ipc:** cap the lock read and create the lock tmp exclusively ([87d6367](https://github.com/Vivswan/chromium-bridge/commit/87d6367fedbf077f8755b6e03e609322f69a4f26))
* **ipc:** fail closed if the OS CSPRNG is unavailable ([58e69d9](https://github.com/Vivswan/chromium-bridge/commit/58e69d9abdb06aeb0c8b126e9c40d231f020c813))
* **ipc:** keep the new server's socket alive across takeover ([e87cb75](https://github.com/Vivswan/chromium-bridge/commit/e87cb75a4459a8be67a840cbddc651b912048c90))
* **ipc:** reject non-hex handshake MAC without panicking ([e550994](https://github.com/Vivswan/chromium-bridge/commit/e55099482f6bcf4b970915e2ce791fc3539c3bb5))
* **just:** restore ci's one-line doc string in just --list ([c672b36](https://github.com/Vivswan/chromium-bridge/commit/c672b363a9ac415faa94e09b66c7ffdcffb8dd85))
* **kill:** drain and clear the browser registry in the sweep itself, not via reader wakeup ([b05e976](https://github.com/Vivswan/chromium-bridge/commit/b05e97666b4dd79e98d952a1aecdd13683622b9d))
* **kill:** harden the confirm-window panic-latch release lifecycle ([2ed5c22](https://github.com/Vivswan/chromium-bridge/commit/2ed5c229132c26c34a49d1b64a83c214c87bc56f))
* **kill:** require an authoritative killed frame for panic-latch refusal proof ([72d70c7](https://github.com/Vivswan/chromium-bridge/commit/72d70c77c47dff043af49cd67b56340ff2f97a41))
* MCP server supplants stale instances; tool calls wait for host connect ([0217ba0](https://github.com/Vivswan/chromium-bridge/commit/0217ba01e62285015651e26a9fa01ecdcaa2ef41))
* **mcp:** attest lock-file pid identity before takeover SIGTERM ([2a9f143](https://github.com/Vivswan/chromium-bridge/commit/2a9f143853c49918b54150fe5f1316bd1dbaf138))
* native host no longer zombies when MCP server is supplanted ([26c16f5](https://github.com/Vivswan/chromium-bridge/commit/26c16f5e2af383108a21cad9494a93a86e2cc0fb))
* **native-host:** cap the socket receive leg ([f9b6281](https://github.com/Vivswan/chromium-bridge/commit/f9b6281480956462beb7ba2f6480d2d3e662e9f2))
* **native-host:** drop server-injected enclave frames on the socket leg ([17c84b6](https://github.com/Vivswan/chromium-bridge/commit/17c84b6b24a9ef97d9c9b7661ca20c3eb79cb153))
* point extension tsconfig at jest-dom 7's vitest types entry ([083a769](https://github.com/Vivswan/chromium-bridge/commit/083a769bdcf7e93a8dd8d3cb1d3175c33bea8077))
* **protocol:** bound and de-recurse mcp_read on the client leg ([e1a4585](https://github.com/Vivswan/chromium-bridge/commit/e1a4585bc6d1e5dfcff4f9611bdd848d52dd3319))
* **protocol:** bound bridge_read to prevent unbounded allocation ([863847f](https://github.com/Vivswan/chromium-bridge/commit/863847fb1c735ca2b60373cf8e73f89f83727848))
* **release:** adapt release automation and code owners to the workspace ([66a979a](https://github.com/Vivswan/chromium-bridge/commit/66a979a13de7dbf425c9be6d33cb59669d97df4a))
* **release:** DMG art speaks the Gatedeck deck language ([f61c576](https://github.com/Vivswan/chromium-bridge/commit/f61c576bff0f8a7db183aabe575bfa606133788a))
* **release:** publish the extension zip from an explicit macos-only step ([7ec7251](https://github.com/Vivswan/chromium-bridge/commit/7ec725117429b269a5f6c35f0697d59c0158ed6c))
* **release:** route Intel Macs to build-from-source, not Rosetta ([597d1ef](https://github.com/Vivswan/chromium-bridge/commit/597d1ef6bd3afaf219b04c3a2ee44af74a265215))
* **runbook:** phase8-touchid-proof must use the signed bundle host ([00a9f1e](https://github.com/Vivswan/chromium-bridge/commit/00a9f1ebca3a0464ad1e2c26e97f0376e1fc9803))
* **runbook:** touchid-gates prints the CLI capability-grant steps ([353c18c](https://github.com/Vivswan/chromium-bridge/commit/353c18cc082aa8cace8a1140f2c735248357c622))
* **scripts:** parse hasher.ignorePatterns with Bun.YAML instead of a regex line scan ([5775818](https://github.com/Vivswan/chromium-bridge/commit/57758183fa7621ba6a84ab8ab93ea4e3f15e04a6))
* **site:** correct security claims and install steps to match the docs ([3a24fe2](https://github.com/Vivswan/chromium-bridge/commit/3a24fe25f9753622289b182b9532a78a1bb374dc))
* **site:** scope the Enclave and enrollment claims to what the docs support ([379dc82](https://github.com/Vivswan/chromium-bridge/commit/379dc821ff4d932a30aedd59af22df853c1d3ff0))
* **site:** send relative directory links to the GitHub tree instead of 404 routes ([72e5d40](https://github.com/Vivswan/chromium-bridge/commit/72e5d4086896263bba04eb712c876854fbe7e0e9))
* **site:** the bridge has no silent enrollment path (scope to what ADR-0031 claims) ([4ada799](https://github.com/Vivswan/chromium-bridge/commit/4ada799030778aebc5d1f4e497949c436b64092d))
* teach both cargo-deny license gates about the source-available relicense ([b71f87f](https://github.com/Vivswan/chromium-bridge/commit/b71f87f2e021c526747bfd473370e2de7532af31))
* **test:** make cli and registration path fixtures Windows-correct ([b38f2b6](https://github.com/Vivswan/chromium-bridge/commit/b38f2b617a90add11d2f978486bef919c30207c0))
* **tests:** await Page.loadEventFired in the CDP client instead of fixed sleeps ([0c3b347](https://github.com/Vivswan/chromium-bridge/commit/0c3b347b1de93e4a08a7439f6e85c52991cc6729))
* **tests:** make server_stderr non-blocking on a live server; drop the duplicate accessor ([39bce93](https://github.com/Vivswan/chromium-bridge/commit/39bce931615ea40d6ac11fa886566477ee7dfee2))
* **tests:** state the true native-messaging gap (no host registration) and probe it ([26dba69](https://github.com/Vivswan/chromium-bridge/commit/26dba6912c44b96f8f473821506c491cdcb2f12d))
* **tools:** reconcile page_eval description with reconfirm-every-call behavior ([99057a8](https://github.com/Vivswan/chromium-bridge/commit/99057a854a2875bd16db4b4264bddd14f13034ac))
* **typography:** replace look-alike punctuation in Rust sources with ASCII ([765e5da](https://github.com/Vivswan/chromium-bridge/commit/765e5dabc8fb947086a88f8d360f86827cd12caf))
* **typography:** replace stray em-dashes/ellipses with ASCII; shrink .typography-allow to exact paths ([c3ab1de](https://github.com/Vivswan/chromium-bridge/commit/c3ab1de576a824fa300f9755cfa19295cf48a785))
* **web:** allowlist the rendered root docs instead of denylisting scratch notes ([845f608](https://github.com/Vivswan/chromium-bridge/commit/845f608da6224e7143a8cc6fa4d1effdfeb166b7))
* **web:** fail the build on a trailing-slash md link to a non-directory ([501d66e](https://github.com/Vivswan/chromium-bridge/commit/501d66e344907f288ff157d0a89f833187706e5b))


### Miscellaneous Chores

* relicense to the Individual and Small Organization License 1.0.0 ([f6d5824](https://github.com/Vivswan/chromium-bridge/commit/f6d58244664db3fe763e9957f89cde7fe5585926))


### Code Refactoring

* carve out a cargo workspace and rebrand to chromium-bridge ([052af98](https://github.com/Vivswan/chromium-bridge/commit/052af988dabba05c5cf8c4a842ecd3bb9957fa55))


### Build System

* make moon the canonical command interface and adopt proto ([305c5ef](https://github.com/Vivswan/chromium-bridge/commit/305c5ef64e02ea8e3f71d014e1bf8d3325f91a11))

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
