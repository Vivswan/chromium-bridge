# 開發指南

本頁涵蓋本機開發迴圈、工具鏈、測試與模糊測試的機制, 以及一次發行會更動的版本副本。分支、提交與合併的工作流程見 [CONTRIBUTING.md](../../CONTRIBUTING.md); 專案為何如此設計, 見 [architecture.md](./architecture.md) 與 [security/rationale.md](./security/rationale.md)。

## 先決條件

[proto](https://moonrepo.dev/proto) 是啟動用的工具鏈管理器: 安裝一次, 把 `~/.proto/shims` 和 `~/.proto/bin` 加入 PATH, 之後在新簽出的儲存庫裡執行一次 `proto install`, 就會佈建儲存庫根目錄 `.prototools` 所固定的每個工具 (bun、moon、node、uv)。

Rust 只由 rustup 管理, 來自 `rust-toolchain.toml`, 所以新機器要先安裝 [rustup.rs](https://rustup.rs)。proto 刻意把 rust 留給 rustup: proto 的 rust 外掛會註冊一個工具鏈, 而 rustup 隨後會誤以為它已安裝。接著:

```sh
proto install    # provisions bun, moon, node, uv at the pinned versions (rustup owns rust)
moon run setup   # installs the bun workspace, the pinned Rust toolchain, and the crates; wires the git hooks (lefthook); the gate itself never installs
```

有四個工具沒有第一方的 proto 外掛, 需手動安裝一次: `cargo install cargo-nextest` (`moon run gate` 使用的測試執行器) 與 `brew install typos-cli cargo-machete actionlint` (只有 `moon run ci` 才執行的工具; typos 與 cargo-machete 也可透過 `cargo install` 取得)。CI 從哪裡取得它們:

- **`Containerfile` 以 `ARG <TOOL>_VERSION` 固定這四個工具加上 cargo-deb**。CI 映像檔帶有這四個; cargo-deb 只安裝在裸機的發行與安裝程式執行器上。
- **自行安裝某個工具的工作透過 `bun scripts/pin.ts <tool>` 讀取同一個固定版本**: checks.yml 的 tooling 工作讀 cargo-machete (在映像檔內, 該版本已經就位), `installers.yml` 與 `update-release.yml` 在各自的裸機執行器上讀 cargo-deb。
- **typos 與 actionlint 經由受管理的 ci.yml 的 fleet actions 執行**, 使用平台自己的固定版本, 所以本機的版本偏差最壞也只是提早浮現一項發現。

| 工具 | 用途 | 備註 |
|------|----------|-------|
| [proto](https://moonrepo.dev/proto) | 工具鏈啟動 | 佈建 `.prototools` 固定的一切, 本機與 CI (`.github/actions/setup-moon`) 皆然; 唯一同時存在於別處的固定版本 (bun) 由 `moon run check-toolchain` 交叉檢查 |
| [moon](https://moonrepo.dev) | 任務執行器 | 標準的命令介面: 每個開發工作都是一個 moon 任務。`moon run help` 列出全部; `moon run <task>` 執行其中一個 |
| Rust (cargo) | `chromium-bridge` 執行檔 | 由 `rust-toolchain.toml` 固定 (權威的固定來源; rustup 與 IDE 都讀它); `rustfmt` + `clippy` 元件, 以 `cargo-nextest` 作為測試執行器 |
| bun | 所有 TypeScript | 套件管理器、指令碼執行器、擴充功能打包、TS 測試套件。固定於 `.prototools` (並鏡像到 `package.json` 的 `packageManager`) |
| node | vitest 測試套件 (`extension:test`) | 只固定於 `.prototools`; 由 proto 佈建, 所以沒有任何工作或映像檔自行安裝 |
| [`uv`](https://docs.astral.sh/uv/) | 協定 e2e 測試 | 佈建儲存庫根目錄 `.python-version` 所固定的確切 Python 版本, 讓本機執行與 CI 使用同一個直譯器。uv 本身只固定於 `.prototools`。測試套件僅使用標準函式庫 |
| Chrome | DOM + 冒煙測試 | `CHROME_BIN` 覆寫路徑 |
| [`typos`](https://github.com/crate-ci/typos) + [`cargo-machete`](https://github.com/bnjbvr/cargo-machete) | 拼字 + 未使用相依套件閘門 | `moon run typos` / `moon run machete`; CI 在受管理的 ci.yml 中把關 typos, 在 checks.yml 中把關 machete |
| [`actionlint`](https://github.com/rhysd/actionlint) | GitHub Actions 工作流程 lint 閘門 | `moon run check-actions`; CI 在受管理的 ci.yml 的 actionlint 工作中執行 |

Git hooks 由 [lefthook](https://lefthook.dev) 管理 (`lefthook.yml`): `moon run setup` 會接上多個 hooks, 在提交前與 rebase 後執行 `moon run gate`, 即儲存庫自身工具鏈所能提供的檢查; `moon run ci` 再加上只有 CI 才配備的工具。

## 目錄配置

TypeScript 這一側是一個以儲存庫頂層為根的 bun 工作區 (`package.json` 的 `workspaces`), 只有一個 `bun.lock` 和一棵 node_modules 樹。可建置的程式碼位於 `src/` 之下 (apps 與 packages); 那裡的每個目錄都是 cargo 工作區或 bun 工作區的成員, 所以一道閘門就能編譯整張圖。TS 套件把原始碼與測試分開存放 (`src/` 與 `tests/`)。

```text
src/apps/host/           Rust binary "chromium-bridge" (thin argv dispatch over the library)
src/apps/extension/      MV3 extension (WXT); builds to build/extension (gitignored)
src/apps/web/            the Astro landing page (bun workspace member; moon run web:build; not part
                         of `moon run ci`); the docs site is the fleet's render of docs/
src/packages/core/       Rust library "chromium-bridge-core": MCP server + native-host bridge
src/packages/core/fuzz/  cargo-fuzz workspace: wire parsers + semantic validators
                         (nightly + libFuzzer; see the Fuzzing section below)
src/packages/shared/     contract types / validators / i18n (bun workspace member)
tests/protocol/          e2e.py, adversarial.py, chaos.py - drive the real release binary
tests/browser/           the browser suites (run_all.ts lists them); integration_e2e.ts and
                         presence_exchange_test.ts run apart (bun workspace member; isolated Chrome only)
tests/interop/           the official MCP SDK client against the release binary (bun workspace member)
tests/harness/           harness-smoke: real harness CLIs in isolated config dirs
tests/fixtures/          HTML/CSS pages and the probe extension the browser suites load
scripts/                 bun workspace member: gen-ops.ts, check-version.ts, check-extension-id.ts,
                         check-docs-literals.ts, check-docs-policy.ts, build-repro.ts,
                         fuzz-smoke.ts, lib.ts, ...; unit tests in scripts/tests/
```

所有工具指令碼都是以 bun 執行的 TypeScript, 放在 `scripts/` 這個 bun 工作區成員裡。moon 的 `script:` 或工作流程的 `run:` 只保留一條直線式的工具呼叫; 一旦需要控制流程、輸出解析或錯誤處理, 就改寫成這裡的一個指令碼, 並在 `scripts/tests/` 附上單元測試。

有兩個指令碼, `scripts/build-repro.ts` 與 `scripts/fuzz-smoke.ts`, 只依賴 node 內建模組而自給自足, 因此不需 `bun install` 就能執行: 發行工作流程在安裝工作區之前就先建置執行檔, 而夜間模糊測試工作則完全不安裝工作區。

相依套件由自動化的供應鏈檢查把關, 沒有逐一人工稽核 crate 的步驟; 各層級以及各自能攔截什麼, 見 [SECURITY.md](../../.github/SECURITY.md#dependency-supply-chain)。`moon run audit` 可在本機重現 cargo-deny 的檢查。

## 常用工作

moon 是標準的命令介面: 每個開發工作都是一個 moon 任務, `moon run help` 會印出帶說明的完整選單 (原始 JSON: `moon query tasks`)。未限定範圍的名稱 (`moon run ci`) 解析到根專案; 各專案的任務寫成 `project:task` (`moon run extension:build`)。

```sh
moon run build     # build everything (see below)
moon run dev       # dev everything: extension (WXT) + the landing page (Astro) + a dev browser
moon run test      # rust tests (nextest + doctests) + protocol e2e
moon run ci        # THE GATE: the cross-platform CI steps (see below for what CI adds)
moon run release   # pre-release gate: version checks + full ci
moon run install   # build the release binary, then register it (doctor --fix)
moon run lint      # lint everything: clippy -D warnings + biome lint
moon run fmt       # format everything: cargo fmt + biome format
moon run fix       # auto-fix everything: biome check --write + cargo fmt
```

`moon run build` 用一道命令建置整個儲存庫: 對 `src/packages/shared` 做型別檢查、打包擴充功能 (先算繪其圖示)、建置登陸頁、對 `scripts/` 做型別檢查, 並執行 `cargo build --workspace`。用它來證明跨領域的變更之後整張圖仍可編譯。

`moon run ci` 依其 `deps` 清單宣告的順序執行跨平台的閘門步驟:

| 步驟 | 任務 |
|------|-------|
| Rust | `core:fmt-check`、`core:lint` (每個 cargo 工作區各執行一次, 根工作區與模糊測試工作區)、`typos`、`machete`、`core:test`、`core:test-doc`、`core:test-loom`、`doc` |
| TypeScript | `typecheck`、`check-ts`、`shared:test`、`extension:test`、`extension:build` |
| 協定 | `test-e2e` |
| 衛生 | `hygiene` (下方的 bun 側檢查)、`check-refresh-lockfiles`、`test-fuzz` |
| 契約 | `check-envelope`、`check-gen-isolation` |
| 工作流程 | `check-yaml`、`check-actions` |

CI 在此之上還會執行更多: macOS 與 Windows 的 rust 矩陣、覆蓋率、linux-install、adversarial 與 chaos 測試套件、互通測試套件、瀏覽器測試套件、安裝程式、網站建置, 以及各項稽核 (見下方的 [CI 配置](#ci-配置))。

根目錄 `package.json` 的 scripts 是薄薄的別名, 所以兩個進入點共用同一份實作:

| `bun run ...` | moon 任務 |
|------|------|
| `build`、`gen`、`typecheck` | 同名任務 |
| `lint`、`format`、`format:check`、`check`、`test` | `lint-ts`、`fmt-ts`、`fmt-check-ts`、`check-ts`、`test-ts` |

全儲存庫層級的動詞一次涵蓋所有語言: `moon run lint` 是 clippy 加 biome lint, `moon run fmt` 是 cargo fmt 加 biome format, `moon run test` 是 Rust 加協定 e2e。每個任務本體都是一道你也能手動執行的普通命令:

```sh
bun install
moon run gen                             # the TS side of the Rust contract: the tsc run and the extension build read it; the moon tasks build it themselves
bun run --cwd src/apps/extension wxt prepare   # the WXT tsconfig and module types the extension's tsc reads; moon's extension:prepare
cargo build --release
cargo nextest run
cargo fmt --check && cargo clippy --all-targets -- -D warnings
# the fuzz workspace is excluded from the root one, so its two checks run against its own manifest
cargo fmt --check --manifest-path src/packages/core/fuzz/Cargo.toml
cargo clippy --locked --manifest-path src/packages/core/fuzz/Cargo.toml --all-targets -- -D warnings
uv run --no-project --isolated tests/protocol/e2e.py
bun run tsc -p src/apps/extension        # one TS project; `moon run typecheck` covers them all
moon run check-ts                        # Biome lint + format check, warnings fail (biome.jsonc)
bun run --cwd src/apps/extension build
```

完整的任務選單, 依領域分列:

| 領域 | 任務 |
|------|-------|
| 彙總 | `build`、`test`、`ci`、`hygiene` (CI 的 hygiene 工作所執行的 bun 側檢查; `ci` 相依於它)、`release`、`lint`、`fmt`、`fix` |
| 開發迴圈 | `dev`、`dev-web`、`extension:dev` |
| Rust | `core:fmt-check` (= `core:fmt-check-workspace` + `core:fmt-check-fuzz`)、`core:lint` (= `core:lint-workspace` + `core:lint-fuzz`)、`test-rust` (= `core:test` + `core:test-doc` + `core:test-loom`, 即核心 `loom` 功能下的中介 (broker) 參考計數模型檢查)、`doc`、`build-release`、`build-repro`、`typos`、`machete`、`audit` |
| 模糊測試工作區 | `fuzz-seeds`、`fuzz-smoke`、`check-fuzz-smoke`、`test-fuzz` (該工作區的 clippy 與 fmt 檢查分別由 `core:lint-fuzz` 與 `core:fmt-check-fuzz` 執行) |
| TypeScript | `typecheck`、`test-ts` (= `shared:test` + `extension:test` + `check-harness-driver`)、`lint-ts`、`check-ts`、`fmt-ts`、`fmt-check-ts`、`extension:prepare`、`extension:build`、`web:build` |
| 契約程式碼產生 | `gen` (= `gen-shared` = `gen-ops` + `gen-envelope`)、`gen-icons`、`gen-architecture-map`、`check-envelope`、`check-gen-isolation` |
| 協定測試套件 | `test-e2e`、`test-adversarial`、`test-chaos`、`check-uv` |
| 互通測試套件 | `test-interop` (官方 MCP SDK v2 用戶端對發行執行檔)、`harness-smoke` (真實的用戶端程式 (harness) CLI 搭配隔離的設定目錄; 舊時代開啟方式的金絲雀) |
| 瀏覽器測試套件 | `test-browser`、`test-integration` (僅限隔離的 Chrome; 絕不納入 `ci`) |
| 版本管理 | `check-version`、`check-extension-id`、`check-refresh-lockfiles` |
| 儲存庫衛生 (`hygiene` 的 deps) | `check-version`、`check-extension-id`、`check-toolchain`、`check-pins`、`check-hasher`、`check-moon-edges`、`check-ignored`、`check-install-hooks`、`check-cjk`、`check-typography`、`check-fuzz-smoke`、`check-harness-driver`、`check-docs-literals`、`check-docs-policy`、`check-planning-refs`、`check-compose`、`check-ci-scripts`、`check-docs-probe`、`check-architecture`、`check-docs-locales` |
| 工作流程 | `check-yaml`、`check-actions` |

`check-docs-probe` 讓英文文件的每個段落與清單項目都維持在 70 字以內, 並讓它們點名的每條路徑都真實存在。翻譯頁面 (位於 `zh-cn` 或 `zh-tw` 文件樹下, 或根目錄的 `README.<locale>.md`) 只探測路徑與連結: 以空白切分的字數讀不懂 CJK, 所以由英文頁面承擔字數上限, 而 `check-docs-locales` 讓翻譯樹與它逐檔鏡像。

## moon: 標準的命令介面

每個任務只有一份定義並宣告其輸入: 全儲存庫層級的任務與操作手冊放在根目錄的 `moon.yml`, 各專案 (`core`、`shared`、`extension`、`web`) 的任務放在其程式碼旁的 `moon.yml`。

CI 執行同樣的任務: 儲存庫自有的 `.github/workflows/checks.yml` 凡有對應任務的步驟都呼叫 `moon run <task>`。Rust 的作業系統矩陣保留原始的 cargo 動詞, 而 `runInCI: false` 的測試套件 (例如 `test-interop`) 則直接呼叫, 因為 `CI=true` 時 moon 不會解析它們。

**閘門永不快取。** 依工作區預設, 每個任務都不快取 (`.moon/tasks/all.yml` 中的 `taskOptions.cache: false`): 能被快取命中滿足的閘門就不是閘門, 因為錯誤的雜湊會讓未經驗證的程式碼落地。moon 無法雜湊像產生出來的 `.wxt/tsconfig.json` 這類被 gitignore 的輸入, 而一個寫錯的 `hasher.ignorePattern` 會悄悄把受追蹤的檔案從每個雜湊中剔除。

兩個選擇重新開啟快取的任務 (`web:build`、`shared:typecheck`) 都不是閘門步驟。因此 `moon run ci` 一律執行完整套件, 並依其 `deps` 清單宣告的固定順序進行 (`runDepsInParallel: false`)。底層工具 (cargo、tsc、vite、bun) 保有各自的增量快取, 所以暖機後的重跑依然快速。

除了統一的任務詞彙之外, moon 還帶來什麼:

```sh
moon run extension:build   # one task, one definition, used by dev + CI
moon run :test             # every project's test task
moon ci                    # affected-only, based on touched files - a LOCAL
                           # convenience for quick iteration, NEVER the gate
```

**契約邊永不收窄。** Rust 核心是標準的跨程序契約, 所以 `shared` 與 `extension` 的任務把整個核心 crate、每個 `scripts/gen-*.ts` 指令碼以及 cargo 資訊清單都宣告為輸入: 即 `.moon/tasks/all.yml` 中的 `rust-contract` 檔案群組。

這份清單刻意過寬, 因為契約路徑上的過期結果是這個儲存庫唯一不能接受的失敗模式。編輯這些任務定義時, 放寬輸入永遠安全, 收窄輸入永遠不安全。

不納入任何雜湊的內容:

- **產生與下載的輸出** (target、build、.wxt、算繪後的圖示、模糊測試語料庫與產物) 列在 `.moon/workspace.yml` 的 `hasher.ignorePatterns`。新的被 gitignore 的輸出目錄也放這裡; 忘了放只會過度失效, 不會過期。
- **受追蹤的檔案不得符合任何模式:** `moon run check-hasher` (閘門的一部分) 負責證明這一點。
- **moon 自身的狀態** 位於被 gitignore 的 .moon/cache 目錄; `rm -rf .moon/cache` 就是重置按鈕。

## 工具鏈固定 (proto)

`.prototools` 固定 proto 本身、bun、moon、node 與 uv; `proto install` 一次佈建全部, 而 rust 只透過 rustup 來自 `rust-toolchain.toml`。CI 以同樣方式佈建, 透過單一的複合 action `.github/actions/setup-moon`, 每個需要工具鏈的儲存庫自有工作都用它:

1. `setup-bun` 安裝 `.bun-version` 指定的 bun, 只用來執行固定版本讀取器。
2. `bun scripts/pin.ts proto` 讀取 proto 自身的版本, 這是 `moonrepo/setup-toolchain` 唯一讀不到的固定版本。
3. 該 action 安裝 proto, 接著 `proto install` 佈建 `.prototools` 的工具 (它的 bun 疊在第一個之上, 所以裸機執行器會有兩個)。
4. 設定 `cargo: "true"` 時, `setup-rust-toolchain` 依 `rust-toolchain.toml` 安裝 rust。

CI 映像檔 (`Containerfile`) 在建置時執行同一個 `proto install`, proto 版本以它唯一的建置引數傳入 (`container-image.yml` 與 `scripts/compose-run.ts` 以 `bun scripts/pin.ts proto` 計算)。在映像檔內, 該 action 會發現一切就緒, 只重跑 `proto install`; 除非映像檔發布後有固定版本變動, 否則那是個空操作。

`bun scripts/pin.ts <tool>` 是在 proto 存在之前唯一需要的固定版本讀取器。它同時掃描兩個擁有者檔案, 並在某個工具被同時固定於兩處、重複固定或完全未固定時失敗; `bun scripts/pin.ts --all` 以同一規則掃過兩個檔案的每個固定版本, 而 `moon run check-pins` (隸屬於 `hygiene`) 執行這次掃描以及讀取器的單元測試:

| 工具 | 擁有者檔案 | 行的格式 |
|-------|------------|------------|
| proto、bun、moon、node、uv | `.prototools` | `tool = "x.y.z"` |
| cargo-nextest、typos、actionlint、cargo-machete (映像檔的工具) 與 cargo-deb (發行與安裝程式執行器的工具) | `Containerfile` | `ARG <TOOL>_VERSION=x.y.z` |

有一個固定版本也存在於第二個檔案, 而 `moon run check-toolchain` (閘門與 CI hygiene 工作的一部分) 會在兩份副本不一致, 或 `.prototools` 竟固定了 rust、啟用了 proto 的 rust 或 python 外掛時失敗:

- **bun**: 鏡像於 `package.json` 的 `packageManager` 與範本管理的 `.bun-version`。

uv 只固定於 `.prototools`, 而 python 由 uv 擁有: 協定測試套件透過 `uv run --no-project --isolated` 在 `.python-version` 固定的直譯器下執行。proto 刻意永不佈建 python (`.prototools` 中的 `settings.builtin-plugins`)。

## CI 配置

`checks.yml` 把每個關注點定義一次, 由受管理的 ci.yml 在 all-green 閘門內呼叫。Linux 工作在已發布的 CI 映像檔 (`ghcr.io/<owner>/<repo>-ci:latest`, 由 `container-image.yml` 從 main 建置) 內執行。

工作流程層級的 `CI_IMAGE_TAG` 是唯一的開關: 空值會讓每個工作改以同一個複合 action 在裸機執行器上執行。

| 工作 | 執行內容 | 位置 |
|-----|------|-------|
| `image` | 把映像檔標籤解析成摘要一次, 讓每個工作固定到同一份內容 | 裸機執行器 |
| `rust` | 在 ubuntu、macOS 與 Windows 上執行 clippy 與測試; fmt、loom 模型、rustdoc, 以及模糊測試工作區的 fmt、clippy 與測試只在 Linux 上執行 | Linux 用映像檔, 其他平台用裸機 |
| `build-release` | `moon run build-release`, 上傳供下方的測試套件使用 | 裸機執行器, 讓執行檔連結執行器較舊的 glibc, 在兩種環境中都能執行 |
| `coverage` | `cargo llvm-cov`, 僅供參考 (`continue-on-error`, 無門檻) | 映像檔 |
| `extension` | `typecheck`、`check-ts`、`shared:test`、`extension:test`、`extension:build`, 然後對建置出的資訊清單執行 `check-extension-id` | 映像檔 |
| `contract` | `check-envelope`、`check-gen-isolation`、`check-refresh-lockfiles` | 映像檔 |
| `hygiene` | `moon run hygiene` | 映像檔 |
| `tooling` | `machete`, 使用 `Containerfile` 固定版本的 cargo-machete | 映像檔 |
| `web` | `web:build` | 映像檔 |
| `linux-install` | 先下載 `build-release` 的執行檔, 再執行 `scripts/linux-registration.ts`: 在隔離的 HOME 與 XDG 目錄下執行 `doctor --fix`、重新註冊、多瀏覽器、`uninstall` | 裸機執行器, 並帶有 cargo 與 moon 以建置情境驅動指令碼讀取的產生身分模組 |
| `protocol` | 對下載的執行檔執行 `e2e`、`adversarial` 與 `chaos` 測試套件 | 映像檔 |
| `interop` | 官方 MCP SDK 用戶端對下載的執行檔 | 映像檔 |
| `browser` | 可重用的 `browser.yml` (輸入 `chrome-version`), `nightly.yml` 也會呼叫它 | 裸機執行器, Chrome 來自 `setup-chrome` |
| `installers` | `installers.yml` 建置 .pkg、.deb 與 .msi, 並在各自的執行器上安裝 | 各平台的執行器 |
| `audits` | `audits.yml`: 對根工作區與模糊測試工作區執行 cargo deny | 裸機執行器 |

## 開發擴充功能

擴充功能建立在 WXT 之上, 由它產生資訊清單 (含固定的金鑰) 並打包 `src/apps/extension/src/entrypoints/` 下的進入點。

```sh
moon run setup              # once per checkout: the bun workspace, the Rust toolchain, the crates
moon run extension:dev      # WXT dev mode: rebuild on change
moon run extension:build    # production bundle
```

在 `chrome://extensions` (開發人員模式) 中把 `build/extension/chrome-mv3` 載入為未封裝的擴充功能。單元測試 (`moon run extension:test`) 以 Vitest 搭配 `fakeBrowser` 執行, 不需要真實瀏覽器。

## 測試

協定測試套件 (`tests/protocol/e2e.py`、`adversarial.py`、`chaos.py`) 以子程序驅動真實的發行執行檔, 走真正的線路協定, 不需要瀏覽器: `moon run test-e2e` (納入閘門)、`test-adversarial`、`test-chaos`。

`tests/browser/run_all.ts` 中列出的瀏覽器測試套件共用一個執行器, CI 的 `browser.yml`、容器與 `moon run test-browser` 都呼叫它。它先建置擴充功能, 執行那些測試套件, 然後檢查每個套件都留下了自己的 RAN 標記。下表最後一列單獨執行:

| 測試套件 | 證明什麼 |
|-------|----------------|
| `dom_test.ts` | 每個內容指令碼操作, 以建置出的內容指令碼 (`build/extension/chrome-mv3` 下的 content-scripts/content.js) 透過 CDP 注入無頭頁面 |
| `ext_test.ts` | 載入 `build/extension/chrome-mv3` 後 Service Worker 能啟動 (puppeteer-core); `BB_EXT_DIR` 可指向另一個未封裝的擴充功能 |
| `security_browser_test.ts` | 安全模型在瀏覽器端的那一半, 對同一個載入的擴充功能 |
| `webauthn_test.ts` | 主機驗證器所假設的 Chrome WebAuthn 用戶端事實, 以 CDP 虛擬驗證器代替 Touch ID |
| `cancel_test.ts` | 來自替身主機的 `cancel` 訊框會被消耗且永不回應; 不在 Windows 上執行 |
| `presence_exchange_test.ts` | 端對端的 WebAuthn 交換: 兩個隔離的 Chrome 對著真實的發行版主機。單獨執行 (`moon run test-presence-exchange`); `run_all.ts` 中的 `suitesFor` 說明了原因 |

```sh
bun tests/browser/run_all.ts                           # builds the extension, then the suites
CHROME_BIN=/path/to/isolated/chrome bun tests/browser/run_all.ts
```

沒有隔離的 `CHROME_BIN` 時執行器會略過; 讓略過或空洞的測試套件失敗的兩個 CI 開關, 只在 [`tests/README.md`](../../tests/README.md#-safety---never-point-browser-tests-at-your-daily-chrome) 的 Safety 一節陳述一次。`moon run test-integration` (`tests/browser/integration_e2e.ts`) 是選擇加入的端對端執行: 真實執行檔、隔離的 Chrome 與擴充功能一起上陣。

## 在容器中執行閘門與瀏覽器測試套件

容器就是隔離: 它帶有儲存庫固定版本的每個閘門工具以及發行版的 Chromium, 宿主機上的任何瀏覽器或程序都不在它的觸及範圍內。`Containerfile` 建置它; `compose.yaml` 執行它, 並停留在 `docker compose` 與 `podman compose` 都實作的 Compose Specification 子集內 (`moon run check-compose`, 納入閘門, 負責守住這一點)。

| 任務 | 在容器內執行 |
|------|---------------------------|
| `moon run ci-container` | `moon run ci` |
| `moon run test-browser-container` | `xvfb-run -a moon run test-browser`, 並設定 `BB_REQUIRE_BROWSER=1` 與 `BB_BROWSER_CANARY_DIR=/work/tmp/browser-canary`, 所以略過或空洞的測試套件會像在 CI 中一樣失敗, 且 RAN 標記在宿主機上仍可讀取 |
| `moon run shell-container` | 位於 `/work` 的互動式 `bash` |

Docker 是預設引擎; `CONTAINER_ENGINE=podman moon run ci-container` 可切換。第一次執行會建置映像檔 (需要幾分鐘, 只一次); 簽出目錄以 bind mount 掛載於 `/work`, 所以建置結果會像原生建置一樣落在宿主機上被 gitignore 的 build 目錄。

具名磁碟區讓 Linux 產物不進入宿主機的簽出目錄, 並讓重跑保持暖機; `docker compose down -v` (或 `podman compose down -v`) 會把它們全部刪除:

| 磁碟區 | 掛載點 | 內容 |
|--------|------------|-------|
| `cargo-registry` | `/home/ci/.cargo/registry` | 下載的 crate |
| `cargo-target` | `/work/target` | Linux 建置, 遮蔽宿主機的 target 目錄 |
| `bun-cache` | `/home/ci/.bun/install/cache` | 下載的套件 |
| `node-modules` | `/work/node_modules` | Linux 的安裝 (進入點執行 `bun install --frozen-lockfile`) |
| `moon-cache` | `/work/.moon/cache` | 容器執行的 moon 狀態 |

Podman rootless 會把宿主機使用者映射成容器的 root, 所以 `compose.podman.yaml` 加上 `userns_mode: keep-id:uid=1000,gid=1000`, 改把宿主機使用者映射到映像檔的使用者; `CONTAINER_ENGINE=podman` 時任務會傳入該檔案。手動執行 compose 需要任務所提供的同樣事實 (`scripts/compose-run.ts`), 包括映像檔唯一的建置引數:

```sh
env UID="$(id -u)" GID="$(id -g)" docker compose build --build-arg "PROTO_VERSION=$(bun scripts/pin.ts proto)" shell
env UID="$(id -u)" GID="$(id -g)" docker compose run --rm shell
# from a linked worktree, use the launcher instead: bun scripts/compose-run.ts shell
```

隔離防護的容器例外只在 [`tests/README.md`](../../tests/README.md#-safety---never-point-browser-tests-at-your-daily-chrome) 的 Safety 一節陳述一次。

## 模糊測試

`src/packages/core/fuzz/` 是獨立的 cargo 工作區 (cargo-fuzz + libFuzzer, nightly rust), 有十一個目標。凡存在正確性性質之處, 目標就斷言該性質, 而不只是檢查 panic。根工作區的 clippy 與 rustfmt 閘門也涵蓋這個工作區, 使用根 lint 表的一份副本, 其例外由該工作區的 `Cargo.toml` 說明。

| 目標 | 模糊測試對象 | 無 panic 之外的預言機 |
|---------|----------------|------------------------|
| `nm_frame`、`mcp_jsonrpc`、`handshake`、`attach` | 線路訊框解碼器 | decode -> encode -> decode 為恆等 |
| `bridge_envelope` | 內部橋接信封讀取器, 以原始值及兩種具型別訊框的形式 | 無 (拒絕或解碼, 三次) |
| `handshake_verify` | MAC 驗證器與伺服器接受路徑 | 正確計算的 MAC 能通過驗證 |
| `enclave_challenge` | 主機金鑰挑戰訊息建構器 | 只接受文件化的欄位矩陣, 且被接受的訊息能拆回其各個欄位 |
| `classify_frame` | 控制訊框路由器 | 訊框的 `type` 正是它被讀取為的標籤 |
| `registration_manifest` | 我方/外來資訊清單與擴充功能指標的判定 | 凡無法證明是我方的都是 `Foreign` |
| `policy_doc` | 策略儲存的解析介面 | serde 往返, 比較格 (lattice) 劃分每一對 |
| `webauthn_authdata` | WebAuthn authenticatorData 版面配置解析器, 並把同樣的位元組餵給證明物件與斷言驗證器 | 從已證明資料解析出的憑證金鑰, 經其儲存拼寫往返後不變 |

`handshake_verify` 透過記憶體內 I/O 驅動完整的伺服器交握。伺服器每次交握都綁定新的 nonce, 所以靜態的模糊回應在那裡只會走到失敗即關閉的拒絕路徑; 接受路徑由同一目標的 MAC 預言機加上 `handshake.rs` 中的 socketpair 單元測試涵蓋。

位元組輸入目標的本體位於 crate 的函式庫 (`fuzz/src/targets.rs`); 每個 `fuzz_targets/<name>.rs` 執行檔以 `fuzz_target!` 包裝其中一個, 而函式庫的測試在 stable rust 上以同樣的本體在行程內跑過每個產生的種子。

語意目標透過核心 crate 的 `fuzzing` 功能觸及私有函式: 預設關閉, 只由模糊測試工作區啟用, 內容僅是沒有執行階段行為的重新匯出。`--all-features` 確實會編譯它; 隔離的論據是沒有任何出貨的執行檔啟用該功能, 且 fuzz crate 位於獨立的工作區, 所以功能統一 (feature unification) 無法把它拉進真正的建置。

三個生命週期各異的目錄, 加上失敗報告:

- `fuzz/seeds/<target>/`: 被 gitignore, 由 `moon run fuzz-seeds` (`fuzz/src/seeds/`) 在每次模糊測試之前從正式型別產生。crate 的測試把每個種子釘在其標籤上, 所以種子不會偏離產生它的型別。
- 正常路徑種子走真正的編碼器: NDJSON 與原生訊息寫入器、記錄信封的 `encode`、工具目錄自身的引數 schema。
- 對抗性種子是正常路徑種子的一步變異 (未知欄位、邊界加一、高於階梯的版本、重複的鍵、截斷的 base64), 並標上必須拒絕它的讀取器。
- 結構化目標 (`handshake_verify`、`enclave_challenge`) 接受 `Arbitrary` 衍生的輸入, 其編碼在不同 `arbitrary` 版本間不穩定, 所以沒有種子; 它們的回歸改用單元測試。
- `fuzz/corpus/<target>/`: 被 gitignore, 由模糊測試器產生。夜間 CI 透過 `actions/cache` 還原並儲存它, 所以探索會跨次累積, 而不是每晚從零開始。
- `fuzz/dictionaries/`: 交給 libFuzzer 的 token 字典。`json_protocol.dict` (JSON 種子的每個鍵與字串值) 與種子一同產生並被 gitignore。
- `fuzz/failures/<target>/`: 被 gitignore, 每次 `fuzz-smoke.ts` 執行都會清空重寫。每個當掉的目標一個目錄, 內含 `report.md` (重播命令、種子、小型輸入的 base64 內嵌、釘住的指示) 以及當機輸入的副本, 遵循 fleet 的失敗報告契約 (fleet 儲存庫的 docs/fuzzer.md)。夜間工作用來提交 issue 的 action 會取用這些。

在本機執行:

```sh
moon run fuzz-seeds        # regenerate fuzz/seeds/ and the JSON dictionary (fuzz-smoke runs this first)
moon run fuzz-smoke        # bun scripts/fuzz-smoke.ts: every target, bounded run
moon run test-fuzz         # every generated seed through its target in-process (in the ci gate)
moon run check-fuzz-smoke  # unit tests for the driver itself (in the ci gate)
```

冒煙測試需要 nightly 工具鏈加上 `cargo install cargo-fuzz`, 缺少任一者時會印出訊息並略過。夜間工作傳入 `--require-toolchain`, 把這個略過變成失敗: 略過的一晚不能被讀成綠燈而自動關閉追蹤 issue。

- 目標來自 `cargo +nightly fuzz list`, 所以清單不會偏離 `fuzz/Cargo.toml`。
- 工具鏈就緒時, 沒有產生種子或字典的簽出目錄會被拒絕, 並提示要執行的任務 (`moon run fuzz-seeds`), 所以在全新複製的儲存庫上直接執行 `bun scripts/fuzz-smoke.ts` 會以 1 結束, 而不是在沒有語料庫的情況下進行模糊測試。
- 當掉的目標不會中止整輪: 指令碼寫下該目標的失敗報告, 繼續下一個, 並在最後有任何失敗時以 1 結束。
- `--seed=N` 固定 libFuzzer 的 PRNG, 以盡力做到確定性的重跑; 當機輸入檔仍是真正的重現器, 因為持久化的語料庫每晚不同。
- 本機每個目標 30 秒。夜間執行給每個目標 120 秒並傳入 `--cmin`, 在儲存快取之前最小化每個通過目標的語料庫 (cmin 限制每個快照的大小; GitHub 的 LRU 快取淘汰限制快照的數量)。
- 要對單一目標進行真正的戰役, 在 `src/packages/core` 執行 `cargo +nightly fuzz run <target>` 即可無限制地跑。

夜間工作位於 `.github/workflows/nightly-fuzz.yml`, 是 fleet 的 fuzzer 模組範本在本儲存庫的實例。瀏覽器與變異測試留在 `nightly.yml`, 它以自己的 `nightly-failure` 標籤走同樣的生命週期, 但沒有失敗產物, 所以它的 issue 指向執行日誌。

- 紅燈之夜: 把 `fuzz/artifacts/` 與 `fuzz/failures/` 上傳為 `fuzz-failures-<attempt>` 產物, 依報告建立或更新 `fuzz-nightly` 追蹤 issue, 並對它派發 auto-assign。
- 綠燈之夜: 關閉開啟中的 issue。
- `workflow_dispatch` 接受 `seed` 與 `iterations`, 所以任何一晚的設定都能隨需重跑。

當機被提報時:

1. 用 issue 中的命令重播它 (下載產物, 或解碼內嵌的 base64)。
2. 修正錯誤。
3. 把該輸入釘成產生器中帶標籤的種子 (`fuzz/src/seeds/`: 產生它的變異, 以及必須拒絕它的讀取器), 或對兩個結構化目標而言釘成單元測試, 並與修正一同提交。釘住這一步, 才讓下一個綠燈之夜的自動關閉成為證據而非運氣。

刻意不做模糊測試的部分及原因:

- `allowlist.rs`、`trust.rs`、`ipc/lockfile.rs`: 純粹以 `serde_json::from_slice` 解析進衍生了 `deny_unknown_fields` 的結構。對它們做模糊測試只是在測 serde_json, 不是我們的程式碼; 負向單元測試已釘住失敗即關閉的行為。
- `enclave/pubkey.rs`: `EnclavePublicKey::from_x963` 只是長度檢查加前導位元組檢查, 不是點驗證。太過瑣碎, 不值得一個目標。
- 中介語意: 由 loom 模型檢查與 `tests/protocol/adversarial.py` 負責, 它們演練的是交錯執行與敵意對端, 而非位元組解析。
- 在場簽章: 是 Security.framework 呼叫, 不是位元組解析器。
- TypeScript 側 (產生的 Zod schema 與手寫的信封不對稱層): 這是範圍上的決定, 不是宣稱該程式碼經過多人審閱。

策略: 凡在 Rust 核心的信任邊界新增或修改自訂解析器或語意驗證器的 PR, 必須新增或擴充模糊測試目標, 或把排除項連同理由加進上方清單。確切規則及其範圍界定見 [SECURITY.md](../../.github/SECURITY.md#security-relevant-changes-review-bar)。

供應鏈範圍: 模糊測試工作區只在夜間 CI 執行, 永不連結進出貨的執行檔, 其第三方直接相依套件僅限 `libfuzzer-sys`、`arbitrary` 與 `serde_json` (加上受測的 crate `chromium-bridge-core` 本身); `derive_arbitrary` 經由 `arbitrary` 的 derive 功能間接引入。新的模糊測試相依套件仍要通過 audits 工作流程中對 `fuzz/Cargo.toml` 的 `cargo deny` 檢查, 以及一般的 PR 審查。

## 日誌

兩種執行檔模式都把日誌寫到 **stderr** (stdout 承載線路協定)。以 `BB_LOG` 設定層級:

```sh
BB_LOG=debug chromium-bridge          # verbose
BB_LOG=error chromium-bridge          # quiet
# default is info
```

## 發行

發行由 release-please 從綠燈的 `main` 切出; 管線 (草稿發行、打包矩陣、證明、發布) 見 [docs/release.md](./release.md)。發行 PR 是唯一的版本提升: `release-please-config.json` 中的 extra-files 改寫下方每一份副本, 而 `moon run check-version` 會在任一副本或設定不一致時讓 CI 失敗, 發行 PR 本身也不例外。

| 版本副本 | 誰讀取它 |
|---|---|
| `Cargo.toml` `[workspace.package] version` | 各 crate、打包工作的標籤檢查 |
| `src/apps/extension/package.json` `version` | WXT 建置的資訊清單 (`scripts/lib.ts` 中的 `versionedJsonFiles`) |
