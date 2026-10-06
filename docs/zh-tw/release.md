# 發行: release-please 管線

> 合併發行 PR 會建立一個草稿發行, 並在同一次 CI 執行中建置預先建置的產物、安裝程式、總和檢查碼、建置來源證明 (provenance attestation) 與 SBOM 並附加到草稿上, 然後發布它, 並在 Homebrew tap 開啟版本升級的 pull request。哪個版本號因哪種變更而變動, 見下方的[版本](#版本); 磁碟上的註冊路徑見 [architecture.md 第 4.3 節](./architecture.md#43-磁碟上的產物); 這些工作背後的工具鏈見 [development.md](./development.md)。

## 觸發: 合併發行 PR

發行由 **release-please** 驅動。`main` 上的 Conventional Commits 會累積到一個滾動的發行 PR (`chore(main): release X.Y.Z`); 合併它就會建立發行。GitHub 發行一旦發布就不可變 (標籤與資產都凍結), 所以每次發行都經過同樣的三個步驟, 一律草稿優先, 全部在同一次 CI 執行中完成:

1. release-please 以**草稿**建立發行, 其標籤已強制建立在合併的 SHA 上 (`release-please-config.json` 中的 `draft` + `force-tag-creation`)。發行內文是 release-please 的變更日誌條目; 不會加入 GitHub 自動產生的說明。
2. 下方的打包工作 - 也就是本儲存庫自有的 `.github/workflows/update-release.yml` 掛勾中的工作 - 會修改草稿: 它們從標籤建置, 並用 `gh release upload` 附加資產。掛勾中的 `mark-prerelease` 工作會在發行仍是草稿時, 把帶有後綴的標籤標記為預先發行。
3. 艦隊 (fleet) 的 `publish-release` 階段等待每個掛勾工作完成, 為草稿上的每個資產產生建置來源證明並彙整成單一的 `attestation.json` 資產, 然後把草稿轉為正式發布。發布在結構上永遠是最後一步: 掛勾無法重新排序或跳過它。

如果管線在草稿存在之後中斷, 重新執行無法重新建立它 (release-please 會看到已強制建立的標籤); 請重新執行失敗的工作, 或用 `gh release upload <tag> <assets> --clobber` 與 `gh release edit <tag> --draft=false` 手動完成 (手動發布的發行不帶 `attestation.json`)。

這套機制是受管理的 `.github/workflows/ci.yml`, 位於 all-green 閘門的下游, 所以發行只可能從綠燈的 `main` 建立, 而打包工作也在同一次 CI 執行中進行。它的工作依序為:

- **`release`** 呼叫艦隊的 `fleet-release.yml`: release-please 建立草稿。
- **`update-release`** 呼叫本儲存庫的掛勾, 僅在 release-please 回報 `release_created` 時執行。
- **`publish-release`** 呼叫艦隊的 `fleet-release-publish.yml`: 先證明, 再發布。
- **`site`** 在發布之後、同一次執行中部署網站。
- **`update-release-pr`** 在 release-please 建立或更新發行 PR 時, 呼叫儲存庫自有的 `update-release-pr.yml` 掛勾。

`update-release.yml` 內最後一個工作 `release-ready` 會在任一打包工作未成功時失敗: 被跳過或取消的工作會阻擋發布, 而 `continue-on-error` 的工作 (SBOM、Homebrew) 在那裡視為成功。受管理的發布階段只看得到掛勾的彙總結果, 所以正是這個工作防止意外的跳過流入發布。

當版本升級改變了鎖定檔時, 發行 PR 會多帶一個 release-please 自身之外的提交: `update-release-pr` 掛勾會為升級後的版本重新鎖定 `Cargo.lock`、`src/packages/core/fuzz/Cargo.lock` 與 `bun.lock`, 並把該提交推送到 PR 分支, 因為 release-please 只升級資訊清單, 而每個 `--locked` 步驟都拒絕落後的鎖定檔。

受管理的工作流程只以 `github.token` 執行; 不涉及任何儲存庫機密。它的限制:

- **PR 的 CI 執行不會自行啟動。** release-please 用該權杖建立發行 PR, 掛勾的推送也用它, 所以要關閉再重新開啟 PR (或向它推送) 才能執行它的檢查。
- **建立發行可能因工作流程檔案的變更而失敗**, 當這類變更在發行 PR 合併與建立發行的工作之間落到 `main` 上時, 因為 `github.token` 無法在工作流程檔案與 `main` 不同的提交上建立 ref。下一次合併到 `main` 會再次執行 release-please 並建立發行, 或者手動建立發行。

每個打包工作的第一步是**版本一致性檢查**: 去掉標籤開頭的 `v` 以及任何 `-dev`/`-rc` 預先發行後綴後, 其核心版本必須等於 `Cargo.toml` 中的 `version`, 否則執行立即失敗。Cargo 是唯一的版本來源。帶後綴的標籤 (例如 `v0.1.0-rc.1`) 會被標記為預先發行。

## 建置矩陣與預先建置的壓縮檔

update-release.yml 在一個矩陣上建置 `binaries` 工作 (目前是 `macos-14/arm64`、`ubuntu-22.04/x64` 與 `windows-2022/x64`; Intel macOS 被**刻意省略**, 因為託管執行器稀缺, 而 Linux 使用較舊的 glibc 基準以擴大相容性)。對每個目標:

1. `bun scripts/build-repro.ts` 產生可重現的發行執行檔。
2. `bun install --frozen-lockfile && bun run --cwd src/apps/extension build` 產生擴充功能套件。
3. 所有內容打包成 `chromium-bridge-<tag>-<platform>-<arch>.tar.gz` (Windows 上為 `.zip`), 內含執行檔、`extension/dist`、`RELEASE.txt`、`LICENSE.md` 與 `README.md`。
4. 同一個執行檔被包裝成該平台的安裝程式 (見下一節)。
5. 產生壓縮檔的 `.sha256`、壓縮檔內執行檔的另一個 `.binary.sha256`, 以及安裝程式的 `.sha256`, 並以一份建置來源證明涵蓋這三個檔案; 它的 Sigstore bundle 成為 `chromium-bridge-<tag>-<platform>-<arch>.attestation.jsonl` 資產。獨立的擴充功能 zip 與 SBOM 也以同樣方式附帶 `<asset>.attestation.jsonl` bundle; `--bundle` 驗證方式記載於 [SECURITY.md](../../.github/SECURITY.md#release-artifact-integrity)。
6. `gh release upload` 把資產附加到草稿發行; 艦隊的 `publish-release` 階段隨後為草稿上的每個資產產生證明, 彙整成發行層級的 `attestation.json`, 並在所有掛勾工作完成後發布。

因此使用者**不需要 Rust/bun 工具鏈**即可安裝: 註冊就是執行檔自己的 `chromium-bridge doctor --fix`, 見 [quickstart.md](./quickstart.md)。第三方 Actions 在本儲存庫的工作流程與艦隊的發行分支 (leg) 中都固定到提交 SHA; 平台自己的 actions 與可重用工作流程則取 `@stable`, 這是一個指向平台綠燈 `main` 提交的移動標籤 (信任模型見 repo-platform 的 [build-provenance.md](https://github.com/Vivswan/repo-platform/blob/main/docs/platform/build-provenance.md))。

## 安裝程式: .pkg、.deb 與 .msi

每個分支把它的執行檔原封不動地包裝成該平台的安裝程式。安裝後步驟就是執行檔自己的 `doctor --fix`, 絕不是第二套實作; 它寫入的內容見 [cli.md](./cli.md#doctor---fix--uninstall-原生訊息註冊)。

| 分支 | 資產 | 安裝到 | 安裝後步驟 |
| --- | --- | --- | --- |
| macos-arm64 | `chromium-bridge-<tag>-macos-arm64.pkg` | `/usr/local/bin/chromium-bridge` | 以主控台登入的使用者身分 (`/dev/console` 的擁有者) 執行 `doctor --fix`, 在 Installer.app 與 `sudo installer` 下皆然; 無人登入時失敗 |
| linux-x64 | `chromium-bridge-<tag>-linux-x64.deb` | `/usr/bin/chromium-bridge` | 以 root 身分執行 `doctor --fix --system`: 每個帳戶的瀏覽器都會讀取的機器層級註冊, 以廠商套件的安裝目錄偵測; 還沒有瀏覽器時印出提示, 安裝照樣成功; `dpkg -r` 會先執行 `uninstall --system` |
| windows-x64 | `chromium-bridge-<tag>-windows-x64.msi` | `%LOCALAPPDATA%\Programs\chromium-bridge\` (每位使用者各自安裝, 不需提升權限, 位於使用者的 PATH 上) | 以安裝的使用者身分執行 `doctor --fix`; 首次安裝失敗時以 `uninstall` 回復其註冊, 升級失敗時還原先前的設定; 解除安裝時執行 `chromium-bridge uninstall` |

- **.deb 做機器層級的註冊**, 因為 Debian 維護者指令碼以 root 執行且沒有使用者情境, 不得寫入家目錄; 執行檔在 root 下拒絕每使用者範圍 ([cli.md](./cli.md#doctor---fix--uninstall-原生訊息註冊))。
- **沒有偵測到任何瀏覽器會使 .pkg 與 .msi 安裝失敗**, 安裝程式日誌中會有 `doctor --fix` 給出的原因。請先安裝一個 Chromium 瀏覽器, 或改用壓縮檔。
- **這種情況下 .deb 照樣安裝** (`doctor --fix` 結束碼 3, 沒有可註冊的東西), 因為失敗的維護者指令碼會讓 dpkg 停在半設定狀態, 比 .pkg 的拒絕更糟; 因其他原因失敗的註冊仍會讓安裝失敗。
- **來源:** `packaging/pkg/scripts/postinstall`、`packaging/deb/{postinst,prerm}`、`packaging/msi/chromium-bridge.wxs`, 以及 `src/apps/host/Cargo.toml` 中的 `[package.metadata.deb]` 表。`scripts/release-package.ts installer` 執行 pkgbuild、cargo-deb (`--no-build --no-strip`, 所以 .deb 攜帶的是經過證明的位元組) 以及 WiX 3 的 candle 與 light。
- **每個 pull request 上的證明:** `.github/workflows/installers.yml` 由 `checks.yml` 在 all-green 閘門內呼叫, 從分支建置全部三種安裝程式, 並透過 `scripts/installer-smoke.ts` 在各自的執行器上安裝。Windows 分支是 HKCU 註冊真正執行的地方, 也是迄今唯一執行過的地方。

**目前未簽章。** Gatekeeper 會要求使用者右鍵點選並開啟 .pkg, SmartScreen 則會對 .msi 發出警告。簽章只需切換兩個儲存庫機密以及使用它們的步驟, 而這些目前都還不存在:

| 平台 | 要新增的機密 | 要在該分支新增的步驟 |
| --- | --- | --- |
| macOS | 一張 Developer ID Installer 憑證 (`.p12` 及其密碼) 與一把 App Store Connect API 金鑰 | 對 .pkg 執行 `productsign`, 然後 `xcrun notarytool submit --wait` 與 `xcrun stapler staple` |
| Windows | 一張 Authenticode 憑證 | 在 candle 之前對執行檔、在 light 之後對 .msi 執行 `signtool sign /fd SHA256 /tr <timestamp url>` |

## Homebrew tap

`homebrew` 工作從兩個 `.tar.gz.sha256` 資產產生 `Formula/chromium-bridge.rb` (`scripts/release-package.ts brew-formula`), 並以 `REPO_PLATFORM_TOKEN` 在 `Vivswan/homebrew-tap` 上開啟 pull request。

- **tap 儲存庫由擁有者建立, pull request 也由他們合併。** 在它存在之前這個工作會失敗, 而 `continue-on-error` 讓它不會阻擋發行, 與 SBOM 相同; 在合併之前, tap 提供的是前一版 formula。
- **tap 只接收正式發行。** Homebrew 把 `1.2.3-dev` 排在 `1.2.3` 之上, 所以預先發行標籤不會產生 formula, 也不會開啟 pull request。
- **formula 的 `post_install` 就是 `doctor --fix`。** 那裡失敗時安裝仍保留, 並附帶 brew 的警告; `brew postinstall chromium-bridge` 可重試。

## SBOM: 附加到草稿的 CycloneDX

update-release.yml 中的 `sbom` 工作與打包工作並行執行 (它以前是一個獨立的 `release: published` 工作流程, 但已發布的發行不可變, 所以 SBOM 必須落在草稿上):

- 它使用 `anchore/sbom-action` 從**已提交的鎖定檔** (`Cargo.lock` + `bun.lock`) 產生 CycloneDX JSON (`chromium-bridge.cdx.json`), 掃描的是宣告的相依套件而非已安裝的目錄樹 (全新的簽出沒有 `node_modules`/`target`)。
- 它為 SBOM 產生建置來源證明 (與執行檔相同的 `actions/attest-build-provenance` 步驟), 所以 `gh attestation verify chromium-bridge.cdx.json --repo <repo>` 可對下載的資產運作。
- 它把 SBOM 及其 `.attestation.jsonl` bundle 附加到該標籤的草稿發行。

SBOM 工具失敗仍然**永遠不會阻擋**執行檔的發行: 這個工作是 `continue-on-error`, 所以艦隊的發布階段 (它等待每個掛勾工作) 仍會執行。發行會在沒有 SBOM 的情況下出去, 而執行上的失敗註解會標示出來。

- **證明服務中斷同樣會讓 SBOM 資產缺席。** 證明步驟在上傳之前執行, 因為沒有人能驗證的資產不得出貨。
- **對該標籤而言這個損失是永久的。** 已發布的發行不可變, 所以 SBOM 之後無法再附加。下一次發行會再度帶上。

## 版本

有三個數字都叫「版本」; 每個都有單一來源與單一含義。

| 版本 | 值 | 單一來源 | 變更的含義 |
|------|------|------|----------|
| MCP JSON-RPC 版本 | 日期字串 `2026-07-28` | [`src/packages/core/src/protocol.rs`](../../src/packages/core/src/protocol.rs) 中的 `MCP_PROTOCOL_VERSION` | MCP 用戶端與 MCP 伺服器之間的外部協定; 無狀態, 逐請求把關, 並暫時支援停留在前一修訂版的舊時代用戶端程式 (harness) |
| 內部橋接協定版本 | 單調遞增整數 (目前為 `1`) | [`src/packages/core/src/protocol.rs`](../../src/packages/core/src/protocol.rs) 中的 `BRIDGE_PROTOCOL_VERSION` | MCP 伺服器、原生訊息主機與擴充功能之間的線路契約 |
| 擴充功能/執行檔發行版本 | SemVer (例如 `0.1.0`) | `Cargo.toml` | 發行產物的版本, 依下方 SemVer 規則變動 |

內部橋接協定版本只在橋接線路契約 (`BridgeReq`/`BridgeResp` 的形狀、驗證交握、op 與能力語意) 發生不相容變更時才變動。新的選用欄位、新工具、新能力與附加式的主機處理控制訊框不會提升它; 依 SemVer 它們落在發行版本的次版本號。兩側版本不一致時的行為見[疑難排解頁面](./troubleshooting.md#擴充功能與主機版本不一致)。

有一次平台層面的破壞性變更在沒有提升版本號的情況下落地: 移除 `requireEnrollment` 退出選項, 這使得沒有 Secure Enclave 的 Mac 無法登記。線路契約沒有變動, 所以號碼也沒有。

## SemVer 規則

相容性紀律在 1.0 之前同樣適用; `0.x` 不被視為可以隨意破壞相容性的許可:

- **修補版本 (Patch)**: 錯誤修正、內部重構、日誌改進; 不改變工具參數或安全語意。
- **次版本 (Minor)**: 新工具、新選用欄位、新能力、新設定; 向後相容。
- **主版本 (Major)**: 移除/重新命名工具、改變欄位含義、改變預設權限、放寬安全邊界, 或不相容的 Bridge 協定或擴充功能版本 (對應內部橋接協定版本的提升, 見[版本](#版本))。

## 尚未就緒 (如實說明)

- macOS **發行閘門中的真實整合測試**: 它們需要真實的瀏覽器, 目前還不是發行閘門的一部分。
- 指引中提到的 **Web Store 上架**: 其狀態以 [quickstart.md](./quickstart.md#cli-macoslinuxwindows) 第 4 步為準。

## 發布到 Chrome 線上應用程式商店

尚未完成, 也尚未決定。發布會移除最大的採用障礙 (載入未封裝的擴充功能), 但它涉及散布與安全邊界, 所以依 [GOVERNANCE](../../GOVERNANCE.md) 這是 RFC 層級的決定: 先開 issue, 絕不走快速 PR。做這個決定需要的事實:

- **固定 ID 的陷阱。** 每次安裝都依賴一個固定的擴充功能 ID `mkjjlmjbcljpcfkfadfmhblmmddkdihf`, 它衍生自 [`src/packages/core/src/identity.rs`](../../src/packages/core/src/identity.rs) 中固定的資訊清單金鑰, 並由註冊引擎寫入主機資訊清單的 `allowed_origins`。商店在首次上傳時指派自己的 ID 並忽略資訊清單的 `key`, 所以商店版本無法連線到只信任固定 ID 的主機。
- **要規劃的緩解措施。** 同時信任兩個 ID: 商店的給商店使用者, 固定的給未封裝載入。`PINNED_EXTENSION_ID` 是單數, 註冊引擎也只從它寫入一個 `allowed_origins` 條目, 所以要先讓身分契約與 Registrar 以複數 ID 建模, 再由 `moon run gen` 把結果帶到每個產生的副本。把商店的公鑰回填到資訊清單的 `key` 是可選的, 且會改變今天的固定 ID。
- **它解決什麼, 不解決什麼。** 不再需要開發人員模式與「載入未封裝項目」; 一鍵安裝, 在 Chrome 重新啟動後仍然存在, 也適合受管理的 Chrome。主機安裝仍然保留: 商店只散布擴充功能, `chromium-bridge doctor --fix` 仍是原生訊息主機的註冊方式。
- **先決條件。** 一個開發人員帳戶 (一次性費用, 由擁有者註冊)、一個隱私權政策 URL ([隱私權政策](./privacy-policy.md)即符合), 以及上架素材: 一到五張螢幕截圖 (1280x800 或 640x400)、由 `moon run gen-icons` 從 `assets/icon/` 中的 SVG 來源渲染到擴充功能公開圖示資料夾的 128px `icon128.png`、簡短與詳細描述、一個類別, 以及支援與首頁 URL。
- **打包。** 發行管線已經產出 `chromium-bridge-extension-<tag>.zip`; 確認它就是可上傳的套件。`scripts/check-version.ts` 已經強制資訊清單版本等於 Cargo 的版本。決定 `key` 欄位是保留 (一致的未封裝 ID) 還是交給商店。
- **提交。** 上傳, 填寫資料使用揭露與隱私權政策, 然後送審。審查需時數天到數週, 之後的每次更新也都要經過審查。
- **發布之後。** 透過 `identity.rs` 把商店 ID 接入 `allowed_origins`; 把 README 的「載入擴充功能」改為「從 Chrome 線上應用程式商店加入」, 並以未封裝載入作為開發人員路徑; 更新文件; 在落地的 PR 中記錄這個決定, 因為依 GOVERNANCE 散布變更屬於主要變更; 可選擇在 CI 中自動化上傳。

審查會聚焦在四點, 每一點都需要書面理由:

| 審查重點 | 誠實的回答 |
| --- | --- |
| `page_eval` 執行任意 JS (被拒絕風險最高) | 這是一個開發人員工具, 每次呼叫都在擴充功能擁有的視窗中確認; 考慮讓商店版本預設停用這個工具 |
| `page_snapshot_precise` 使用的 `chrome.debugger` | 一項需要單獨說明的敏感權限 |
| 廣泛的主機權限與選用權限加上 Native Messaging | 橋接僅限 localhost 並以每次執行的機密保護, 網站逐一授權; 連結[安全頁面](./security.md) |
| 「是否使用遠端程式碼」 | `page_eval` 執行使用者提供的 JS, 絕非遠端擷取的程式碼; 表單措辭要精確 |
