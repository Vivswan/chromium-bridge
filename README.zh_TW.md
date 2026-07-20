# chromium-bridge

> 本文是英文 [README](./README.md) 的繁體中文翻譯。以英文版為準;
> 简体中文版見 [README.zh_CN.md](./README.zh_CN.md)。

讓任何 MCP 用戶端 (Claude Code、Claude Desktop、Codex, 或任何支援
Model Context Protocol 的程式) 驅動你真實的 Chromium 瀏覽器: 你的分頁、
你已登入的工作階段、你的 Cookie, 透過一個瀏覽器擴充功能加一個原生訊息主機
(native messaging host) 實現。不需要第二個瀏覽器, 不需要 CDP 偵錯連接埠,
不需要 `--remote-debugging` 參數。

因為它操作的是你已經登入的瀏覽器, 代理 (agent) 能做到全新無頭瀏覽器做不到
的事: 讀取需要登入才能看的頁面、在你已登入的應用裡點擊操作、取出前端框架
存在 `localStorage` 裡的權杖。這份能力同時也是風險所在。安裝前請先閱讀下面
的安全部分。

## 安全第一

chromium-bridge 驅動的是一個真實的、已通過身分驗證的瀏覽器。它能讀取頁面
內容、Cookie (包括 `httpOnly`) 和 Web 儲存, 並能在你的頁面裡執行
JavaScript。相應的防護措施:

- **逐網站核准。** 新的來源 (origin) 會觸發確認提示; 未經你核准的網站上什
  麼都不會執行。
- **高風險操作需確認。** 提交點擊、按鍵、關閉分頁、檔案上傳, 以及每一次
  `page_eval`, 都要在一個頁面無法看見、無法點擊的擴充功能自有視窗中確認。
  在已完成 Touch ID 註冊的 Mac 上, `page_eval` 和 `page_upload` 的核准是一
  次 Secure Enclave 的 Touch ID 觸按, 任何頁面或程式都無法偽造
  ([ADR-0031](./docs/adr/0031-touch-id-confirmations-and-presence-grants.md))。
- **憑證唯讀。** Cookie 和儲存只能讀取 (且始終遮罩: JWT、長十六進位字串、
  長數字串), 永遠不能寫入。設計上不存在 `cookie_set` 或 `storage_set`。
- **經過驗證與證明的橋接。** 在 macOS 和 Linux 上, 主機行程之間的橋接是一
  個私有的 Unix 網域通訊端 (沒有監聽連接埠)。每個連線都必須通過核心對端
  UID 檢查、核心認證的可執行檔身分, 以及基於每次執行隨機金鑰的 HMAC 質詢。
  MCP 用戶端本身要對照一份以認證程式碼身分為鍵的受信用戶端允許清單獲得准
  入, 任何一方都可以隨時撤銷信任
  ([ADR-0024](./docs/adr/0024-multi-client-attested-pairing-and-broker.md)、
  [ADR-0025](./docs/adr/0025-any-side-revocation-epoch.md))。
- **全域緊急停止開關。** 在 CLI、擴充功能或桌面應用程式中的一個動作即可停
  止一切, 直到你以在場證明 (proof of presence) 明確解除
  ([ADR-0030](./docs/adr/0030-global-kill-switch-and-audit.md))。每一個安全
  決策都會寫入磁碟上的稽核日誌。

平台差異, 如實說明: 強橋接保證 (無連接埠通訊端、對端 UID 檢查、身分證明)
僅存在於 macOS 和 Linux。在 Windows 上, 橋接是一個僅由 HMAC 金鑰把守的回送
TCP 通訊端, 伺服器啟動時會對此發出警告。Windows 支援是盡力而為。詳見
[SECURITY.md](./SECURITY.md#platform-support)。

完整細節: [SECURITY.md](./SECURITY.md)、
[威脅模型](./docs/security/threat-model.md)、
[信任邊界](./docs/security/trust-boundaries.md)、
[逐工具風險矩陣](./docs/security/tool-risk-matrix.md)。

## 使用桌面應用程式快速上手 (macOS)

Chromium Bridge 桌面應用程式是首選安裝路徑。它內建已簽署的主機二進位檔和
擴充功能; 這條路徑裡唯一的指令, 是把伺服器註冊給 MCP 用戶端的那一條。

> 應用程式安裝包尚未發布 (目前發布版只含 CLI 壓縮檔)。在此之前, 請在原始
> 碼檢出中用 `moon run run-app` 建置並啟動應用程式, 或使用下面的 CLI 路徑。

1. **安裝應用程式。** 取得 `Chromium Bridge.app` (見上面的說明) 並開啟。首
   次啟動時它會向偵測到的每一個 Chromium 系瀏覽器 (Chrome、Brave、Edge
   等) 註冊原生訊息主機, 並展示它寫入了什麼。
2. **載入擴充功能。** 在應用程式的 Setup 頁點擊「Reveal folder」開啟內建擴
   充功能目錄, 然後在瀏覽器中開啟 `chrome://extensions`, 啟用開發人員模式,
   點擊「載入未封裝項目」, 選擇該目錄。重新啟動瀏覽器使註冊生效。
3. **用 Touch ID 配對。** 在應用程式的 Pairing 頁點擊 Pair (會彈出
   Touch ID), 然後在擴充功能的選項頁核對並核准金鑰指紋。macOS 上擴充功能
   預設要求完成此註冊, 在指紋相符之前拒絕執行任何操作
   ([ADR-0021](./docs/adr/0021-enrollment-ceremony.md))。
4. **接上你的 MCP 用戶端。** 在 Setup 頁點擊 Install, 將 `chromium-bridge`
   指令安裝到 `~/.local/bin`, 然後在用戶端裡註冊它。以 Claude Code 為例:

   ```sh
   claude mcp add chromium-bridge -- "$HOME/.local/bin/chromium-bridge"
   ```

   其他用戶端以同一個二進位檔作為 `mcpServers` 條目; 見英文 README 的
   [Connect your MCP client](./README.md#connect-your-mcp-client)。

讓用戶端「列出我的瀏覽器分頁」試試。第一次操作新網站時, 點擊 Chromium
Bridge 工具列圖示並核准該網站。

裝好之後應用程式仍然有用: 它是配對、受信用戶端、緊急停止開關和稽核日誌的
控制面板, 危險操作在已註冊的 Mac 上由 Touch ID 把守。見
[docs/desktop-app.md](./docs/desktop-app.md)。

## 使用 CLI 快速上手 (macOS、Linux、Windows)

CLI 與桌面應用程式地位對等: 應用程式能做的它都能做, 只依賴二進位檔本身。
在 Linux、Windows、無介面機器和 CI 上它是自然選擇。

1. 從[最新發布版](https://github.com/Vivswan/chromium-bridge/releases/latest)
   下載對應平台的壓縮檔並解壓。建議先驗證; macOS/Linux 範例如下 (Windows
   壓縮檔是 `.zip`, 請用你自己的 sha256 工具核對; 詳見
   [SECURITY.md](./SECURITY.md#release-artifact-integrity)):

   ```sh
   shasum -a 256 -c chromium-bridge-<tag>-<platform>-<arch>.tar.gz.sha256
   gh attestation verify chromium-bridge-<tag>-<platform>-<arch>.tar.gz --repo Vivswan/chromium-bridge
   ```

2. 把解壓出的二進位檔註冊給你的瀏覽器。註冊是冪等的, 同一條指令既是全新安
   裝, 也是修復, 也是移動二進位檔後的重新註冊:

   ```sh
   ./chromium-bridge doctor --fix          # 每一個偵測到的瀏覽器
   ./chromium-bridge doctor --fix --browser chrome,brave
   ```

   把二進位檔放在一個穩定路徑 (註冊指向它所在的位置)。在 Linux 上,
   `~/.local/lib/chromium-bridge/` 是個好去處。`chromium-bridge uninstall`
   會精確撤銷註冊過的內容。

3. 載入擴充功能: 透過 `chrome://extensions` (開發人員模式, 「載入未封裝項
   目」) 載入壓縮檔裡的 `extension/dist/` 目錄。重新啟動瀏覽器。

4. 在 macOS 上配對: 執行 `chromium-bridge pair` (會彈出 Touch ID), 然後在
   擴充功能的選項頁核准指紋; macOS 上擴充功能預設要求完成此註冊。Linux 和
   Windows 跳過這一步。

5. 將你的 MCP 用戶端指向解壓出的二進位檔 (絕對路徑), 方法同上。

從原始碼建置: `cargo build --release`, 然後用
`target/release/chromium-bridge` 執行同樣的 `doctor --fix` (見
[docs/development.md](./docs/development.md))。

完整的 CLI (doctor、配對、撤銷、緊急停止開關、稽核) 見
[docs/cli.md](./docs/cli.md)。安裝與首次使用的完整指南 (含翻譯) 見
[docs/quickstart.zh_TW.md](./docs/quickstart.zh_TW.md)。

## 你能做什麼: 26 個工具

以 Rust 工具目錄
([`src/packages/core/src/tools/catalogue.rs`](./src/packages/core/src/tools/catalogue.rs))
為唯一事實來源。逐工具的影響範圍詳見
[工具風險矩陣](./docs/security/tool-risk-matrix.md)。

### 瀏覽器

| 工具 | 作用 | 風險 |
|------|------|------|
| `list_browsers` | 列出連接到橋的瀏覽器 (標籤 + 開啟的分頁數) | 低 |

可以同時連接多個瀏覽器 (在 macOS/Linux 上每個瀏覽器有自己的原生主機和標
籤, 例如 `chrome` 和 `brave`)。其他每個工具都接受可選的 `browser` 參數來指
定; 連接多個時, 未指定的呼叫會以明確錯誤失敗, 而不是猜測該在哪個已登入瀏覽
器裡操作。見 [ADR-0022](./docs/adr/0022-multi-browser-label-routing.md)。

### 分頁

| 工具 | 作用 | 風險 |
|------|------|------|
| `tab_list` | 列出開啟的分頁 (id、標題、url、是否作用中) | 低 |
| `tab_focus` | 將分頁切到前景 | 低 |
| `tab_open` | 在新分頁開啟 URL (主機必須在允許清單內) | 中 |
| `tab_close` | 關閉分頁 (確認視窗) | 高 |

### 導覽

| 工具 | 作用 | 風險 |
|------|------|------|
| `page_navigate` | 在作用中分頁載入 http(s) URL | 中 |
| `page_back` / `page_forward` | 在歷史記錄中前進/後退 | 低 |
| `page_reload` | 重新載入作用中分頁 | 低 |

### 檢查頁面

| 工具 | 作用 | 風險 |
|------|------|------|
| `page_snapshot` | 互動元素的無障礙樹近似, 每個元素帶穩定 `ref` | 低 |
| `page_snapshot_precise` | 經 `chrome.debugger` 的權威無障礙樹 (shadow DOM / 複雜 ARIA); ref 用 `p` 前綴 | 中 |
| `page_text` | 頁面可見文字 (密碼和類似卡號的數字遮罩) | 中 |
| `page_screenshot` | 可見視口的 PNG 截圖 | 中 |
| `console_get` | 最近的主控台輸出 (遮罩) | 中 |

### 操作頁面

| 工具 | 作用 | 風險 |
|------|------|------|
| `page_click` | 按 `ref` 或 `selector` 點擊; 提交/連結點擊需確認 | 高 |
| `page_fill` | 在輸入框中輸入 (原生 setter, React/Vue 能感知) | 高 |
| `page_press` | 送出按鍵或組合鍵 (需確認) | 高 |
| `page_select` | 在 `<select>` 中選擇選項 (需確認) | 高 |
| `page_hover` | 將指標移到元素上 | 低 |
| `page_scroll` | 上 / 下 / 頂部 / 底部 / N 像素 | 低 |
| `page_wait_for` | 等待選擇器、文字或導覽 | 低 |
| `page_handle_dialog` | 接受或關閉 JS 對話框 (預設關閉) | 高 |

### 執行程式碼與上傳 (最高風險)

| 工具 | 作用 | 風險 |
|------|------|------|
| `page_eval` | 執行任意 JS。每次呼叫都確認並顯示完整程式碼; 已註冊的 Mac 上是 Touch ID。回傳值預設遮罩。優先使用上面的工具。 | 危急 |
| `page_upload` | 把指定的本機檔案附加到檔案輸入框 (預設關閉; 每次呼叫都確認並顯示路徑) | 危急 |

### 讀取憑證 (唯讀, 始終遮罩)

| 工具 | 作用 | 風險 |
|------|------|------|
| `cookie_get` | 讀取作用中分頁的 Cookie, 含 `httpOnly`; 僅限允許清單內的主機 | 高 |
| `storage_get` | 讀取頁面的 `localStorage` / `sessionStorage` (同源) | 高 |

設計上沒有寫入工具; Cookie/儲存寫入不在範圍內
([ADR-0010](./docs/adr/0010-cookie-storage-readonly.md))。

## 運作原理

一個 Rust 二進位檔、兩種模式, 由一條經過驗證的本機通訊端連接。桌面應用程
式和 CLI 管理同一份狀態。

- **MCP 伺服器 (預設模式)**: 由你的 MCP 用戶端透過 stdio 啟動, 說
  JSON-RPC 2.0 (MCP 協定 `2025-06-18`)。第一個實例持有通訊端並成為
  broker (中樞); 後續實例作為中繼接入, 多個用戶端並行共享瀏覽器。
- **`--native-host`**: 由瀏覽器按主機資訊清單啟動, 是把 Chrome 原生訊息幀
  轉成通訊端上 NDJSON 的薄橋。每個安裝的瀏覽器用自己的標籤啟動自己的主機,
  一個 broker 可以按名字定址多個瀏覽器。
- **桌面應用程式 / CLI**: 基於同一個核心的對等管理面 (註冊、配對、撤銷、
  緊急停止開關、稽核)。兩者都不是信任根; 授予能力的操作最終都落在一次使用
  者在場驗證上。

為什麼是兩個行程? 瀏覽器負責拉起原生主機, MCP 用戶端負責拉起伺服器。兩者
不是父子行程, 所以需要一條 IPC。原生主機保持輕薄, 這樣 MV3 服務工作者的回
收 (約每 5 分鐘) 和主機重啟都不會遺失工作階段狀態。

深入閱讀: [docs/architecture.md](./docs/architecture.md)。

## 相容性

| | 支援情況 |
|---|---|
| macOS | Apple Silicon (arm64) 預編譯; 桌面應用程式和 Touch ID 門在這裡。Intel 需從原始碼建置。 |
| Linux | x64 預編譯; 任何 Chromium 系瀏覽器; 用 CLI 管理。 |
| Windows | x64 預編譯 (原生, 無需管理員)。橋接安全性為盡力而為; 見 [SECURITY.md](./SECURITY.md#platform-support)。 |
| 瀏覽器 | 任何 Chromium 系瀏覽器, Manifest V3 |
| MCP 協定 | `2025-06-18` ([ADR-0007](./docs/adr/0007-mcp-protocol-version-2025-06-18.md)) |
| 內部橋協定 | `1` ([src/packages/core/src/protocol.rs](./src/packages/core/src/protocol.rs) 中的 `BRIDGE_PROTOCOL_VERSION`) |

已知瀏覽器 (`--browser` 鍵): `chrome`、`chromium`、`brave`、`edge`、
`vivaldi`、`opera`。不在表內的 Chromium 變體可用
`doctor --fix --manifest-dir <dir>` 明確指定其目錄。見
[docs/compatibility.md](./docs/compatibility.md) 和
[docs/cli.md](./docs/cli.md)。

## 設定

啟動時讀取的環境變數:

| 變數 | 取值 | 預設 | 作用 |
|------|------|------|------|
| `BB_LOG` | `error` \| `warn` \| `info` \| `debug` | `info` | stderr 日誌 / 稽核閾值 |
| `BB_LOG_FORMAT` | `text` \| `json` | `text` | 稽核行格式; `json` 每行一個物件 |

持久稽核日誌 (`chromium-bridge audit`) 獨立於這兩個變數記錄; 見
[docs/cli.md](./docs/cli.md#logging-and-audit-bb_log--bb_log_format)。

## 疑難排解

先執行內建的唯讀自檢:

```sh
chromium-bridge doctor    # 或: chromium-bridge status
```

它報告伺服器是否可達、鎖檔狀態、緊急停止開關狀態, 以及每個瀏覽器的註冊狀
態; `doctor --fix` 就地修復註冊。然後檢查 MCP 用戶端的伺服器介面 (Claude
Code 裡用 `/mcp` 重連) 和 `chrome://extensions` 裡擴充功能的 Service
Worker 主控台 (找 `[bb]` 日誌)。完整手冊: [docs/cli.md](./docs/cli.md) 和
[docs/operations.md](./docs/operations.md)。

## 文件地圖

| 文件 | 內容 |
|------|------|
| [docs/quickstart.zh_TW.md](./docs/quickstart.zh_TW.md) | 安裝與首次使用 (應用程式 + CLI) |
| [docs/architecture.md](./docs/architecture.md) | 元件、資料流、協定、安全模型、關鍵約束 |
| [docs/security/](./docs/security/) | 威脅模型、信任邊界、工具風險矩陣、事件回應 |
| [docs/cli.md](./docs/cli.md) | 完整 CLI: doctor/--fix、uninstall、配對、撤銷、緊急停止開關、稽核 |
| [docs/desktop-app.md](./docs/desktop-app.md) | 桌面應用程式: 管理什麼、如何驗證 |
| [docs/operations.md](./docs/operations.md) | 二進位模式、日誌/稽核、執行時目錄、重連 |
| [docs/privacy-policy.zh_TW.md](./docs/privacy-policy.zh_TW.md) | 擴充功能的隱私權政策 |
| [docs/adr/](./docs/adr/) | 架構決策記錄: 每一個「為什麼這麼選」 |

## 專案狀態

1.0 之前 ([Cargo.toml](./Cargo.toml))。協定層由端對端、對抗性和混沌測試覆
蓋; 線格式解析器經過模糊測試。見 [CHANGELOG.md](./CHANGELOG.md)。

## 貢獻與治理

[CONTRIBUTING.md](./CONTRIBUTING.md) (工作流程)、
[GOVERNANCE.md](./GOVERNANCE.md) (變更如何發生)、
[SECURITY.md](./SECURITY.md) (回報 + 審查標準)、
[docs/development.md](./docs/development.md) (建置/測試/發布)。

## 授權

[Apache-2.0](./LICENSE)。版權歸 browser-bridge 貢獻者所有。
