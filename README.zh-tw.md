# chromium-bridge

[![CI](https://github.com/Vivswan/chromium-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/Vivswan/chromium-bridge/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Individual%20and%20Small%20Organization%201.1.0-blue)](./LICENSE.md)

[English](./README.md) | [简体中文](./README.zh-cn.md) | 繁體中文

你安裝的程式無法在你不知情的情況下使用你的瀏覽器。在這條標準之下, chromium-bridge 讓任何 MCP 用戶端 (Claude Code、Claude Desktop、Codex, 或任何支援 Model Context Protocol 的程式) 操作你真實的 Chromium 瀏覽器: 你的分頁、你已登入的工作階段、你的 Cookie, 全部透過一個瀏覽器擴充功能與一個原生訊息主機完成。不需要第二個瀏覽器, 不需要 CDP 偵錯連接埠, 也不需要 `--remote-debugging` 旗標。

因為它操作的是你已經登入的瀏覽器, 代理程式能讀取需要你的身分驗證才能看到的頁面、在你已登入的應用程式裡逐步點擊, 或取出你的框架存放在 `localStorage` 裡的權杖。這份能力同時也是風險, 所以安裝前請先閱讀[安全優先](#安全優先)。這條標準止步之處寫在[安全頁面](./docs/zh-tw/security.md)。

## 特色

- **你真實的瀏覽器, 而不是無頭瀏覽器:** 26 個涵蓋分頁、頁面、Cookie 與儲存空間的工具, 每一個都標明了風險等級與閘門 ([見下文](#你能做什麼-26-個工具))。
- **護欄預設開啟:** 逐站核准、在任何頁面都碰不到的視窗中確認危險動作、以 WebAuthn 證明在場、緊急開關 (kill switch)、稽核日誌 ([安全優先](#安全優先))。
- **一條經過驗證與證明的橋接**, 連接 MCP 伺服器與瀏覽器的主機, 沒有監聽連接埠 ([運作原理](#運作原理))。
- **多個用戶端同時連接,** 每一個都經過證明, 也能個別撤銷。
- **一個執行檔, 三種角色:** MCP 伺服器、原生訊息主機, 以及負責安裝、配對、緊急停止與稽核的 CLI。

## 安全優先

chromium-bridge 操作的是一個真實、已通過身分驗證的瀏覽器。它能讀取頁面內容、Cookie (包含 `httpOnly`) 與網頁儲存空間, 也能在你的頁面中執行 JavaScript。護欄如下:

- **核准每一個網站。** 新的來源 (origin) 會觸發提示; 在你尚未核准的網站上, 什麼都不會執行。
- **確認高風險動作。** 送出表單的點擊、按鍵、關閉分頁、檔案上傳, 以及每一次 `page_eval`, 都要在一個頁面看不到也點不到的、由擴充功能持有的視窗上確認。`page_eval` 與 `page_upload` 每次呼叫都重新確認。同一使用者的程式在這個視窗前後仍能做到的事, 寫在[信任邊界帳冊](./docs/zh-tw/security/trust-boundaries.md#邊界-4-擴充功能---網頁-chrome-api--內容指令碼--dom)裡。
- **以 WebAuthn 證明在場。** 解除緊急開關需要在該瀏覽器下登記的認證器輕觸一次, 而登記另一個瀏覽器則需要本機上任何一個已登記的認證器輕觸一次; 兩者都由主機驗證。只有在沒有任何已登記的認證器能夠回應時, 才由確認視窗代替。
- **閘門預設開啟。** 每一道閘門都是有文件記載的設定, 放寬任何一道都是明確且知情的選擇 ([SECURITY.md](./.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe))。
- **憑證唯讀。** Cookie 與儲存空間可以讀取 (一律遮罩: JWT、長十六進位字串、長數字串), 但永遠不能寫入。刻意不提供 `cookie_set` 或 `storage_set`。
- **經過驗證與證明的橋接。** 在 macOS 與 Linux 上, 主機程序透過一個私有的 Unix domain socket 通訊 (沒有監聽連接埠)。每一條連線都必須通過核心對端 UID 檢查、由核心證明的執行檔身分, 以及以每次執行的秘密為基礎的 HMAC 挑戰。
- **受信任用戶端允許清單。** MCP 用戶端依據一份以經證明的程式碼身分為鍵的允許清單進行准入, 任何一方都能隨時撤銷信任。
- **全域緊急開關。** 從 CLI 或擴充功能執行一個動作, 就能停止一切, 直到你以在場證明解除它 (輕觸一次、在該瀏覽器未登記任何認證器時使用確認視窗, 或在終端機輸入指定的語句)。每一個安全決策都會記錄到磁碟上的稽核日誌。

橋接的保證在 macOS、Linux 與 Windows 上都成立; 各作業系統背後的機制不同 ([SECURITY.md](./.github/SECURITY.md#platform-support))。

| 平台 | 橋接傳輸 | 連線的閘門 |
|---|---|---|
| macOS、Linux | 私有 Unix domain socket, 無監聽連接埠 | 對端 UID 檢查、核心證明、HMAC 挑戰 |
| Windows | 只有你的使用者能開啟的具名管道, 無監聽連接埠 | 管道的描述元 (由核心強制執行)、相互證明、HMAC 挑戰 |

完整細節: [SECURITY.md](./.github/SECURITY.md)、[安全頁面](./docs/zh-tw/security.md)、[信任邊界](./docs/zh-tw/security/trust-boundaries.md)、[各工具風險矩陣](./docs/zh-tw/security/tool-risk-matrix.md)。

## 需求

| | 支援 |
|---|---|
| macOS | 提供 Apple Silicon (arm64) 預先建置版本; Intel 需從原始碼建置 |
| Linux | 提供 x64 預先建置版本; 任何 Chromium 系瀏覽器 |
| Windows | 提供 x64 預先建置版本 (原生, 不需管理員權限); 只有你的使用者能開啟、並具相互證明的具名管道 ([SECURITY.md](./.github/SECURITY.md#platform-support)) |
| 瀏覽器 | 任何 Chromium 系瀏覽器, Manifest V3: `chrome`、`chromium`、`brave`、`edge`、`vivaldi`、`opera` 是已知的 `--browser` 鍵值; 在 macOS 與 Linux 上, 其他變種透過 `doctor --fix --manifest-dir <dir>` 註冊, 而 Windows 上的註冊則是已知瀏覽器的一個 HKCU 登錄機碼 |
| MCP 用戶端 | 任何透過 stdio 使用 MCP 協定 `2026-07-28` 的用戶端 |
| 內部橋接協定 | `1` ([src/packages/core/src/protocol.rs](./src/packages/core/src/protocol.rs) 中的 `BRIDGE_PROTOCOL_VERSION`) |

1.0 之前 ([Cargo.toml](./Cargo.toml)): 協定層由端對端、對抗性與混沌測試涵蓋, 線路解析器則經過模糊測試 ([CHANGELOG.md](./CHANGELOG.md))。

## 快速開始

CLI 除了執行檔本身之外不需要任何東西, 在桌面、無頭機器與 CI 上都一樣。完整步驟, 包括各個安裝管道以及每個管道為你做了什麼, 寫在[快速入門](./docs/zh-tw/quickstart.md); 以下是簡短版:

1. 從[最新發行版](https://github.com/Vivswan/chromium-bridge/releases/latest)安裝: `.pkg`、`.msi`、`.deb`、Homebrew, 或壓縮檔。若要先驗證下載的檔案, 命令寫在 [SECURITY.md](./.github/SECURITY.md#release-artifact-integrity)。

2. 將執行檔註冊到你的瀏覽器, 除非安裝程式已經做了 (`.pkg`、`.msi` 與 Homebrew 會做)。註冊是冪等的, 所以同一個命令既是全新安裝, 也是修復, 也是搬移執行檔後的重新註冊:

   ```sh
   chromium-bridge doctor --fix          # every detected browser
   chromium-bridge doctor --fix --browser chrome,brave
   ```

   若使用壓縮檔, 請以 `./` 前綴執行解壓縮出來的執行檔, 並把它放在穩定的路徑 (它是就地註冊的)。`chromium-bridge uninstall` 會精確還原所註冊的內容。

3. 載入擴充功能: 透過 `chrome://extensions`, 開啟開發人員模式, 點「載入未封裝項目」, 選擇壓縮檔中的 `extension/dist` 目錄。重新啟動瀏覽器。擴充功能需要 Chrome 134 或更新版本; 更舊的瀏覽器會拒絕載入它。

4. 配對與登記: `chromium-bridge pair` 會印出主機金鑰的指紋; 在擴充功能的選項頁面核准它, 然後在同一個頁面登記你瀏覽器的認證器 ([docs/cli.md](./docs/zh-tw/cli.md#登記-pair--revoke--enclave-status))。

5. 將你的 MCP 用戶端連接到執行檔的絕對路徑 (大多數用戶端不會展開 `~`)。不帶參數執行時, 執行檔透過 stdio 使用 MCP 通訊。

   ```sh
   claude mcp add chromium-bridge -- /absolute/path/to/chromium-bridge
   ```

   Claude Desktop 與其他使用 `mcpServers` JSON 的用戶端接受 `"command": "/ABSOLUTE/PATH/TO/chromium-bridge"` 搭配 `"args": []`; Codex 則在 `~/.codex/config.toml` 的 `[mcp_servers.chromium-bridge]` 之下接受同樣的兩個鍵。

改為從原始碼建置: `cargo build --release`, 然後從 `target/release/chromium-bridge` 執行同樣的 `doctor --fix` ([docs/development.md](./docs/zh-tw/development.md))。在 WSL 上, 請安裝在瀏覽器執行的那一側 ([在 WSL 下執行](./docs/zh-tw/troubleshooting.md#在-wsl-下執行))。

## 你能做什麼: 26 個工具

依據唯一的事實來源, 也就是 Rust 工具目錄 ([`src/packages/core/src/tools/catalogue.rs`](./src/packages/core/src/tools/catalogue.rs)) 分組; 每個工具的影響範圍與閘門寫在[工具風險矩陣](./docs/zh-tw/security/tool-risk-matrix.md)。

| 群組 | 工具 | 風險 |
|---|---|---|
| 瀏覽器 | `list_browsers` | 低 |
| 分頁 | `tab_list`、`tab_focus`、`tab_open`; `tab_close` 需確認 | 低至高 |
| 導覽 | `page_navigate`、`page_back`、`page_forward`、`page_reload` | 低至中 |
| 檢視頁面 | `page_snapshot`、`page_snapshot_precise`、`page_text`、`page_screenshot`、`console_get` | 低至中 |
| 操作頁面 | `page_click`、`page_fill`、`page_press`、`page_select`、`page_hover`、`page_scroll`、`page_wait_for`、`page_handle_dialog`; 送出表單的點擊、按鍵與選取需確認, 對話方塊處理預設關閉 | 低至高 |
| 執行程式碼與上傳 | `page_eval` (預設關閉; 每次呼叫都要確認, 並顯示完整程式碼)、`page_upload` (預設關閉; 每次呼叫都會連同路徑一起確認) | 嚴重 |
| 讀取憑證 | `cookie_get` (包含 `httpOnly`, 僅限已列入允許清單的主機)、`storage_get` (同源); 唯讀, 一律遮罩 | 高 |

可以同時連接多個瀏覽器; 在 macOS 與 Linux 上, 每個瀏覽器都有自己的原生主機與標籤 (例如 `chrome` 與 `brave`), 其他每個工具都接受一個選用的 `browser` 參數, 而在連接多個瀏覽器時, 未指定瀏覽器的呼叫會以明確的錯誤失敗, 而不是猜測。刻意不提供任何寫入工具: 偽造的 `httpOnly` Cookie 是工作階段固定攻擊的風險。

## 運作原理

一個 Rust 執行檔, 兩種模式, 由一條經過驗證的本機 socket 連接; CLI 負責管理狀態。

```text
MCP client A --stdio--> chromium-bridge (broker: first MCP server instance)
MCP client B --stdio--> chromium-bridge ----attach----^   |
(each client attested against the trusted-client         | bridge socket
 allowlist before it is served)                          | (Unix-domain socket,
                                                          | or a user-only named pipe
                                                          | on Windows; attestation + HMAC)
                                                          v
                             chromium-bridge --native-host   <-- spawned by
                                       |                         each browser
                                       | chrome.runtime.connectNative
                                       v
                             Chromium Bridge extension (MV3) --> your page
```

- **MCP 伺服器 (預設模式):** 由你的 MCP 用戶端透過 stdio 啟動; JSON-RPC 2.0, MCP 協定 `2026-07-28`, 無狀態, 並為較舊的用戶端程式 (harness) 保留暫時的舊版相容性。第一個實例擁有 socket 並成為中介 (broker); 之後的實例以中繼身分附接。
- **`--native-host`:** 由瀏覽器透過主機資訊清單啟動, 每個瀏覽器一個, 在 macOS 與 Linux 上各有自己的標籤; 一個精簡的橋接, 把 Chrome 的原生訊息訊框轉換為 socket 上的 NDJSON。
- **CLI:** 建立在同一個核心上的管理介面 (註冊、配對、撤銷、緊急開關、稽核)。它不是信任根; 授予能力的動作最終都要通過使用者在場的閘門。

瀏覽器產生原生主機, MCP 用戶端產生伺服器, 所以兩者不是父子關係, 需要 IPC; 主機保持精簡, 讓 MV3 Service Worker 的回收 (約每 5 分鐘一次) 與主機重啟不會遺失工作階段狀態。深入探討見 [docs/architecture.md](./docs/zh-tw/architecture.md)。

## 設定

啟動時讀取的環境變數:

| 變數 | 值 | 預設 | 效果 |
|-----|--------|---------|--------|
| `BB_LOG` | `error` \| `warn` \| `info` \| `debug` | `info` | stderr 日誌 / 稽核門檻 |
| `BB_LOG_FORMAT` | `text` \| `json` | `text` | 稽核行格式; `json` 每行輸出一個物件 |

持久的稽核日誌 (`chromium-bridge audit`) 獨立於這些變數記錄 ([docs/cli.md](./docs/zh-tw/cli.md#日誌與稽核-bb_log--bb_log_format))。

## 文件

文件發布於 <https://vivswan.github.io/chromium-bridge/docs/zh-tw/>, 提供英文、簡體中文與繁體中文版本; 同樣的頁面也放在 [docs/](./docs/zh-tw/README.md) 之下。

| 我想要 | 頁面 |
|---|---|
| 安裝並連接用戶端 | [快速入門](https://vivswan.github.io/chromium-bridge/docs/zh-tw/quickstart) |
| 了解某個工具可能做什麼 | [工具風險矩陣](https://vivswan.github.io/chromium-bridge/docs/zh-tw/security/tool-risk-matrix) |
| 執行 CLI: doctor、配對、受信任用戶端、緊急開關、策略、稽核 | [CLI](https://vivswan.github.io/chromium-bridge/docs/zh-tw/cli) |
| 修復某個症狀 | 先執行 `chromium-bridge doctor`, 再看[疑難排解](https://vivswan.github.io/chromium-bridge/docs/zh-tw/troubleshooting); 若兩者都沒有問題, 則檢查你的 MCP 用戶端的伺服器介面 (Claude Code 中的 `/mcp`) 與擴充功能在 `chrome://extensions` 的 Service Worker 主控台 (`[bb]` 日誌) |
| 知道什麼受信任, 什麼不受信任 | [安全](https://vivswan.github.io/chromium-bridge/docs/zh-tw/security)、[信任邊界](https://vivswan.github.io/chromium-bridge/docs/zh-tw/security/trust-boundaries)、[設計依據](https://vivswan.github.io/chromium-bridge/docs/zh-tw/security/rationale) |
| 看各部分如何組合 | [架構](https://vivswan.github.io/chromium-bridge/docs/zh-tw/architecture) |
| 建置、測試或發行 | [開發](https://vivswan.github.io/chromium-bridge/docs/zh-tw/development)、[發行](https://vivswan.github.io/chromium-bridge/docs/zh-tw/release) |

## 貢獻與治理

[CONTRIBUTING.md](./CONTRIBUTING.md) 是工作流程, [GOVERNANCE.md](./GOVERNANCE.md) 說明變更如何做出, [SECURITY.md](./.github/SECURITY.md) 是回報管道與審查標準, [tests/README.md](./tests/README.md) 則是各測試套件與瀏覽器安全規則。

## 授權

[Individual and Small Organization License 1.1.0](./LICENSE.md)。包含來自 [browser-bridge](https://github.com/whg517/browser-bridge) 的程式碼, 依 Apache-2.0 授權; 見 [LICENSE-APACHE](./LICENSE-APACHE) 與 [NOTICE](./NOTICE)。
