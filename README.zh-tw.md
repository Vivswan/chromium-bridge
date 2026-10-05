# chromium-bridge

> English: [README.md](./README.md)

讓任何 MCP 用戶端 (Claude Code、Claude Desktop、Codex, 或任何支援 Model Context Protocol 的程式) 操作你真實的 Chromium 瀏覽器: 你的分頁、你已登入的工作階段、你的 Cookie, 全部透過一個瀏覽器擴充功能與一個原生訊息主機完成。不需要第二個瀏覽器, 不需要 CDP 偵錯連接埠, 也不需要 `--remote-debugging` 旗標。

因為它操作的是你已經登入的瀏覽器, 代理程式能做到全新無頭瀏覽器做不到的事:

- 讀取需要你的身分驗證才能看到的頁面;
- 在你已登入的應用程式裡逐步點擊;
- 取出你的框架存放在 `localStorage` 裡的權杖。

這份能力同時也是風險。安裝前請先閱讀[安全優先](#安全優先)。

本專案對自己的要求: 你安裝的程式無法在你不知情的情況下使用你的瀏覽器; 這條標準今天在 macOS、Linux 與 Windows 上都成立 ([安全頁面](./docs/zh-tw/security.md) 陳述了這條標準, 以及它止步之處)。

## 安全優先

chromium-bridge 操作的是一個真實、已通過身分驗證的瀏覽器。它能讀取頁面內容、Cookie (包含 `httpOnly`) 與網頁儲存空間, 也能在你的頁面中執行 JavaScript。護欄如下:

- **核准每一個網站。** 新的來源 (origin) 會觸發提示; 在你尚未核准的網站上, 什麼都不會執行。
- **確認高風險動作。** 送出表單的點擊、按鍵、關閉分頁、檔案上傳, 以及每一次 `page_eval`, 都要在一個頁面看不到也點不到的、由擴充功能持有的視窗上確認。`page_eval` 與 `page_upload` 每次呼叫都重新確認。同一使用者的程式在這個視窗前後仍能做到的事, 寫在[信任邊界帳冊](./docs/zh-tw/security/trust-boundaries.md#邊界-4-擴充功能---網頁-chrome-api--內容指令碼--dom)裡。
- **以 WebAuthn 證明在場。** 解除緊急開關 (kill switch) 需要在該瀏覽器下登記的認證器輕觸一次, 而登記另一個瀏覽器則需要本機上任何一個已登記的認證器輕觸一次; 兩者都由主機驗證。只有在沒有任何已登記的認證器能夠回應時, 才由確認視窗代替。
- **閘門預設開啟。** 每一道閘門都是有文件記載的設定, 放寬任何一道都是明確且知情的選擇 ([SECURITY.md](./.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe))。
- **憑證唯讀。** Cookie 與儲存空間可以讀取 (一律遮罩: JWT、長十六進位字串、長數字串), 但永遠不能寫入。刻意不提供 `cookie_set` 或 `storage_set`。
- **經過驗證與證明的橋接。** 在 macOS 與 Linux 上, 主機程序透過一個私有的 Unix domain socket 通訊 (沒有監聽連接埠)。每一條連線都必須通過核心對端 UID 檢查、由核心證明的執行檔身分, 以及以每次執行的秘密為基礎的 HMAC 挑戰。
- **受信任用戶端允許清單。** MCP 用戶端依據一份以經證明的程式碼身分為鍵的允許清單進行准入, 任何一方都能隨時撤銷信任。
- **全域緊急開關。** 從 CLI 或擴充功能執行一個動作, 就能停止一切, 直到你以在場證明解除它 (輕觸一次、在該瀏覽器未登記任何認證器時使用確認視窗, 或在終端機輸入指定的語句)。每一個安全決策都會記錄到磁碟上的稽核日誌。

**平台誠實說明。** 橋接的保證在 macOS、Linux 與 Windows 上都成立; 各作業系統背後的機制不同 ([SECURITY.md](./.github/SECURITY.md#platform-support))。

| 平台 | 橋接傳輸 | 連線的閘門 |
|---|---|---|
| macOS、Linux | 私有 Unix domain socket, 無監聽連接埠 | 對端 UID 檢查、核心證明、HMAC 挑戰 |
| Windows | 只有你的使用者能開啟的具名管道, 無監聽連接埠 | 管道的描述元 (由核心強制執行)、相互證明、HMAC 挑戰 |

完整細節: [SECURITY.md](./.github/SECURITY.md)、[安全頁面](./docs/zh-tw/security.md)、[信任邊界](./docs/zh-tw/security/trust-boundaries.md)、[各工具風險矩陣](./docs/zh-tw/security/tool-risk-matrix.md)。

## 使用 CLI 快速入門 (macOS、Linux、Windows)

CLI 除了執行檔本身之外不需要任何東西, 在桌面、無頭機器與 CI 上都一樣。完整步驟, 包括各個安裝管道以及每個管道為你做了什麼, 寫在 [docs/quickstart.md](./docs/zh-tw/quickstart.md); 以下是簡短版:

1. 從[最新發行版](https://github.com/Vivswan/chromium-bridge/releases/latest)安裝: `.pkg`、`.msi`、`.deb`、Homebrew, 或壓縮檔。若要先驗證下載的檔案, 命令寫在 [SECURITY.md](./.github/SECURITY.md#release-artifact-integrity)。

2. 將執行檔註冊到你的瀏覽器, 除非安裝程式已經做了 (`.pkg`、`.msi` 與 Homebrew 會做)。註冊是冪等的, 所以同一個命令既是全新安裝, 也是修復, 也是搬移執行檔後的重新註冊:

   ```sh
   chromium-bridge doctor --fix          # every detected browser
   chromium-bridge doctor --fix --browser chrome,brave
   ```

   若使用壓縮檔, 請以 `./` 前綴執行解壓縮出來的執行檔, 並把它放在穩定的路徑 (它是就地註冊的)。`chromium-bridge uninstall` 會精確還原所註冊的內容。

3. 載入擴充功能: 透過 `chrome://extensions`, 開啟開發人員模式, 點「載入未封裝項目」, 選擇壓縮檔中的 `extension/dist` 目錄。重新啟動瀏覽器。擴充功能需要 Chrome 134 或更新版本; 更舊的瀏覽器會拒絕載入它。

4. 配對與登記: `chromium-bridge pair` 會印出主機金鑰的指紋; 在擴充功能的選項頁面核准它, 然後在同一個頁面登記你瀏覽器的認證器 ([docs/cli.md](./docs/zh-tw/cli.md#登記-pair--revoke--enclave-status))。

5. 將你的 MCP 用戶端連接到執行檔的絕對路徑, 方法如下。

改為從原始碼建置: `cargo build --release`, 然後從 `target/release/chromium-bridge` 執行同樣的 `doctor --fix` (見 [docs/development.md](./docs/zh-tw/development.md))。

完整的 CLI (doctor、配對、撤銷、緊急開關、稽核) 記載於 [docs/cli.md](./docs/zh-tw/cli.md)。

## 連接你的 MCP 用戶端

把你的用戶端指向已安裝的執行檔。不帶參數執行時, 它透過 stdio 使用 MCP 通訊。請使用絕對路徑; 大多數用戶端不會展開 `~`。

Claude Code:

```sh
claude mcp add chromium-bridge -- /absolute/path/to/chromium-bridge
```

Claude Desktop 與其他使用 `mcpServers` JSON 的用戶端:

```json
{
  "mcpServers": {
    "chromium-bridge": {
      "command": "/ABSOLUTE/PATH/TO/chromium-bridge",
      "args": []
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.chromium-bridge]
command = "/absolute/path/to/chromium-bridge"
args = []
```

可以同時連接多個用戶端: 第一個伺服器實例成為中介 (broker), 之後的實例附接到它, 每一個都經過證明, 也能個別撤銷。

在 WSL 上, 請安裝在瀏覽器執行的那一側 ([在 WSL 下執行](./docs/zh-tw/troubleshooting.md#在-wsl-下執行)):

- 日常使用 Windows Chrome: 安裝在 Windows 上, 並讓 WSL 用戶端透過 `/mnt/c` 指向該 `.exe`; 不要安裝 Linux 主機。
- 在 WSLg 下使用 Chrome: 直接在 Linux 中原生安裝。

## 你能做什麼: 26 個工具

依據唯一的事實來源, 也就是 Rust 工具目錄 ([`src/packages/core/src/tools/catalogue.rs`](./src/packages/core/src/tools/catalogue.rs)) 分組。每個工具的完整影響範圍細節在[工具風險矩陣](./docs/zh-tw/security/tool-risk-matrix.md)。

### 瀏覽器

| 工具 | 功能 | 風險 |
|------|------|------|
| `list_browsers` | 列出連接到橋接的瀏覽器 (標籤 + 開啟的分頁數) | 低 |

可以同時連接多個瀏覽器; 在 macOS/Linux 上, 每個瀏覽器都有自己的原生主機與標籤 (例如 `chrome` 與 `brave`)。其他每個工具都接受一個選用的 `browser` 參數來指定瀏覽器。連接多個瀏覽器時, 未指定瀏覽器的呼叫會以明確的錯誤失敗, 而不是猜測該在哪個已登入的瀏覽器中操作。

### 分頁

| 工具 | 功能 | 風險 |
|------|------|------|
| `tab_list` | 列出開啟的分頁 (id、title、url、active) | 低 |
| `tab_focus` | 將分頁帶到前景 | 低 |
| `tab_open` | 在新分頁開啟 URL (主機名稱必須在允許清單中) | 中 |
| `tab_close` | 關閉分頁 (確認視窗) | 高 |

### 導覽

| 工具 | 功能 | 風險 |
|------|------|------|
| `page_navigate` | 在作用中的分頁載入 http(s) URL | 中 |
| `page_back` / `page_forward` | 在歷史記錄中前後移動 | 低 |
| `page_reload` | 重新載入作用中的分頁 | 低 |

### 檢視頁面

| 工具 | 功能 | 風險 |
|------|------|------|
| `page_snapshot` | 互動元素的無障礙式樹狀結構, 每個元素都有穩定的 `ref` | 低 |
| `page_snapshot_precise` | 透過 `chrome.debugger` 取得權威的無障礙樹 (shadow DOM / 複雜 ARIA); ref 使用 `p` 前綴 | 中 |
| `page_text` | 頁面可見文字 (密碼與類似卡號的數字會遮罩) | 中 |
| `page_screenshot` | 可見視埠的 PNG | 中 |
| `console_get` | 最近的主控台輸出, 已遮罩 | 中 |

### 操作頁面

| 工具 | 功能 | 風險 |
|------|------|------|
| `page_click` | 以 `ref` 或 `selector` 點擊; 送出/連結的點擊需要確認 | 高 |
| `page_fill` | 在欄位中輸入文字 (使用原生 setter, 所以 React/Vue 能偵測到) | 高 |
| `page_press` | 送出按鍵或組合鍵 (確認) | 高 |
| `page_select` | 在 `<select>` 中選擇選項 (確認) | 高 |
| `page_hover` | 將指標移到元素上 | 低 |
| `page_scroll` | 上 / 下 / 頂端 / 底端 / N 像素 | 低 |
| `page_wait_for` | 等待選擇器、文字或導覽 | 低 |
| `page_handle_dialog` | 接受或關閉 JS 對話方塊 (預設關閉) | 高 |

### 執行程式碼與上傳 (風險最高)

| 工具 | 功能 | 風險 |
|------|------|------|
| `page_eval` | 執行任意 JS。預設關閉; 每次呼叫都要確認, 並顯示完整程式碼。回傳值預設遮罩。請優先使用上述工具。 | 嚴重 |
| `page_upload` | 將指定的本機檔案附加到檔案輸入欄位 (預設關閉; 每次呼叫都會連同路徑一起確認) | 嚴重 |

### 讀取憑證 (唯讀, 一律遮罩)

| 工具 | 功能 | 風險 |
|------|------|------|
| `cookie_get` | 讀取作用中分頁的 Cookie, 包含 `httpOnly`; 僅限允許清單中的主機名稱 | 高 |
| `storage_get` | 讀取頁面的 `localStorage` / `sessionStorage` (同源) | 高 |

刻意不提供寫入工具; Cookie/儲存空間的寫入不在範圍內: 偽造的 httpOnly Cookie 是工作階段固定攻擊的風險 ([工具風險矩陣](./docs/zh-tw/security/tool-risk-matrix.md) 有完整的理由)。

## 運作原理

一個 Rust 執行檔, 兩種模式, 由一條經過驗證的本機 socket 連接。CLI 負責管理狀態。

```
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

- **MCP 伺服器 (預設模式)**: 由你的 MCP 用戶端透過 stdio 啟動。使用 JSON-RPC 2.0 通訊: MCP 協定 `2026-07-28`, 無狀態, 並為較舊的用戶端程式 (harness) 保留暫時的舊版相容性。
  - 第一個實例擁有 socket 並成為中介; 之後的實例以中繼身分附接, 因此多個用戶端能同時共用瀏覽器。
- **`--native-host`**: 由瀏覽器透過主機資訊清單啟動。一個精簡的橋接, 把 Chrome 的原生訊息訊框轉換為 socket 上的 NDJSON。
  - 每個已安裝的瀏覽器都啟動自己的主機, 帶有自己的標籤, 所以一個中介能以名稱指定多個瀏覽器。
- **CLI**: 建立在同一個核心上的管理介面 (註冊、配對、撤銷、緊急開關、稽核)。它不是信任根; 授予能力的動作最終都要通過使用者在場的閘門。

**為什麼要兩個程序?** 瀏覽器產生原生主機, MCP 用戶端產生伺服器, 所以兩者不是父子關係, 需要 IPC。原生主機保持精簡, 讓 MV3 Service Worker 的回收 (約每 5 分鐘一次) 與主機重啟不會遺失工作階段狀態。

深入了解: [docs/architecture.md](./docs/zh-tw/architecture.md)。

## 相容性

| | 支援 |
|---|---|
| macOS | 提供 Apple Silicon (arm64) 預先建置版本; Intel 需從原始碼建置。 |
| Linux | 提供 x64 預先建置版本; 任何 Chromium 系瀏覽器; CLI 管理介面。 |
| Windows | 提供 x64 預先建置版本 (原生, 不需管理員權限)。橋接是只有你的使用者能開啟的具名管道, 並有相互證明; 見 [SECURITY.md](./.github/SECURITY.md#platform-support)。 |
| 瀏覽器 | 任何 Chromium 系瀏覽器, Manifest V3 |
| MCP 協定 | `2026-07-28` |
| 內部橋接協定 | `1` ([src/packages/core/src/protocol.rs](./src/packages/core/src/protocol.rs) 中的 `BRIDGE_PROTOCOL_VERSION`) |

已知的瀏覽器 (`--browser` 鍵值): `chrome`、`chromium`、`brave`、`edge`、`vivaldi`、`opera`。每個 Chromium 瀏覽器都讀取同一份原生訊息資訊清單; 只有各使用者的 `NativeMessagingHosts` 位置不同, 核心中的共用解析器知道所有位置。

對於不在清單中的 Chromium 變種, `doctor --fix --manifest-dir <dir>` 可以明確指定其目錄 (macOS/Linux; 在 Windows 上註冊是一個 HKCU 登錄機碼)。見 [docs/cli.md](./docs/zh-tw/cli.md)。

## 設定

啟動時讀取的環境變數:

| 變數 | 值 | 預設 | 效果 |
|-----|--------|---------|--------|
| `BB_LOG` | `error` \| `warn` \| `info` \| `debug` | `info` | stderr 日誌 / 稽核門檻 |
| `BB_LOG_FORMAT` | `text` \| `json` | `text` | 稽核行格式; `json` 每行輸出一個物件 |

持久的稽核日誌 (`chromium-bridge audit`) 獨立於這些變數記錄; 見 [docs/cli.md](./docs/zh-tw/cli.md#日誌與稽核-bb_log--bb_log_format)。

## 疑難排解

先執行內建的唯讀自我檢查:

```sh
chromium-bridge doctor    # or: chromium-bridge status
```

它會回報伺服器是否可連線、鎖定檔狀態、緊急開關, 以及每個瀏覽器的註冊狀態; `doctor --fix` 會就地修復註冊。如果這些都正常, 請檢查:

- 你的 MCP 用戶端的伺服器介面 (在 Claude Code 中以 `/mcp` 重新連線);
- 擴充功能在 `chrome://extensions` 的 Service Worker 主控台 (尋找 `[bb]` 日誌)。

完整手冊: [docs/cli.md](./docs/zh-tw/cli.md) 與 [docs/troubleshooting.md](./docs/zh-tw/troubleshooting.md)。

## 文件地圖

| 文件 | 內容 |
|-----|--------------|
| [docs/quickstart.md](./docs/zh-tw/quickstart.md) | 安裝與首次使用 |
| [docs/architecture.md](./docs/zh-tw/architecture.md) | 元件、資料流、協定、安全模型、關鍵限制 |
| [docs/security/](./docs/zh-tw/security/) | 信任邊界帳冊、工具風險矩陣、設計依據、事件回應; 面向讀者的頁面是 [docs/security.md](./docs/zh-tw/security.md) |
| [docs/cli.md](./docs/zh-tw/cli.md) | 完整的 CLI: doctor/--fix、uninstall、配對、撤銷、緊急開關、稽核 |
| [docs/troubleshooting.md](./docs/zh-tw/troubleshooting.md) | 逐一症狀: doctor 各列、緊急開關記錄的復原、版本不一致、兩種 WSL 模式 |
| [docs/release.md](./docs/zh-tw/release.md) | release-please 發行、預先建置的壓縮檔 + 校驗和、SBOM、哪個版本何時變動 |
| [docs/security/rationale.md](./docs/zh-tw/security/rationale.md) | 每個安全決策的理由, 以及被否決的方案 |

<details>
<summary>測試與專案配置</summary>

跨兩種語言的獨立測試套件 ([tests/README.md](./tests/README.md)):

| 套件 | 位置 | 功能 |
|---|---|---|
| 協定 | `tests/protocol/e2e.py` (加上 `adversarial.py` 與 `chaos.py`) | 透過真實的線路協定驅動真實的執行檔 |
| 瀏覽器 | `tests/browser/run_all.ts`: DOM、冒煙、安全、WebAuthn 與取消套件 | 僅限隔離的 Chrome: 透過 CDP 的內容指令碼、建置好的擴充功能的 Service Worker、瀏覽器端的安全證明、WebAuthn 用戶端、取消訊框 |
| 真實整合 (選擇加入) | `tests/browser/integration_e2e.ts` 搭配 `BB_REAL_E2E=1` | 對真實環境進行端對端測試 |

配置:

| 路徑 | 內容 |
|---|---|
| `src/apps/host` | Rust 執行檔 |
| `src/apps/extension` | MV3 擴充功能 (WXT) |
| `src/packages/core` | Rust 函式庫, 也是跨程序契約的唯一來源 |
| `src/packages/shared` | 產生的 TS 契約 + 驗證器 |

</details>

## 專案狀態

1.0 之前 ([Cargo.toml](./Cargo.toml))。協定層由端對端、對抗性與混沌測試涵蓋; 線路解析器經過模糊測試。見 [CHANGELOG.md](./CHANGELOG.md)。

## 貢獻與治理

[CONTRIBUTING.md](./CONTRIBUTING.md) (工作流程)、[GOVERNANCE.md](./GOVERNANCE.md) (變更如何做出)、[SECURITY.md](./.github/SECURITY.md) (回報 + 審查標準)、[docs/development.md](./docs/zh-tw/development.md) (建置/測試/發行循環)。

## 授權

[Individual and Small Organization License 1.0.0](./LICENSE.md)。包含來自 [browser-bridge](https://github.com/whg517/browser-bridge) 的程式碼, 依 Apache-2.0 授權; 見 [LICENSE-APACHE](./LICENSE-APACHE) 與 [NOTICE](./NOTICE)。
