# 快速上手: 安裝與首次使用

> 本文是 [quickstart.md](./quickstart.md) 的繁體中文翻譯。以英文版為準;
> 简体中文版見 [quickstart.zh_CN.md](./quickstart.zh_CN.md)。

本指南帶你從下載走到在 MCP 用戶端裡成功執行「列出我的瀏覽器分頁」。入口
是 CLI (macOS、Linux、Windows)。

開始之前, 請先閱讀 [README](../README.zh_TW.md) 裡的安全摘要: 這個工具驅動
的是你已登入的瀏覽器, 它向你展示的確認提示就是安全模型本身, 而不是麻煩。

## CLI (macOS、Linux、Windows)

CLI 只需要二進位檔本身, 在桌面機器、無介面機器和 CI 上都一樣。目前唯一的例
外是 macOS 上的配對 (第 5 步), 它需要一個帶應用程式識別碼簽署的建置。

1. **取得二進位檔。** 從[最新發布版](https://github.com/Vivswan/chromium-bridge/releases/latest)
   下載對應平台的壓縮檔並解壓。想先驗證的話, 核對發布的 SHA-256 和建置來源
   證明; 指令見 [SECURITY.md](../.github/SECURITY.md#release-artifact-integrity)。
   也可以從原始碼建置: `cargo build --release`。
2. **放到穩定的位置。** 註冊指向二進位檔目前所在的路徑, 所以位置不能消
   失。Linux 上 `~/.local/lib/chromium-bridge/` 很合適; macOS 上放在家目錄
   下任意位置都可以。 (AppImage 掛載點或暫存目錄不穩定, `doctor --fix` 偵
   測到會發出警告。)
3. **註冊給瀏覽器:**

   ```sh
   ./chromium-bridge doctor --fix                       # 每一個偵測到的瀏覽器
   ./chromium-bridge doctor --fix --browser chrome,brave
   ./chromium-bridge doctor --fix --manifest-dir DIR    # 表外的 Chromium 變體
                                                        # (macOS/Linux)
   ```

   修復即冪等的重新註冊: 全新機器上它就是安裝, 移動二進位檔後它就是修復,
   跑兩遍也無害。`chromium-bridge doctor --list` 唯讀地顯示狀態,
   `chromium-bridge uninstall` 精確撤銷寫入過的內容。

4. **載入擴充功能。** 發布壓縮檔內含 `extension/dist/`; 透過
   `chrome://extensions` (開發人員模式, 「載入未封裝項目」) 載入 (原始碼
   檢出則先建置, 再載入 `build/extension/chrome-mv3`)。重新啟動瀏
   覽器。

5. **在 macOS 上配對。** 執行 `chromium-bridge pair` (Touch ID 彈出, 並印
   出金鑰指紋), 然後在擴充功能的選項頁核准該指紋。macOS 上擴充功能無條件
   要求完成此註冊 (舊的 `requireEnrollment` 開關已移除),
   在釘選完成之前拒絕執行任何操作。目前配對需要一個帶應用程式識別碼簽署的
   建置: 未簽署的發布二進位檔無法建立 Enclave 金鑰, WebAuthn 在場驗證軌道
   將取消這一要求。Linux 和 Windows 沒有 Secure Enclave, 跳過這一步。

6. **接上 MCP 用戶端**, 指向二進位檔的絕對路徑。以 Claude Code 為例:

   ```sh
   claude mcp add chromium-bridge -- /absolute/path/to/chromium-bridge
   ```

   Claude Desktop 等使用 JSON 設定的用戶端, 在 `mcpServers` 裡新增一個指向
   同一絕對路徑、不帶參數的條目即可。

完整指令參考 (配對、受信用戶端、撤銷、緊急停止開關、稽核日誌) 見
[cli.md](./cli.md)。

## 你應該看到什麼

- `chromium-bridge doctor` 報告你的瀏覽器註冊狀態為 `ok`; MCP 用戶端工作階
  段開啟後, 報告伺服器可達。
- 擴充功能的工具列圖示顯示連線狀態。
- 對新網站的第一次工具呼叫會在瀏覽器裡彈出核准提示; 高風險操作彈出確認視
  窗; 已註冊的 Mac 上, `page_eval` 和 `page_upload` 會彈出 Touch ID。

## 建議的強化

配對 (第 5 步) 在 macOS 上是必需的, 也是把最高風
險確認升級為硬體 Touch ID 的機制。另有一個可選儀式綁定 MCP 用戶端一側:

- `chromium-bridge pair-client` 建立受信用戶端允許清單。清單一旦存在, 只有程式碼身分經過認證且被你核准的 MCP 用戶端才會
  被服務, 任何一方都可以隨時撤銷。

兩者的細節見 [cli.md](./cli.md) 和
[威脅模型](./security/threat-model.md)。

## 移除

- `chromium-bridge uninstall` 移除本專案寫入的資訊清單和包裝腳
  本, 且僅移除這些。然後刪除二進位檔, 並在瀏覽器裡移除擴充功能。

註冊狀態是獨立的: `chromium-bridge revoke` 刪除 Secure Enclave 金鑰, 擴充
功能的選項頁清除其釘選。
