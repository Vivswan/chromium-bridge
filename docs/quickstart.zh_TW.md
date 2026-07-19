# 快速上手: 安裝與首次使用

> 本文是 [quickstart.md](./quickstart.md) 的繁體中文翻譯。以英文版為準;
> 简体中文版見 [quickstart.zh_CN.md](./quickstart.zh_CN.md)。

本指南帶你從下載走到在 MCP 用戶端裡成功執行「列出我的瀏覽器分頁」。有兩條
對等的路徑: 桌面應用程式 (macOS, 無需終端機) 和 CLI (macOS、Linux、
Windows)。兩者驅動同一個引擎、寫入相同的註冊資訊, 所以可以用其中一個開
始, 用另一個修復或移除。

開始之前, 請先閱讀 [README](../README.zh_TW.md) 裡的安全摘要: 這個工具驅動
的是你已登入的瀏覽器, 它向你展示的確認提示就是安全模型本身, 而不是麻煩。

## 路徑 A: 桌面應用程式 (macOS)

> 應用程式安裝包尚未發布 (目前發布版只含 CLI 壓縮檔)。在此之前, 請在原始
> 碼檢出中用 `just run-app` 建置並啟動應用程式, 或使用路徑 B。

1. **安裝應用程式。** 取得 `Chromium Bridge.app` (見上面的說明) 並開啟。首
   次啟動時它會向偵測到的每一個 Chromium 系瀏覽器註冊內建的原生訊息主機,
   並逐條列出寫入的內容。系統裡的其他東西一概不碰。
2. **載入擴充功能。** 在應用程式的 Setup 頁點擊「Reveal folder」。在瀏覽器
   中開啟 `chrome://extensions`, 開啟開發人員模式, 點擊「載入未封裝項目」,
   選擇剛才開啟的目錄。然後重新啟動瀏覽器, 使它重新讀取原生訊息註冊。
3. **用 Touch ID 配對。** 在應用程式的 Pairing 頁點擊 Pair; Touch ID 彈出
   後, 頁面會顯示新金鑰的指紋。在擴充功能的選項頁核准同一枚指紋。macOS 上
   擴充功能預設要求完成此註冊 (`requireEnrollment`), 在釘選完成之前拒絕執
   行任何操作 ([ADR-0021](./adr/0021-enrollment-ceremony.md))。
4. **把指令交給 MCP 用戶端。** 在 Setup 頁點擊 Install, 將
   `chromium-bridge` 指令放到 `~/.local/bin/chromium-bridge`, 然後在用戶端
   裡註冊。對 Claude Code 來說, 這是整條路徑中唯一的一條指令:

   ```sh
   claude mcp add chromium-bridge -- "$HOME/.local/bin/chromium-bridge"
   ```

   Claude Desktop 等使用 JSON 設定的用戶端, 在 `mcpServers` 裡新增一個指向
   同一絕對路徑、不帶參數的條目即可。

5. **試一試。** 讓用戶端「列出我的瀏覽器分頁」。第一次操作新網站時, 點擊
   Chromium Bridge 工具列圖示並核准該來源。

裝好之後應用程式依然有用: 它是瀏覽器註冊、Touch ID 註冊、受信 MCP 用戶
端、緊急停止開關和稽核日誌的控制面板。見 [desktop-app.md](./desktop-app.md)。

## 路徑 B: CLI (macOS、Linux、Windows)

CLI 只需要二進位檔本身。在 Linux、Windows、無介面機器和 CI 上它是自然選
擇。

1. **取得二進位檔。** 從[最新發布版](https://github.com/Vivswan/chromium-bridge/releases/latest)
   下載對應平台的壓縮檔並解壓。想先驗證的話, 核對發布的 SHA-256 和建置來源
   證明; 指令見 [SECURITY.md](../SECURITY.md#release-artifact-integrity)。
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
   出金鑰指紋), 然後在擴充功能的選項頁核准該指紋。macOS 上擴充功能預設要
   求完成此註冊, 在釘選完成之前拒絕執行任何操作。Linux 和 Windows 沒有
   Secure Enclave, 跳過這一步。

6. **接上 MCP 用戶端**, 指向二進位檔的絕對路徑, 方法同路徑 A。

完整指令參考 (配對、受信用戶端、撤銷、緊急停止開關、稽核日誌) 見
[cli.md](./cli.md)。

## 兩條路徑之後: 你應該看到什麼

- `chromium-bridge doctor` 報告你的瀏覽器註冊狀態為 `ok`; MCP 用戶端工作階
  段開啟後, 報告伺服器可達。
- 擴充功能的工具列圖示顯示連線狀態。
- 對新網站的第一次工具呼叫會在瀏覽器裡彈出核准提示; 高風險操作彈出確認視
  窗; 已註冊的 Mac 上, `page_eval` 和 `page_upload` 會彈出 Touch ID。

## 建議的強化

配對 (路徑 A 第 3 步 / 路徑 B 第 5 步) 在 macOS 上是必需的, 也是把最高風
險確認升級為硬體 Touch ID 的機制。另有一個可選儀式綁定 MCP 用戶端一側:

- `chromium-bridge pair-client` (或應用程式的 Clients 頁) 建立受信用戶端允
  許清單。清單一旦存在, 只有程式碼身分經過認證且被你核准的 MCP 用戶端才會
  被服務, 任何一方都可以隨時撤銷。

兩者的細節見 [cli.md](./cli.md) 和
[威脅模型](./security/threat-model.md)。

## 移除

- 應用程式路徑: 結束應用程式, 刪除 `Chromium Bridge.app`, 並在
  `chrome://extensions` 移除擴充功能。註冊指向應用程式套件內部; 用
  `chromium-bridge uninstall` (Setup 頁安裝的 CLI 或任意一份二進位檔) 清理
  註冊。
- CLI 路徑: `chromium-bridge uninstall` 移除本專案寫入的資訊清單和包裝腳
  本, 且僅移除這些。然後刪除二進位檔, 並在瀏覽器裡移除擴充功能。

註冊狀態是獨立的: `chromium-bridge revoke` 刪除 Secure Enclave 金鑰, 擴充
功能的選項頁清除其釘選。
