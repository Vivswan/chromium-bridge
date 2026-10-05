# 快速入門: 安裝與首次使用

本指南帶你把 chromium-bridge 從下載完成, 一路走到在 MCP 用戶端裡成功「列出我的瀏覽器分頁」。入口是 CLI (macOS、Linux、Windows)。

開始之前, 請先閱讀 [README](../../README.zh-tw.md#安全優先) 中的安全摘要: 這個工具操作的是你已經登入的瀏覽器, 它顯示給你的確認視窗就是安全模型本身, 而不是阻礙。

擴充功能需要 Chrome 134 或更新版本; 更舊的瀏覽器會拒絕載入它。

## CLI (macOS、Linux、Windows)

CLI 只需要執行檔本身, 在桌面、無頭機器與 CI 上都一樣。

1. **安裝。** 從[最新發行版](https://github.com/Vivswan/chromium-bridge/releases/latest)挑一個; 若想先驗證下載內容, 相關命令在 [SECURITY.md](../../.github/SECURITY.md#release-artifact-integrity)。

   | 管道 | 命令或點擊 | 作用 |
   | --- | --- | --- |
   | macOS `.pkg` | 右鍵點擊, 開啟 (目前尚未簽署) | 安裝 `/usr/local/bin/chromium-bridge`, 並替你執行步驟 3 |
   | Windows `.msi` | 雙擊 (目前尚未簽署; SmartScreen 會警告) | 為你的帳戶安裝到 `%LOCALAPPDATA%\Programs\chromium-bridge`, 加入你的 PATH, 並替你執行步驟 3 |
   | Linux `.deb` | `sudo dpkg -i chromium-bridge-<tag>-linux-x64.deb` | 安裝 `/usr/bin/chromium-bridge`, 並替你執行步驟 3, 機器層級 |
   | Homebrew | `brew install vivswan/tap/chromium-bridge`, 待 tap 建立後 ([release.md](./release.md#homebrew-tap)) | 安裝執行檔, 並替你執行步驟 3 |
   | 壓縮檔 | 解壓 `chromium-bridge-<tag>-<platform>-<arch>.tar.gz` (Windows 上為 `.zip`) | 取得執行檔與 `extension/dist`; 步驟 2 與 3 需自行完成 |

   或者用 `cargo build --release` 從原始碼建置。Windows 的註冊尚未在使用者的機器上實際試過 ([cli.md 的 Windows 注意事項](./cli.md#doctor---fix--uninstall-原生訊息註冊))。
2. **僅限壓縮檔: 放到穩定的位置。** 註冊會直接指向執行檔所在的路徑, 所以要挑一個不會消失的路徑: Linux 上是 `~/.local/lib/chromium-bridge/`, macOS 上則是家目錄下的任何位置。AppImage 掛載點或暫存目錄都不穩定, 若你這麼做, `doctor --fix` 會提出警告。
3. **向你的瀏覽器註冊。** .pkg、.msi 與 Homebrew 已經替你做了, .deb 也替安裝當時已有的瀏覽器做了; 壓縮檔需要自行執行 (請在解壓出來的目錄中以 `./` 前綴執行執行檔):

   ```sh
   chromium-bridge doctor --fix                       # every detected browser
   chromium-bridge doctor --fix --browser chrome,brave
   chromium-bridge doctor --fix --manifest-dir DIR    # an unlisted Chromium
                                                      # variant (macOS/Linux)
   ```

   執行兩次也無妨, `chromium-bridge doctor --list` 以唯讀方式顯示狀態, `chromium-bridge uninstall` 則精確還原寫入的內容; 細節由 [cli.md](./cli.md#doctor---fix--uninstall-原生訊息註冊) 負責說明。

4. **載入擴充功能。** 擴充功能的 Web Store 上架頁面尚未發布 ([release.md 的 Web Store 一節](./release.md#發布到-chrome-線上應用程式商店)): 請透過 `chrome://extensions`, 開啟開發人員模式, 「載入未封裝項目」, 載入發行壓縮檔中的 `extension/dist` (若是原始碼 checkout, 請先建置, 再載入 `build/extension/chrome-mv3`)。然後重新啟動瀏覽器。

   上架頁面存在之後, [cli.md 的指標表](./cli.md#doctor---fix--uninstall-原生訊息註冊) 會說明哪些瀏覽器會依據步驟 3 留下的指標提供擴充功能, 以及哪些情況下不會寫入任何指標。

5. **配對。** 執行 `chromium-bridge pair`: 它會要求你在終端機輸入一段確認, 產生主機金鑰, 並印出金鑰的指紋。在擴充功能的選項頁面核准該指紋; 在固定完成之前, 擴充功能在每個平台上都拒絕執行任何動作 ([cli.md](./cli.md#登記-pair--revoke--enclave-status) 負責說明這項程序與其旗標)。

6. **登記 (建議)。** 在選項頁面的身分區段登記你瀏覽器的認證器。機器上的第一次登記是首次使用即信任; 之後每一次都需要一個已登記認證器的觸碰。

7. **連接你的 MCP 用戶端** 到執行檔的絕對路徑。以 Claude Code 為例:

   ```sh
   claude mcp add chromium-bridge -- /absolute/path/to/chromium-bridge
   ```

   對於 Claude Desktop 與其他以 JSON 設定的用戶端, 請新增一個 `mcpServers` 項目, 指向同一個絕對路徑, 不帶任何引數。

完整的命令參考 (配對、受信任用戶端、撤銷、緊急開關 (kill switch)、稽核日誌) 在 [cli.md](./cli.md)。

## 你應該看到什麼

- `chromium-bridge doctor` 回報你的瀏覽器註冊為 `ok`, 而且一旦你的 MCP 用戶端開啟了工作階段, 伺服器會顯示為可連線。
- 擴充功能的工具列圖示顯示連線狀態。
- 對新網站的第一次工具呼叫會在瀏覽器中跳出核准提示; 高風險動作會跳出確認視窗。

## 建議的強化

配對 (步驟 5) 在每個平台上都是必要的。登記 (步驟 6) 是建議項: 沒有已登記認證器的瀏覽器會在確認視窗中回答在場請求 (例如解除緊急開關), 而不是以觸碰回答。另有一項選用的程序可綁定 MCP 用戶端這一側:

- `chromium-bridge pair-client` 建立受信任用戶端允許清單。清單一旦存在, 只有程式碼身分經過證明且獲你核准的 MCP 用戶端才會獲得服務, 而且任何介面都能隨時撤銷其中一個。

兩者都在 [cli.md](./cli.md) 與[安全頁面](./security.md)中有說明。

## 解除安裝

`chromium-bridge uninstall` 精確移除 `--fix` 寫入的內容 ([cli.md](./cli.md#doctor---fix--uninstall-原生訊息註冊) 說明移除什麼, 以及拒絕移除什麼)。接著依照安裝時的方式移除執行檔:

| 管道 | 移除執行檔 |
| --- | --- |
| macOS `.pkg` | `sudo rm /usr/local/bin/chromium-bridge && sudo pkgutil --forget io.github.vivswan.chromium-bridge` |
| Windows `.msi` | 設定、應用程式、Chromium Bridge、解除安裝 (它會替你執行 `chromium-bridge uninstall`) |
| Linux `.deb` | `sudo dpkg -r chromium-bridge` |
| Homebrew | `brew uninstall chromium-bridge` |
| 壓縮檔 | 刪除解壓出來的目錄 |

配對狀態是分開的: `chromium-bridge revoke --all` 刪除主機金鑰並忘記每一個瀏覽器與受信任用戶端, 擴充功能的選項頁面則清除其固定的金鑰; 步驟 6 登記的認證器保存在主機的信任記錄中, `revoke <browser>` 只忘記一個瀏覽器的。
