# 快速入門: 安裝與首次使用

本指南帶你把 genkan 從下載完成, 一路走到在 MCP 用戶端裡成功「列出我的瀏覽器分頁」。入口是 CLI (macOS、Linux、Windows)。

開始之前, 請先閱讀 [README](../../README.zh-tw.md#安全優先) 中的安全摘要: 這個工具操作的是你已經登入的瀏覽器, 它顯示給你的確認視窗就是安全模型本身, 而不是阻礙。

擴充功能需要 Chrome 134 或更新版本; 更舊的瀏覽器會拒絕載入它。

## CLI (macOS、Linux、Windows)

CLI 只需要執行檔本身, 在桌面、無頭機器與 CI 上都一樣。

1. **安裝。** 從[最新發行版](https://github.com/Vivswan/genkan/releases/latest)挑一個; 若想先驗證下載內容, 相關命令在 [SECURITY.md](../../.github/SECURITY.md#release-artifact-integrity)。

   | 管道 | 命令或點擊 | 作用 |
   | --- | --- | --- |
   | macOS `.pkg` | 右鍵點擊, 開啟 (目前尚未簽署) | 安裝 `/usr/local/bin/genkan`, 並替你執行步驟 3 |
   | Windows `.msi` | 雙擊 (目前尚未簽署; SmartScreen 會警告) | 為你的帳戶安裝到 `%LOCALAPPDATA%\Programs\genkan`, 加入你的 PATH, 並替你執行步驟 3 |
   | Linux `.deb` | `sudo dpkg -i genkan-<tag>-linux-x64.deb` | 安裝 `/usr/bin/genkan`, 並替你執行步驟 3, 機器層級 |
   | Homebrew | `brew install vivswan/tap/genkan`, 待 tap 建立後 ([release.md](./release.md#homebrew-tap)) | 安裝執行檔, 並替你執行步驟 3 |
   | 壓縮檔 | 解壓 `genkan-<tag>-<platform>-<arch>.tar.gz` (Windows 上為 `.zip`) | 取得執行檔與 `extension/dist`; 步驟 2 與 3 需自行完成 |

   或者用 `cargo build --release` 從原始碼建置。Windows 的註冊尚未在使用者的機器上實際試過 ([cli.md 的 Windows 注意事項](./cli.md#doctor---fix--uninstall-原生訊息註冊))。
2. **僅限壓縮檔: 放到穩定的位置。** 註冊會直接指向執行檔所在的路徑, 所以要挑一個不會消失的路徑: Linux 上是 `~/.local/lib/genkan/`, macOS 上則是家目錄下的任何位置。AppImage 掛載點或暫存目錄都不穩定, 若你這麼做, `doctor --fix` 會提出警告。
3. **向你的瀏覽器註冊。** .pkg、.msi 與 Homebrew 已經替你做了, .deb 也替安裝當時已有的瀏覽器做了; 壓縮檔需要自行執行 (請在解壓出來的目錄中以 `./` 前綴執行執行檔):

   ```sh
   genkan doctor --fix                       # every detected browser
   genkan doctor --fix --browser chrome,brave
   genkan doctor --fix --manifest-dir DIR    # an unlisted Chromium
                                                      # variant (macOS/Linux)
   ```

   執行兩次也無妨, `genkan doctor --list` 以唯讀方式顯示狀態, `genkan uninstall` 則精確還原寫入的內容; 細節由 [cli.md](./cli.md#doctor---fix--uninstall-原生訊息註冊) 負責說明。

4. **載入擴充功能。** 擴充功能的 Web Store 上架頁面尚未發布 ([release.md 的 Web Store 一節](./release.md#發布到-chrome-線上應用程式商店)): 請透過 `chrome://extensions`, 開啟開發人員模式, 「載入未封裝項目」, 載入發行壓縮檔中的 `extension/dist` (若是原始碼 checkout, 請先建置, 再載入 `build/extension/chrome-mv3`)。然後重新啟動瀏覽器。

   上架頁面存在之後, [cli.md 的指標表](./cli.md#doctor---fix--uninstall-原生訊息註冊) 會說明哪些瀏覽器會依據步驟 3 留下的指標提供擴充功能, 以及哪些情況下不會寫入任何指標。

5. **配對。** 執行 `genkan pair`: 它會要求你在終端機輸入一段確認, 產生主機金鑰, 並印出金鑰的指紋。在擴充功能的選項頁面核准該指紋; 在固定完成之前, 擴充功能在每個平台上都拒絕執行任何動作 ([cli.md](./cli.md#登記-pair--revoke--enclave-status) 負責說明這項程序與其旗標)。

6. **登記 (建議)。** 在選項頁面的身分區段登記你瀏覽器的認證器。機器上的第一次登記是首次使用即信任; 之後每一次都需要一個已登記認證器的觸碰。

7. **連接你的 MCP 用戶端** 到執行檔的絕對路徑。以 Claude Code 為例:

   ```sh
   claude mcp add genkan -- /absolute/path/to/genkan
   ```

   對於 Claude Desktop 與其他以 JSON 設定的用戶端, 請新增一個 `mcpServers` 項目, 指向同一個絕對路徑, 不帶任何引數。

完整的命令參考 (配對、受信任用戶端、撤銷、緊急開關 (kill switch)、稽核日誌) 在 [cli.md](./cli.md)。

## 你應該看到什麼

在已註冊 Chrome 且 MCP 伺服器正在執行 (由你的 MCP 用戶端啟動) 時的 `genkan doctor`, 在一個全新的 macOS 家目錄上擷取:

```text
$ genkan doctor
genkan doctor - v0.1.0
platform:        macos/aarch64
lock file:       /tmp/quickstart-home/Library/Application Support/genkan/run.lock
  present: yes
  endpoint: /tmp/quickstart-home/Library/Application Support/genkan/run.sock
  pid:     77652
  secret:  <redacted, 32 chars>
mcp server:      reachable (socket connect OK)
kill switch:     off (bridge activity permitted)
policy baseline: none yet (pre-cutover; the extension keeps enforcing its deny baseline until `genkan policy set` or the options page's Security policy section signs a baseline)
native manifests: (host id com.vivswan.genkan.host)
  chrome    detected      user    manifest ok         /tmp/quickstart-home/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vivswan.genkan.host.json
                          system  manifest missing    /Library/Google/Chrome/NativeMessagingHosts/com.vivswan.genkan.host.json
                          user    pointer  ok         /tmp/quickstart-home/Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
  chromium  not detected  user    manifest missing    /tmp/quickstart-home/Library/Application Support/Chromium/NativeMessagingHosts/com.vivswan.genkan.host.json
                          system  manifest missing    /Library/Application Support/Chromium/NativeMessagingHosts/com.vivswan.genkan.host.json
                          user    pointer  missing    /tmp/quickstart-home/Library/Application Support/Chromium/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
  brave     not detected  user    manifest ok         /tmp/quickstart-home/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vivswan.genkan.host.json (reads chrome's)
                          system  manifest missing    /Library/Google/Chrome/NativeMessagingHosts/com.vivswan.genkan.host.json (reads chrome's)
                          user    pointer  missing    /tmp/quickstart-home/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
  edge      not detected  user    manifest missing    /tmp/quickstart-home/Library/Application Support/Microsoft Edge/NativeMessagingHosts/com.vivswan.genkan.host.json
                          system  manifest missing    /Library/Microsoft/Edge/NativeMessagingHosts/com.vivswan.genkan.host.json
                          user    pointer  missing    /tmp/quickstart-home/Library/Application Support/Microsoft Edge/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
  vivaldi   not detected  user    manifest missing    /tmp/quickstart-home/Library/Application Support/Vivaldi/NativeMessagingHosts/com.vivswan.genkan.host.json
                          system  manifest missing    /Library/Application Support/Vivaldi/NativeMessagingHosts/com.vivswan.genkan.host.json
                          user    pointer  missing    /tmp/quickstart-home/Library/Application Support/Vivaldi/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
  opera     not detected  user    manifest missing    /tmp/quickstart-home/Library/Application Support/com.operasoftware.Opera/NativeMessagingHosts/com.vivswan.genkan.host.json
                          system  manifest missing    /Library/Google/Chrome/NativeMessagingHosts/com.vivswan.genkan.host.json (reads chrome's)
                          user    pointer  missing    /tmp/quickstart-home/Library/Application Support/com.operasoftware.Opera/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json

note: the checks above cover the MCP server + native-host bridge only.
They do NOT confirm the Chrome extension is loaded and connected. Verify
that via the Genkan toolbar icon (approve the target site) and
the extension's Service Worker console at chrome://extensions.

OK
```

- 擷取在 `/tmp/quickstart-home` 這個暫存家目錄中執行。在你的機器上, 以它開頭的路徑預設會位於你自己的家目錄下, 而 Linux 與 Windows 會印出各自的位置。
- 擴充功能的工具列圖示顯示連線狀態。
- 對新網站的第一次工具呼叫會在瀏覽器中跳出核准提示; 高風險動作會跳出確認視窗。

## 建議的強化

配對 (步驟 5) 在每個平台上都是必要的。登記 (步驟 6) 是建議項: 沒有已登記認證器的瀏覽器會在確認視窗中回答在場請求 (例如解除緊急開關), 而不是以觸碰回答。另有一項選用的程序可綁定 MCP 用戶端這一側:

- `genkan pair-client` 建立受信任用戶端允許清單。清單一旦存在, 只有程式碼身分經過證明且獲你核准的 MCP 用戶端才會獲得服務, 而且任何介面都能隨時撤銷其中一個。

三者都在 [cli.md](./cli.md) 與[安全頁面](./security.md)中有說明。

## 解除安裝

`genkan uninstall` 精確移除 `--fix` 寫入的內容 ([cli.md](./cli.md#doctor---fix--uninstall-原生訊息註冊) 說明移除什麼, 以及拒絕移除什麼)。接著依照安裝時的方式移除執行檔:

| 管道 | 移除執行檔 |
| --- | --- |
| macOS `.pkg` | `sudo rm /usr/local/bin/genkan && sudo pkgutil --forget io.github.vivswan.genkan` |
| Windows `.msi` | 設定、應用程式、Genkan、解除安裝 (它會替你執行 `genkan uninstall`) |
| Linux `.deb` | `sudo dpkg -r genkan` |
| Homebrew | `brew uninstall genkan` |
| 壓縮檔 | 刪除解壓出來的目錄 |

配對狀態是分開的: `genkan revoke --all` 刪除主機金鑰並忘記每一個瀏覽器與受信任用戶端, 擴充功能的選項頁面則清除其固定的金鑰。

步驟 6 登記的認證器保存在 `trust.json` 中。`revoke <browser>` 忘記在該瀏覽器標籤下登記的認證器; 在共用一份未設定標籤的資訊清單時, 這個標籤對每個瀏覽器都是 `default`, 如 [cli.md](./cli.md#登記-pair--revoke--enclave-status) 所說明。`revoke --all` 從頭來過, 而 `doctor` 無法讀取的 `trust.json` 是[疑難排解頁面](./troubleshooting.md#doctor-顯示緊急開關狀態或信任記錄無法讀取)的情況。
