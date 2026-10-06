# CLI 與疑難排解: chromium-bridge

> 本文件是 `chromium-bridge` 執行檔各子命令的參考, 也涵蓋常見的疑難排解路徑。CLI 是核心之上的管理介面。元件與程序邊界見 [architecture.md](./architecture.md); 磁碟上的路徑見 [architecture.md 第 4.3 節](./architecture.md#43-磁碟上的產物)。

## 子命令總覽

`chromium-bridge` 是單一執行檔, 依子命令分派:

| 呼叫方式 | 模式 | 說明 |
|------|------|------|
| `chromium-bridge` (不帶引數) | MCP 伺服器 | 預設模式, 由 MCP 用戶端啟動。第一個執行個體成為中介 (broker); 之後的執行個體接入它。 |
| `chromium-bridge --native-host [--label <browser>]` | 原生訊息主機 | 輕量橋接, 由瀏覽器透過主機資訊清單啟動。絕不手動呼叫。 |
| `chromium-bridge doctor [--json]` (別名 `status`) | 唯讀診斷 | 環境與連線自我檢查; 不改變任何東西。`--json` 以單一帶版本的物件印出報告。 |
| `chromium-bridge doctor --list` | 唯讀診斷 | 每個已知瀏覽器與範圍一行: 偵測與註冊狀態。 |
| `chromium-bridge doctor --paths` | 唯讀診斷 | 印出此環境解析出的執行階段目錄與鎖定檔路徑, 兩者都不建立。 |
| `chromium-bridge doctor --fix` | 修復 / 安裝 | 為你的帳戶將此執行檔註冊 (或重新註冊) 為原生訊息主機。doctor 唯一會修改狀態的形式。 |
| `chromium-bridge doctor --fix --system` | 修復 / 安裝 (root) | 同樣的動作, 但是機器層級: 寫入每個帳戶的瀏覽器都會讀取的、由 root 擁有的目錄。`.deb` 安裝後執行的就是它。 |
| `chromium-bridge uninstall [--system]` | 移除 | 只移除本專案在該範圍寫入的註冊, 別無其他。 |
| `chromium-bridge pair [--reset] [--file-store]` | 登記 | 在終端機輸入確認之後, 產生擴充功能所固定的主機金鑰; 金鑰存放在作業系統的憑證存放區, 或在使用 `--file-store` 時存放在一個 0600 檔案中。 |
| `chromium-bridge revoke <browser>` | 登記 | 忘記該瀏覽器已登記的認證器; 不需要證明, 該瀏覽器可從其選項頁面重新登記。 |
| `chromium-bridge revoke --all` | 登記 | 從頭來過: 刪除主機金鑰與已簽署的策略基準, 忘記每一個瀏覽器與每一個受信任用戶端。不帶引數的 `revoke` 會被拒絕並顯示用法。 |
| `chromium-bridge enclave-status [--json]` | 唯讀 | 印出主機金鑰的狀態、所在位置及其指紋。 |
| `chromium-bridge pair-client --name <label> (--this-parent \| --hash <hex> \| --signer <id>)` | 受信任用戶端 | 將一個 MCP 用戶端程式 (harness) 加入受信任用戶端允許清單; 需在場驗證。 |
| `chromium-bridge revoke-client --name <label>` | 受信任用戶端 | 移除一個用戶端; 執行中的中介會立即將其斷開。 |
| `chromium-bridge list-clients` | 唯讀 | 印出受信任用戶端允許清單。 |
| `chromium-bridge kill` | 緊急開關 (kill switch) | 啟用全域緊急開關: 停止所有橋接活動, 直到明確解除為止。 |
| `chromium-bridge unkill` | 緊急開關 | 在證明使用者在場之後解除緊急開關: 在互動式終端機輸入一段確認 (以管線輸入的 stdin 會被拒絕)。 |
| `chromium-bridge policy show [--json]` | 唯讀 | 印出主機持有的策略狀態與有效策略。 |
| `chromium-bridge policy set <field flags> [--json]` | 策略 (授予通道) | 在輸入終端機確認之後產生一份全新的已簽章策略基準。只接受簽章; 沒有主機金鑰時一開始就拒絕。 |
| `chromium-bridge policy restrict <field flags>` | 策略 (自由通道) | 套用未簽章的限制覆蓋層; 不提示, 因為它只能移除能力。 |
| `chromium-bridge policy history [--json]` | 唯讀 | 印出已被取代的修訂環。 |
| `chromium-bridge policy rollback --revision <n> [--json]` | 策略 | 將過去某個修訂的有效策略重新推導為一次全新寫入, 絕非重放。 |
| `chromium-bridge audit [--limit <n>]` | 唯讀稽核 | 印出磁碟上的稽核日誌, 最舊的在前 (預設: 最後 200 筆記錄)。 |
| `chromium-bridge lang [show \| set <value>]` | 顯示語言 | 讀取或設定選項頁面顯示的語言; 單獨的 `lang` 等同於 `show`。 |
| `chromium-bridge --help` | 說明 | 用法資訊。 |

選項頁面提供同樣的動作。依設計只在終端機上: `uninstall` (見下文), 以及 `--system` 與 `--manifest-dir` 兩種修復形式。選項頁面的稽核檢視只有預設的那一頁; 更長的日誌用 `audit --limit <n>`。網站允許清單、全部允許與分頁分組留在選項頁面上。它們是瀏覽器本機的擴充功能儲存空間 (見[隱私權政策](./privacy-policy.md)), 沒有任何子命令讀寫它們。

## doctor / status (唯讀自我檢查)

`doctor` (`status` 是等價的別名) 是唯讀子命令: 它不綁定 socket, 不寫入鎖定檔, 也不產生任何子程序。它只探測目前環境並印出結論, 用來回答「為什麼我連不上」這個問題。

它會回報:

- **版本 / 平台**: 執行檔版本 (以 Cargo 為準) 與執行中的平台。
- **鎖定檔**: 執行階段目錄中是否存在橋接鎖定檔, 以及其中記錄的端點與 pid。
- **伺服器可達性**: 對我們自己的橋接 socket 做一次被動的連上即斷開的探測 (不送出任何位元組), 回報 `reachable` / `not reachable`。
- **緊急開關**: 已啟用、已清除或無法讀取。開關啟用期間或其狀態無法讀取時, `doctor` 以非零結束碼結束。
- **原生訊息主機註冊**: 對每個已知瀏覽器 (chrome、chromium、brave、edge、vivaldi、opera), 回報它在這台機器上看起來是否存在, 以及它對 `com.vivswan.chromium_bridge.host` 在 `user` 與 `system` 兩個範圍各自的註冊狀態: `ok`、`missing`、`stale` (是我們的, 但其啟動路徑已失效) 或不是我們的。
- **判定遵循瀏覽器的查找順序**: 有每使用者條目時取它, 沒有時才取系統條目。診斷結果來自 `--fix` 修復時所用的同一個解析器, 所以 doctor 回報的正是 `--fix` 會產生的結果。

選項頁面的「主機註冊」區段顯示同樣的幾列 (鎖定檔、伺服器、緊急開關、策略基準、判定), 措辭來自主機; 其身分區段顯示主機金鑰存放在哪裡, 與 `enclave-status` 印出的一致。

`doctor --json` 在 stdout 上以單一 JSON 物件印出同一份報告, 結束碼相同。先檢查它的 `v` 欄位, 遇到更新的值就拒絕, 然後才讀取其他內容 (失敗即關閉); 此執行檔的每一份 `--json` 報告都適用這條規則。

### 如何解讀「server not reachable」

「Server not reachable」表示 `doctor` 從鎖定檔讀到了端點, 但探測失敗。常見原因:

1. **沒有 MCP 伺服器在執行。** 伺服器由 MCP 用戶端 (例如 Claude Code) 在其工作階段內啟動, 所以沒有用戶端工作階段時就沒有任何東西在監聽, 「not reachable」是預期狀態。請確認用戶端已設定 chromium-bridge 伺服器, 且有一個工作階段開啟中。
2. **過期的鎖定檔。** 先前的中介異常結束, 留下了鎖定檔。下一個伺服器執行個體會在啟動時偵測並取代過期的鎖定檔; 只要開啟新的用戶端工作階段即可。

> `doctor` 只探測, 不修復。它不會終止程序、刪除鎖定檔或重新啟動伺服器。看到「not reachable」時, 請從 MCP 用戶端那一側重新建立工作階段, 而不是手動介入程序。

如果你使用的瀏覽器的註冊缺失或過期, 該瀏覽器就無法啟動原生訊息主機。執行 `chromium-bridge doctor --fix`, 然後重新啟動瀏覽器。

## doctor --fix / uninstall (原生訊息註冊)

下面的 CLI 透過單一引擎 (`registration.rs`) 從終端機註冊原生訊息主機。它只需要主機執行檔本身, 在桌面、無頭機器與 CI 上都一樣。

`chromium-bridge doctor --fix` 將你用來呼叫它的那個執行檔 (重新) 註冊為原生訊息主機: 對每個目標瀏覽器, 它把 `com.vivswan.chromium_bridge.host.json` 資訊清單寫到該瀏覽器尋找它的位置, 並在旁邊寫入擴充功能指標 (見下文)。

- **冪等的重新註冊:** 在全新機器上 `--fix` 同時也是首次註冊; 移動執行檔之後, 它會更新過期的註冊。
- **不建置、不下載、不複製任何東西:** 資訊清單指向此執行檔自身解析出的路徑, 在 macOS/Linux 上經由一個小型的每瀏覽器包裝指令碼。
- **該包裝指令碼** 內建了 `--native-host`, 因為 Chrome 的資訊清單格式沒有 `args` 欄位; 當只有一個瀏覽器會啟動該資訊清單時再加上 `--label <browser>` (`run-host-<browser>.sh`); 多個瀏覽器共讀的資訊清單得到不帶標籤的 `run-host.sh` (規則由 `registration.rs` 中的 `Target` 負責)。
- **會覆寫另一個工具以我們的主機 id 寫下的資訊清單** (報告會指名它原本啟動的是什麼), 拒絕無法讀取的資訊清單, 也拒絕外來的指標; `uninstall` 會留下外來的資訊清單。

選擇瀏覽器:

```text
chromium-bridge doctor --fix                      # every browser detected for this user
chromium-bridge doctor --fix --browser chrome,brave
chromium-bridge doctor --fix --all                # every known browser, detected or not
chromium-bridge doctor --fix --manifest-dir DIR   # exact NativeMessagingHosts dir
                                                  # (absolute; repeatable), for a Chromium
                                                  # variant we do not know by name
sudo chromium-bridge doctor --fix --system        # machine-wide, for every account (root only)
chromium-bridge doctor --list                     # read-only: detection + registration state
```

範圍屬於命令: `--system` 寫入每個帳戶的瀏覽器都會讀取的目錄 (`/etc/opt/chrome/native-messaging-hosts`、`/Library/Google/Chrome/NativeMessagingHosts`、`HKLM`), 需要 root; 不帶它時 root shell 會被拒絕, 因為 root 沒有自己的瀏覽器。

Opera, 以及 macOS 與 Linux 上的 Brave, 讀取的是 Chrome 的系統目錄而非自己的目錄, 而 macOS 上的 Brave 還會讀取 Chrome 的每使用者目錄。對它們而言, `doctor --fix` 在該範圍註冊 Chrome 的資訊清單, `doctor` 則在它們那幾列上把它回報為 Chrome 的。

- **共用的資訊清單不帶標籤:** 任一瀏覽器都可能啟動它, 所以它的連線占用中介的預設槽位, 與 `--manifest-dir` 註冊的連線一樣。
- **每個瀏覽器各自的指標, 在 macOS 上每使用者一份:** Chrome 與 Brave 在那裡各自保有自己的擴充功能指標, 所以兩者都會提示啟用擴充功能 (機器層級時, macOS 為所有瀏覽器只有一個指標目錄)。

已知的瀏覽器鍵: `chrome`、`chromium`、`brave`、`edge`、`vivaldi`、`opera`。「已偵測到」表示就一次廉價的本機檢查所能判斷, 該瀏覽器確實已安裝:

| 平台 | 偵測檢查 | 意義 |
| --- | --- | --- |
| macOS | `/Applications` 或 `~/Applications` 下的應用程式套件 | 只剩下一個每使用者設定目錄並不算數 (已解除安裝的瀏覽器會永遠留著這些目錄, 有些開發工具也會建立它們); 剛安裝、尚未首次執行的瀏覽器則算數 |
| Linux | 每使用者設定目錄; 帶 `--system` 時為廠商套件的安裝目錄 (`/opt/google/chrome`、`/usr/lib/chromium` 之類) | 每使用者的修復註冊此帳戶執行過的瀏覽器; `.deb` 的安裝後步驟以 root 身分註冊為所有帳戶安裝的瀏覽器 |
| Windows | 每使用者設定檔目錄 | 在那裡能取得的最佳廉價訊號 |

- **macOS 上的非標準安裝** 會被判為「未偵測到」; 仍可用 `--browser <key>` 或 `--manifest-dir` 明確註冊。
- **不帶參數的 `doctor` 只計入已偵測到的瀏覽器,** 所以非標準安裝即使有健康的明確註冊, 下方的摘要仍會低於「OK」, 儘管橋接可以運作 - 各瀏覽器那幾行才說明真實情況。
- **什麼都沒偵測到:** `--fix` 拒絕執行並要求明確選擇, 而不是猜測, 並以結束碼 3 而非 1 結束, 讓安裝程式能分辨「還沒有瀏覽器」與失敗。
- **選項頁面的「主機註冊」區段**以同樣的兩種方式為此帳戶修復: 每個偵測到的瀏覽器, 或從其所在列指名的一個瀏覽器。`--manifest-dir` 與 `--system` 留在終端機: 目錄要輸入, root 要持有, 而選項頁面兩者都沒有。

`chromium-bridge uninstall` 在一個範圍內精確反轉本專案 (透過 `--fix`) 註冊的內容: 各瀏覽器的資訊清單、擴充功能指標與包裝指令碼。你註冊時傳過的任何 `--manifest-dir` 都要再傳一次, 機器層級的註冊則 (以 root 身分) 再傳 `--system`。

刪除資訊清單或指標之前, 它會驗證內容是我們的 (我們的主機 id 與描述標記; 單憑 Web Store 更新 url)。其他任何內容, 或任何無法讀取的內容, 都會被回報並原地保留, 作為警告而非失敗, 這樣套件的移除才能完成; 旁邊屬於我們的其他產物仍會移除, 只有屬於我們卻無法移除的東西才會讓命令失敗。

它絕不碰此執行檔或你的瀏覽器。瀏覽器會在下次啟動時卸除它從指標安裝的擴充功能; 未封裝的擴充功能則由你自行移除。

`uninstall` 依設計沒有選項頁面上的對應物。請求它的那個訊框, 會刪除啟動了正在回應它的主機的那份資訊清單。

擴充功能指標, 位於每份資訊清單旁邊:

| 作業系統 | `--fix` 寫到哪裡 | 瀏覽器如何處理它 |
| --- | --- | --- |
| macOS | `<user data dir>/External Extensions/<extension id>.json`, 指名 Web Store; 帶 `--system` 時為所有瀏覽器寫入 `/Library/Application Support/Google/Chrome/External Extensions/` (Chromium 唯一的機器層級目錄) | 下次啟動時詢問「Enable Chromium Bridge?」 |
| Windows | `HKCU\<vendor>\Extensions\<extension id>`, 值為 `update_url`; 帶 `--system` 時為 `HKLM` | 同樣的提示 |
| Linux | 不寫; `doctor` 印出 `pointer n/a` | 它會從指標無聲地安裝, 而威脅模型拒絕這種行為: 請自行從 Web Store 加入擴充功能 |

Chrome 自己的位置來自其文件。其他廠商的位置是從它們存放資訊清單所用的同一個使用者資料根目錄與登錄根目錄推導而來, Edge 也被指向 Chrome 線上應用程式商店 (一項殘餘風險: 在那些瀏覽器上尚未驗證)。

指標只提供資訊給 `doctor`, 絕不決定其結論: 橋接用未封裝的擴充功能、沒有指標也能運作。它會為 `--fix` 指名或偵測到的瀏覽器寫入; `--manifest-dir` 註冊則沒有指標, 因為無法指名其瀏覽器。

商店上的上架頁面是否已存在, 以及在它存在之前該載入什麼, 屬於 [quickstart.md](./quickstart.md#cli-macoslinuxwindows) 第 4 步的範圍。

平台注意事項:

- **Linux AppImage / 暫存路徑**: 指向 AppImage 的 FUSE 掛載點 (或任何暫存目錄) 的註冊, 會在該路徑消失時失效。`--fix` 偵測到這種情況時會警告。請先把執行檔複製到穩定位置, 例如 `~/.local/lib/chromium-bridge/chromium-bridge`, 再從那裡執行 `doctor --fix`。
- **Windows**: 註冊是每個瀏覽器一個 `HKCU` 登錄機碼, 加上 `%LOCALAPPDATA%\chromium-bridge` 下的一份資訊清單檔案 (帶 `--system` 時為 `HKLM` 與 `%ProgramFiles%\chromium-bridge`)。這段程式碼可以編譯, 且仿照已退役的 `install.ps1` 指令碼的做法, 但尚未在真實的 Windows 機器上驗證; 在那之前請把 Windows 註冊視為盡力而為。Windows 上的瀏覽器偵測 (每使用者設定檔目錄; Opera 在漫遊設定檔下) 也有同樣的但書。

## 登記: pair / revoke / enclave-status

主機金鑰程序給擴充功能一個可供固定的主機身分:

- `chromium-bridge pair` 要求你在終端機輸入一段確認 (以管線輸入的 stdin 在任何提示出現之前就被拒絕), 產生一把 P-256 主機金鑰, 把它存放在作業系統的憑證存放區 (鑰匙圈、認證管理員或 Secret Service), 並印出金鑰的 SHA-256 指紋。把這個指紋與擴充功能登記畫面顯示的指紋比對; 不一致表示兩者之間夾了別的東西。
- `chromium-bridge pair --file-store` 改為把金鑰存放在執行階段目錄中的一個 0600 檔案, 供沒有可用憑證存放區的機器使用。這個選擇是明確的: 存放區失敗會被回報, 絕不會悄悄改寫到檔案。
- `chromium-bridge pair --reset` 先要求確認, 然後移除先前的金鑰 (不論哪個存放區持有它) 並產生一把新的; 擴充功能必須重新固定。瀏覽器登記與用戶端配對維持不變。
- 當憑證存放區沒有回應時, `--file-store` 的重置會繼續進行, 並警告存放區中可能仍留有一筆項目。等存放區恢復回應後再執行一次 `pair --reset`; `revoke --all` 也可以, 但它還會忘記每一個瀏覽器與用戶端。
- `chromium-bridge enclave-status [--json]` 以唯讀方式回報目前狀態: 是否存在金鑰、哪個存放區持有它, 以及它的指紋。

瀏覽器自身動作 (解除緊急開關、登記第二個瀏覽器) 的使用者在場證明, 是在瀏覽器認證器上的一次 WebAuthn 觸碰, 由主機驗證。選項頁面的身分區段登記該認證器, 其緊急開關面板以這次觸碰應答主機的在場請求。

忘記操作沒有額外門檻, 因為它只移除能力:

- `chromium-bridge revoke <browser>` 忘記在該標籤下登記的每一個認證器。該瀏覽器的動作回退到確認視窗, 直到它從自己的選項頁面重新登記; 當它是最後一個已登記的瀏覽器時, 下一次登記重新成為首次登記。
- 標籤是瀏覽器主機資訊清單的 `--label` (`brave`、`chrome`); 共用一份未設定標籤的資訊清單的所有瀏覽器 (Windows、共用的 Chrome 資訊清單) 都使用 `default`, 所以 `revoke default` 會把它們全部忘記。未知的標籤會被拒絕, 並列出記錄中持有的標籤。
- 選項頁面為它自己的瀏覽器提供同樣的動作: 身分區段認證器區塊中的「忘記這個瀏覽器」。它作用於該主機的標籤, 所以共用一份資訊清單的瀏覽器會被一起忘記。
- `chromium-bridge revoke --all` 一步從頭來過: 刪除主機金鑰, 策略記錄隨之消失 (已簽署的基準與任何限制覆蓋層), 忘記每一個瀏覽器, 撤銷每一個受信任用戶端, 所以已配對的機器在 `pair-client` 再次信任某個用戶端之前不准入任何用戶端。緊急開關不受影響; 用 `unkill` 解除它。
- `revoke --all` 之後, 已連線的擴充功能無論如何都失敗即關閉: 當憑證存放區確認金鑰已消失且記錄寫入落地時, 透過撤銷推送; 否則在它下一次金鑰驗證時。`revoke <browser>` 不碰主機金鑰與固定。
- 不帶引數的 `chromium-bridge revoke` 兩者都沒有指名, 會被拒絕並顯示用法。

CLI 從不發出那個提示: 它自己的授予 (`pair`、`pair-client`、`unkill`、`policy set`) 由在真實終端機上輸入的片語確認。

## 受信任用戶端: pair-client / revoke-client / list-clients

預設 (未登記) 情況下, 任何啟動伺服器的程序都會被服務, 而且每次啟動都以 ERROR 層級記錄這種開放狀態。建立受信任用戶端允許清單即可關閉它:

```text
chromium-bridge pair-client --name claude-code --this-parent
chromium-bridge pair-client --name codex --hash <sha256-hex>
chromium-bridge pair-client --name claude-desktop --signer <signer-id>
chromium-bridge list-clients
chromium-bridge revoke-client --name codex
```

- `--this-parent` 量測啟動這次 CLI 呼叫的程序 (請在你想信任的用戶端內部執行它)。僅限 Unix: 在 Windows 上, 伺服器以其 stdin 管道的建立者來識別用戶端程式, 而主控台命令沒有這樣的建立者, 所以請改用 `--hash` 或 `--signer` 配對, 其值取自伺服器在未登記時啟動所記錄的日誌。
- 授權以經證明的錨點為準, 絕不以 `--name` 標籤為準; 標籤只用於日誌與撤銷。各平台量測的內容見[信任邊界頁面](security/trust-boundaries.md#邊界-1-mcp-用戶端---rust-mcp-伺服器-stdio-json-rpc-20)。
- 雜湊錨點會在用戶端更新時改變; 以相同名稱重新執行 `pair-client` 即可取代該項目 (重新配對路徑)。
- 新增用戶端是一種能力授予, 所以需在場驗證: 在互動式終端機輸入一段確認, 以管線輸入的 stdin 會被拒絕。撤銷則刻意設計為無阻力; 執行中的中介會斷開被撤銷的用戶端, 並拒絕其重新接入。

允許清單一旦存在, 任何不符合的對象都失敗即關閉, 包括無法量測的身分與無法讀取的允許清單。Windows 的量測方式見 [SECURITY.md](../../.github/SECURITY.md#platform-support)。

## 緊急開關 (kill / unkill)

`chromium-bridge kill` 是緊急煞車: 一道命令, 同時讓每個 MCP 用戶端停止操作每個已連線的瀏覽器。

- 即時的瀏覽器連線在約一秒內被切斷, 新連線被拒絕。進行中的工具呼叫以 `CONNECTION_LOST` 快速失敗。
- 之後來自每個已接入用戶端的每一次工具呼叫, 都以穩定的 `BRIDGE_KILLED` 錯誤碼拒絕。用戶端保持連線, 以便向你顯示拒絕訊息, 而不是無聲地死掉。
- 狀態會持久化 (寫在鎖定檔旁邊的 `trust.json` 中), 在重新啟動、重新連線與重開機後都保留。
- 擴充功能的選項頁面會顯示該狀態; 從任何介面都能啟用開關。從選項頁面解除時, 主機會以一次在場請求應答, 頁面以 WebAuthn 觸碰 (或只在沒有已登記憑證的瀏覽器上提供的軟體確認) 完成它; 網頁看不到也碰不到其中任何東西。

沒有任何東西會自行解除開關。解除在兩種介面上都要求證明使用者在場:

| 介面 | 一次解除要求的證明 |
| --- | --- |
| CLI 上的 `chromium-bridge unkill` | 在真實終端機上輸入的明確確認; 以管線輸入的 stdin 會被直接拒絕, 所以沒有任何指令碼或背景程式能透過 CLI 悄悄重新開啟橋接 |
| 擴充功能 | 來自該瀏覽器下已登記憑證的一次 WebAuthn 斷言; 只有在瀏覽器沒有已登記憑證時才用瀏覽器的確認視窗 |

每次解除嘗試都會記入稽核: 被授予的解除附上做出決定的驗證路徑 (`auth=tty`、`auth=webauthn:<fingerprint>`、`auth=confirm_window`), 在在場閘門被拒絕的附上在場錯誤, 在場驗證通過後因記錄無法寫入而被拒絕的則兩者都附上。

如果任一命令回報信任記錄無法讀取, 見[復原步驟](./troubleshooting.md#doctor-顯示緊急開關狀態或信任記錄無法讀取); 在那之前, 一切持續失敗即關閉。

`doctor` 會印出緊急開關狀態, 並在開關啟用期間或其狀態無法讀取時以非零結束碼結束。

## 主機持有的策略 (policy)

`chromium-bridge policy` 是主機持有的策略介面。相關概念 (已簽章的基準、未簽章的限制覆蓋層、擴充功能側的棘輪) 見 [architecture.md 第 11.3 節](./architecture.md#113-主機持有的策略與語言同步); doctor 的 `policy baseline:` 那一列如何解讀, 見[疑難排解頁面](./troubleshooting.md#doctor-回報-policy-baseline-none-yet)。

```text
chromium-bridge policy show [--json]              # read-only: store state + effective policy
chromium-bridge policy set <field flags> [--json] # GRANT lane: sign a fresh baseline (terminal confirmation)
chromium-bridge policy restrict <field flags>     # FREE lane: unsigned restriction overlay
chromium-bridge policy history [--json]           # read-only: superseded revisions
chromium-bridge policy rollback --revision <n> [--json]
```

**欄位旗標。** `set` 與 `restrict` 共用同一組旗標, 每個策略欄位一個, 寫法是其 camelCase 線路名稱的 kebab-case 形式: `--cdp-mode`、`--file-upload`、`--handle-dialog`、`--page-eval`、`--confirm-high-risk-click`、`--confirm-page-eval`、`--presence-confirm`、`--confirm-tab-close`、`--warn-precise-snapshot`、`--eval-mask`、`--host-reverify-ms`、`--confirm-grace-ms`、`--click-toast-timeout-ms`、`--eval-toast-timeout-ms` 與 `--disabled-tools`。

| 旗標種類 | 值 |
| --- | --- |
| 布林旗標 | `on` 或 `off` |
| 四個 `*-ms` 旗標 | 非負整數 |
| `--disabled-tools` | 以逗號分隔的工具清單, 陳述的是完整的停用集合 (新增一個工具時, 要保留已在其中的工具) |

- **`--disabled-tools ""` 是空集合:** 空項目會被丟棄, 所以這是完全清除, 在 `set` 通道上屬於放寬, 和其他放寬一樣需要觸碰。
- **名稱含逗號或前後有空白的工具** 無法忠實地經由逗號連接的傳輸格式傳遞: 每個寫入接縫都直接拒絕這種名稱, 而不是簽章一份被無聲改動的清單。
- **解析是嚴格的:** 未知的子命令、多餘的引數、重複的旗標或格式錯誤的值都是錯誤, 絕不猜測; 而且 `set`/`restrict` 至少需要一個欄位旗標。

**兩條通道刻意不對稱。**

- **`policy set` 是授予通道:** 它把編輯內容疊加在目前的基準上 (未碰到的欄位沿用基準值, 絕不是有效值), 把碰到的欄位集合嵌入文件, 並在輸入的終端機確認通過後, 用主機金鑰對該文件的精確位元組簽章。
- **沒有主機金鑰就沒有授予:** 在沒有執行過 `pair` 的機器上, CLI 一開始就拒絕, 任何提示都不會出現, 因此不會存在擴充功能的固定指紋無法驗證的基準。
- **`policy restrict` 是自由通道:** 不提示、不簽章, 而接縫的方向檢查拒絕任何會放寬有效策略的編輯, 所以一次腳本化或偽造的限制, 最糟也只是對你自己的橋接造成阻斷服務。

**回滾絕不重放。** `policy rollback --revision <n>` 重新推導該修訂的有效策略, 與目前的有效策略做差異比對, 並把差異作為一次全新寫入套用。

- **只收緊的回滾** 走免提示的自由限制通道。
- **放寬任何內容的回滾** 就是一次新的終端機確認與簽章, 和其他任何授予完全一樣。
- **舊的已簽章產物絕不寫回:** 較低的修訂必須持續無法通過擴充功能的棘輪, 這是防重放特性, 不是限制。

**`--json` 契約。** `show`、`history`、`set` 與 `rollback` 都接受 `--json`, 它把文字敘述換成 stdout 上一份帶版本的報告 (寫入通道在拒絕時則是一個帶版本的錯誤物件)。先檢查 `v` 欄位, 遇到更新的值就拒絕, 然後才讀取其他內容 (失敗即關閉)。

每次策略轉換都會記入稽核, 附上介面, 授予時還附上授權該簽章的在場路徑 (`auth=tty`)。

## 顯示語言 (lang)

擴充功能的顯示語言是由主機保存的共用狀態 (執行階段目錄中的 `lang.json`), 並推送給每一個已連線的瀏覽器, 所以一次選擇會到達它們全部。選項頁面在其頁首用「顯示語言」選擇器設定它; 終端機上的對應物是:

```text
chromium-bridge lang              # the current value (same as `lang show`)
chromium-bridge lang set zh_TW    # one of: auto, en, zh_CN, zh_TW
```

- **語言不是策略:** 不簽署、不棘輪, 也無法影響任何安全決策, 這正是它在兩種介面上都不需要確認的原因。
- **清單之外的值會被拒絕**, 在 argv 與選項頁面的訊框上一樣, 先前的值維持不變; 設定為目前的值什麼都不改變, 也不推送任何東西。
- **已連線的瀏覽器在主機的下一次推送時切換** (在其輪詢間隔內); 離線的瀏覽器在下次連線時採用該值。

## 日誌與稽核 (BB_LOG / BB_LOG_FORMAT)

兩種模式的診斷輸出都送到 **stderr** (stdout 承載協定訊框)。兩個環境變數控制輸出:

| 變數 | 值 | 效果 |
|------|------|------|
| `BB_LOG` | `error` \| `warn` \| `info` (預設) \| `debug` | 日誌門檻。`info` 及以上會印出稽核行; 設為 `warn`/`error` 可關閉稽核輸出。 |
| `BB_LOG_FORMAT` | `text` (預設) \| `json` | 稽核行的格式。`json` 每行輸出一個 JSON 物件, 便於機器收集。 |

**稽核事件 (stderr)**: 每個安全決定都輸出一行稽核: 工具呼叫 (帶 `req`、`tool`、`outcome`, 出錯時還有來自 [`ERROR_SPECS`](../../src/packages/core/src/error.rs) 的穩定 `code`, 以及 `dur_ms`)、用戶端程式的准入與拒絕、用戶端配對與撤銷、主機金鑰撤銷、緊急開關的狀態轉換、WebAuthn 登記與在場裁決、策略寫入, 以及擴充功能的確認與登記決定 (經由連接埠轉送)。

同樣的事件會以嚴格的 JSON 記錄附加到一份持久、有大小上限的 `audit.log` (0600, 位於執行階段目錄中鎖定檔旁邊), 它比寫入它的那些短命程序活得更久。每筆記錄在 `event_kind` 中指名其事件; stderr 的 JSON 形式把記錄包在 `"kind":"audit"` 封套裡, 所以收集器以 `kind` 為鍵, 從 `event_kind` 讀取事件。

- **不記錄任何敏感內容:** 沒有頁面文字、cookie 或儲存空間的值、eval 的回傳值或表單填入值; 遮罩在擴充功能那一側進行 ([信任邊界](./security/trust-boundaries.md))。
- **關聯:** 一行工具呼叫帶有其請求 id (`req`) 以及該呼叫被路由到的瀏覽器連線的世代 (`conn`); 每次重新接入時世代遞增, 所以一次重新連線會開始一個新的 `conn`。
- **兩種只存在於擴充功能本機的事件種類絕不會進入 `audit.log`:** `policy_refused` 與 `policy_compromised` 依設計留在擴充功能自己的稽核環中, 不在轉送允許清單內; 主機則把每次策略轉換記錄為 `policy_write`。

```text
# BB_LOG_FORMAT default (text)
[AUDIT] 2026-10-03 23:12:44.302Z  kill_engage     surface=cli outcome=ok
# BB_LOG_FORMAT=json
{"kind":"audit","v":1,"ts_ms":1791069164310,"event_kind":"kill_engage","surface":"cli","outcome":"ok"}
```

用唯讀子命令讀取持久的稽核日誌:

```text
$ chromium-bridge audit --limit 20
2026-07-17 19:04:11.201Z  kill_engage     surface=cli outcome=ok
2026-07-17 19:04:12.480Z  tool_call       tool=tab_list outcome=error code=BRIDGE_KILLED dur_ms=0
2026-07-17 19:05:02.913Z  kill_release    surface=cli outcome=ok
```

讀取器無法解析的記錄會顯示為 `UNRECOGNIZED RECORD` 並計數, 絕不猜測; `dropped=n` 欄位標記因寫入失敗 (例如磁碟已滿) 而遺失的記錄。記錄過程絕不阻塞或導致操作失敗: 稽核日誌觀察決定, 不把關決定。

選項頁面讀取同一份日誌: 其「近期活動」區段在這個瀏覽器的本機決策環旁邊列出主機日誌 (上文的預設頁, 每行都是主機自己的措辭)。

錯誤碼與錯誤分類見 [architecture.md 第 11.1 節](./architecture.md#111-錯誤分類-error_specs)。

## 相關頁面

- 安裝與首次使用: [quickstart.md](./quickstart.md)。
- 連線生命週期與斷線/重新連線語意: [architecture.md 第 5.2 節](./architecture.md#52-原生訊息主機重新連線)。
- 錯誤分類 (`NOT_CONNECTED` / 斷線類別): [architecture.md 第 11.1 節](./architecture.md#111-錯誤分類-error_specs)。
