# 疑難排解

每一個條目都從唯讀的自我檢查開始, 它不會改變任何東西:

```sh
genkan doctor    # or: genkan status
```

`doctor` 每一列的含義見 [CLI 頁面](cli.md#doctor--status-唯讀自我檢查)。

## doctor 顯示「server not reachable」

- **你看到:** `doctor` 從鎖定檔讀到了一個端點, 但對它的連線後即斷開探測失敗了。
- **這表示:** 沒有任何 MCP 用戶端工作階段在執行, 所以沒有東西在監聽; 或者先前的中介 (broker) 留下了過期的鎖定檔。
- **怎麼做:** 在你的 MCP 用戶端中開啟或重新連線一個工作階段。下一個伺服器實例會在啟動時取代過期的鎖定檔; `doctor` 永遠不會清理它、終止程序或重新啟動伺服器 ([CLI 頁面說明了這個探測](cli.md#如何解讀server-not-reachable))。

## doctor 顯示某個註冊缺失或過期

- **你看到:** 某個瀏覽器的註冊列顯示 `missing` 或 `stale`。
- **這表示:** 該瀏覽器無法啟動原生訊息主機: 沒有為它註冊任何東西, 或者已註冊的內容已損壞, 該列會說明是哪一種 (懸空的啟動路徑, 或在 Windows 上缺少登錄機碼)。
- **怎麼做:** 執行 `genkan doctor --fix`, 然後重新啟動瀏覽器 ([CLI 頁面上的註冊](cli.md#doctor---fix--uninstall-原生訊息註冊))。

## doctor 顯示緊急開關狀態或信任記錄無法讀取

- **你看到:** `kill state unreadable - failing closed`, 或者 `kill` 與 `unkill` 拒絕寫入; `doctor` 以非零狀態結束。
- **這表示:** 執行階段目錄中的 `trust.json`, 也就是緊急開關 (kill switch) 的閂鎖與受信任用戶端允許清單, 無法讀取: JSON 損壞、未知欄位或權限不正確。每個強制執行點都以失敗即關閉的方式讀取它, 所以工具呼叫會被以 `BRIDGE_KILLED` 拒絕, 瀏覽器連線會被切斷, 新的實例也拒絕啟動。
- **怎麼做:** 依下列順序手動復原。從一個你無法讀取的狀態解除緊急開關會變成失敗即開放, 而悄悄重建這個檔案會掩蓋竄改, 所以這兩件事都不會替你自動完成。

1. 執行 `genkan doctor` 確認狀態並找到執行階段目錄。
2. 動手之前先檢視 `trust.json`。一個你無法解釋的損壞 (沒有寫入中途的當機, 也沒有磁碟事故) 是可能的竄改跡象: 先閱讀[事件回應](security/incident-response.md)。
3. 刪除 `trust.json`。這是對用戶端程式 (harness) 信任的原廠重設, 回到會大聲記錄日誌的未登記引導狀態; 已配對的用戶端也會隨之消失。
4. 重新配對每個受信任用戶端 (`genkan pair-client`), 如果你之前啟用了緊急開關, 也要重新啟用。擴充功能登記時固定的金鑰不受影響: 主機金鑰從來不在這份記錄裡。

## doctor 回報 `policy baseline: none yet`

- **你看到:** `policy baseline:` 列顯示 `none yet`。
- **這表示:** 這是切換前的健康狀態。尚未寫入任何已簽章的基準, 所以擴充功能強制執行拒絕基準: 每項能力授予都關閉, 每項確認都開啟。這一列永遠不會改變 `doctor` 的結束碼。
- **怎麼做:** 什麼都不用做, 除非你想要授予: `genkan policy set` 或選項頁面的「安全策略」區段會寫入第一個基準 ([CLI 頁面上的策略](cli.md#主機持有的策略-policy))。已存在的儲存區會回報它的修訂版本、`signed` 或 `unsigned`, 以及是否有未簽章的限制覆蓋層生效; 主機只回報是否已簽章, 永遠不會宣稱「valid」, 因為只有擴充功能能用它自己固定的金鑰驗證簽章。

## doctor 回報 `policy baseline: UNREADABLE`

- **你看到:** `UNREADABLE (...) - failing closed`, 且 `doctor` 以非零狀態結束。
- **這表示:** 策略儲存區存在, 但無法讀取或解析。每個使用方都失敗即關閉: 主機的分派閘門拒絕每個工具, 擴充功能則繼續強制執行它儲存的有效策略或拒絕基準。
- **怎麼做:** 先檢視儲存區, 再做其他任何事。它永遠不會被替你換成預設值, 因為預設值可能比你收緊過的策略更寬鬆, 而一個由垃圾資料構成的放寬手段根本不算放寬手段。

## 原生訊息主機每隔幾分鐘就結束

- **你看到:** 主機程序結束並重新啟動, 擴充功能的連線狀態大約每五分鐘閃爍一次。
- **這表示:** Chromium 大約每五分鐘強制重啟 MV3 Service Worker, 這會關閉原生訊息連接埠; 主機在 stdin 上收到 EOF 後結束, 擴充功能在兩秒後重新連線 ([重新連線流程](architecture.md#52-原生訊息主機重新連線))。
- **怎麼做:** 什麼都不用做。在正在關閉的連線上進行中的呼叫會以 `CONNECTION_LOST` 失敗; 下一次呼叫會重新解析作用中的分頁, 而工作階段的記錄保存在 MCP 伺服器而非 Service Worker 中, 所以重新連線不需要重新配對。

## 擴充功能與主機版本不一致

主機持有的策略訊框是在沒有提升橋接協定版本的情況下加入的: 它們是附加式的且由主機處理, 所以兩種版本偏差的行為如下表所述。哪個號碼在何時變動, 見[發行頁面](release.md#版本)。

| 偏差 | 行為 |
| --- | --- |
| 新擴充功能, 舊主機 | 主機永遠不會推送策略訊框, 所以擴充功能也永遠不會送出 (舊主機會把未知訊框歸類為可轉送, 而伺服器的嚴格解析會把瀏覽器這一側的連線拆除)。擴充功能停留在切換前狀態, 並強制執行拒絕基準。 |
| 舊擴充功能, 新主機 | 舊擴充功能會丟棄不熟悉的 `policy_current` 推送 (有測試固定此行為), 並保留它的本機設定; 新主機仍在分派時套用自己的策略, 所以合併後的強制執行永遠不會比單獨的舊擴充功能更寬鬆。 |
| 新擴充功能, 缺少選項頁面訊框的主機 | 選項頁面會按需送出 `registration_status`、`registration_repair`、`policy_restrict`、`audit_read` 與 `doctor_report`, 所以「永不先開口」規則不涵蓋它們: 中介的嚴格解析會把瀏覽器這一側的連線拆除。在首次發行前已接受此情況, 因為沒有任何已出貨的主機缺少它們; 之後要涵蓋它, 需要延後的交握宣告主機的控制訊框, 並讓擴充功能依此決定是否送出。 |

## 在 WSL 下執行

Chrome、它啟動的原生訊息主機, 以及 MCP 伺服器必須全部屬於同一個作業系統。依 Chrome 執行的位置選擇模式。

### WSL 用戶端搭配 Windows Chrome

常見的設定: MCP 用戶端在 WSL 中執行, 日常使用的瀏覽器是 Windows Chrome。不需要 Linux 安裝, WSL 中也不需要 Chrome。

1. 在 Windows 上解壓縮 Windows 發行壓縮檔 (或從原始碼建置), 在那裡執行 `genkan.exe doctor --fix`, 並把壓縮檔中的 `extension/dist` 載入 Windows Chrome。
2. 在 WSL 的 MCP 設定中, 直接執行 Windows 的 `.exe`。WSL interop 會把它當作 Windows 程序啟動, 所以它與 Windows Chrome 共用登錄檔、`%LOCALAPPDATA%` 鎖定檔以及原生訊息主機。

對 Codex 而言, 在 `~/.codex/config.toml` 中:

```toml
[mcp_servers.genkan]
command = "/mnt/c/Users/YOUR_WINDOWS_USER/AppData/Local/genkan/genkan.exe"
args = []
```

把 `YOUR_WINDOWS_USER` 替換掉並確認路徑存在; 這個範例假設執行檔位於 `%LOCALAPPDATA%\genkan`。

### WSLg 搭配 Linux Chrome 或 Chromium

當瀏覽器本身在 WSLg 內執行時, 直接在 Linux 中原生安裝: 把 Linux 的 `genkan` 執行檔放在 WSL 檔案系統中的穩定路徑並註冊它。

```sh
./genkan doctor --fix                    # every detected browser
./genkan doctor --fix --browser chrome   # Google Chrome only
./genkan doctor --fix --browser chromium # Chromium only
```

| 項目 | 位置 |
| --- | --- |
| 資訊清單 | `~/.config/google-chrome/NativeMessagingHosts/com.vivswan.genkan.host.json`, `~/.config/chromium/NativeMessagingHosts/com.vivswan.genkan.host.json` |
| 鎖定檔 | `$XDG_RUNTIME_DIR/genkan/run.lock`; 沒有 `XDG_RUNTIME_DIR` 時, 則是 `$XDG_CACHE_HOME/genkan/run.lock` 或 `~/.cache/genkan/run.lock` |

在 Linux 瀏覽器的 `chrome://extensions` 載入發行壓縮檔中的 `extension/dist` (或建置好的 `build/extension/chrome-mv3`), 然後把 MCP 用戶端指向 Linux 執行檔 (同樣以 Codex 為例, 在 `~/.codex/config.toml` 中):

```toml
[mcp_servers.genkan]
command = "/home/YOUR_WSL_USER/.local/lib/genkan/genkan"
args = []
```

### 不要混用兩套系統

- **Windows Chrome** 無法讀取 WSL 內的 Linux 原生訊息資訊清單, 也無法啟動 Linux ELF 執行檔。
- **WSLg 中的 Linux Chrome** 不會讀取 Windows 登錄檔, 也無法使用 Windows Chrome 的註冊。
- **從 WSL 啟動 Windows `.exe` 不算混用:** 該程序仍是 Windows 程序, 這正是第一種模式可行的原因。

當連線在 WSL 下失敗時, 確認 Chrome、原生訊息主機與 MCP 伺服器都落在同一側, 然後檢查鎖定檔: Windows 上是 `%LOCALAPPDATA%\genkan\run.lock`, Linux 上是前述的 XDG 路徑。

## 當機後留下了鎖定檔

- **你看到:** 在某個中介異常結束後, `doctor` 回報一個端點無法連線的鎖定檔。
- **這表示:** 鎖定檔 (執行階段目錄中的 `run.lock`) 比它的中介活得更久。不存在對存活擁有者的強制接管: 第二個實例若發現存活的中介, 會改為附接到它。
- **怎麼做:** 啟動一個用戶端工作階段。下一個伺服器實例會在啟動時探測過期的端點並取代鎖定檔; `doctor` 只會讀取它。
