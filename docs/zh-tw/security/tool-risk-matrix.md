# 工具風險矩陣

橋接公開的每個工具, 連同其風險等級、讀取與變更什麼、是否觸及憑證、所需的 Chrome 權限, 以及使用者如何受到保護。這是安全審查的參考: 新增或修改工具就意味著更新此表, 而[審查標準](../../../.github/SECURITY.md#security-relevant-changes-review-bar)說明該變更還要附帶什麼。

風險等級: **低** (唯讀, 無敏感資料)、**中** (讀取頁面內容或導覽)、**高** (寫入頁面, 或讀取憑證)、**嚴重** (任意程式碼或最大影響範圍)。

所列的保護措施都是預設值。確認閘門是主機持有的策略欄位 (`confirmHighRiskClick`、`confirmTabClose`、`confirmPageEval`、`presenceConfirm`、`confirmGraceMs`), 以 `genkan policy` 編輯 (`set` 會簽署一次授予, `restrict` 則無需簽署); 擴充功能的選項頁面只能收緊它們。放寬其中任何一項都是明確且經簽署的選擇, 其殘餘風險列在[預設值表格](../../../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe)中。

| 工具 | 風險 | 讀取 | 寫入 / 效果 | 憑證? | Chrome 權限 | 使用者保護 |
|------|------|-------|-----------------|--------------|-------------|-----------------|
| `list_browsers` | 低 | 已連線的瀏覽器標籤 + 開啟分頁數 | - | 否 | `tabs` (透過對每個瀏覽器路由一次 `tab_list`) | 由 MCP 伺服器回應; 不存取頁面 |
| `tab_list` | 低 | 分頁標題/URL | - | 否 | `tabs` | 不需允許清單 (僅中繼資料) |
| `tab_focus` | 低 | - | 啟用一個分頁 | 否 | `tabs` | - |
| `tab_open` | 中 | - | 開啟一個 URL (導覽) | 否 | `tabs` | 來源受允許清單閘控 |
| `tab_close` | 高 | 分頁標題/URL | **關閉一個分頁** (資料遺失) | 否 | `tabs` | 擴充功能視窗確認 |
| `page_snapshot` | 低 | 可互動元素 (a11y) | - | 否 | `scripting` | 允許清單閘控; 注入內容 |
| `page_click` | 高 [1] | ref 所指的元素 | 點擊 (可能送出/導覽) | 否 | `scripting` | 送出/連結需擴充功能視窗確認 |
| `page_fill` | 高 | - | 在欄位中輸入 | 可能 (輸入到密碼欄位) | `scripting` | 回顯中的密碼值經遮罩 |
| `page_text` | 中 | 可見的頁面文字 | - | 經遮罩 | `scripting` | 密碼與長數字串經遮罩 |
| `page_screenshot` | 中 | 視埠像素 | - | 可能 (螢幕上的任何內容) | `tabs` | - |
| `page_scroll` | 低 | 捲動位置 | 捲動 | 否 | `scripting` | - |
| `page_wait_for` | 低 | 選擇器/文字是否存在 | - | 否 | `scripting` | - |
| `page_navigate` | 中 | - | 在作用中分頁載入一個 http(s) URL | 否 | `tabs` | 以目的地來源做允許清單閘控 |
| `page_back` | 低 | - | 讓作用中分頁在歷史記錄中後退一步 | 否 | `tabs` | 以目前來源做允許清單閘控, 而非目的地 ([殘餘風險](trust-boundaries.md#邊界-4-擴充功能---網頁-chrome-api--內容指令碼--dom)) |
| `page_forward` | 低 | - | 讓作用中分頁在歷史記錄中前進一步 | 否 | `tabs` | 以目前來源做允許清單閘控, 而非目的地 (同一項殘餘風險) |
| `page_reload` | 低 | - | 重新載入作用中分頁 | 否 | `tabs` | 以目前來源做允許清單閘控 |
| `page_press` | 高 | - | 向頁面送出合成按鍵或組合鍵 (可能送出/導覽) | 否 | `scripting` | 擴充功能視窗確認, 每次呼叫 |
| `page_hover` | 低 | - | 把指標移到某個元素上 | 否 | `scripting` | 允許清單閘控 |
| `page_select` | 高 | - | 在 `<select>` 中選擇一個選項 | 否 | `scripting` | 擴充功能視窗確認, 每次呼叫 |
| `console_get` | 中 | 近期的主控台輸出, 含網路錯誤 | - | 經遮罩 | `debugger` | 允許清單閘控; 輸出經遮罩; 「偵錯中」橫幅 |
| `page_handle_dialog` | 高 | - | **接受或關閉** JS 對話框 (alert/confirm/prompt) | 否 | `debugger` | **預設關閉** (需選擇啟用); 允許清單閘控; 「偵錯中」橫幅 |
| `page_upload` | **嚴重** | 指名本機檔案的位元組 | **把本機檔案附加**到檔案輸入欄位 | 可能 (任何可讀取的檔案) | `debugger` | **預設關閉** (需選擇啟用); 允許清單閘控; 每次呼叫都在擴充功能視窗確認並顯示確切路徑; 確認之後重新檢查來源, 並把附加綁定到那時解析出的文件節點; 見殘餘風險 |
| `page_eval` | **嚴重** | 頁面能讀的一切 | 在頁面中執行**任意 JS** | 是 (可讀取權杖/cookie) | `scripting` (host) | 在主機持有的策略下**預設關閉** (`pageEvalEnabled`, 以 `policy set` 授予); **每次呼叫**都在擴充功能視窗確認並顯示完整程式碼; 結果經遮罩 |
| `page_snapshot_precise` | 中 | 權威的無障礙樹 (CDP) | - | 否 | `debugger` | 預先警示的 toast; 「偵錯中」橫幅短暫閃現 |
| `cookie_get` | 高 | cookie, 含 **httpOnly** | - (唯讀) | **是** | `cookies` | 限於允許清單範圍; 值經遮罩; 刻意不提供 `cookie_set` |
| `storage_get` | 高 | local/sessionStorage | - (唯讀) | **是** (權杖) | `scripting` | 同源; 值**一律**經遮罩 |

[1] `page_click` 對一般元素為中風險; 當目標是送出按鈕或會導覽的連結時為**高**風險 (那些會觸發確認視窗)。

## 橫切保護措施

- **瀏覽器路由從不猜測:** 有多個瀏覽器連線時, 工具呼叫必須透過其 `browser` 引數指名一個, 否則失敗 (`BROWSER_AMBIGUOUS`); 未知的標籤也失敗 (`BROWSER_NOT_FOUND`)。每個瀏覽器的連線都獨立認證, 回應了其他瀏覽器請求的連線會被丟棄。
- **允許清單:** 頁面層級的工具只在使用者核准的來源上執行 (逐網站提示加 `chrome.permissions.request`)。`allowAllSites` 是明確的選擇啟用。
- **遮罩:** `page_text`、`cookie_get`、`storage_get` 與 `page_eval` 的輸出都會經過遮罩 (JWT、長十六進位串、長數字串、類權杖字串)。`storage_get` 的遮罩無法由使用者關閉。
- **確認寬限期:** 在[每分頁鍵](../../../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe)下重複的送出或連結點擊在 `confirmGraceMs` 內跳過提示; `page_eval` 從不跳過, 所以先前的核准絕不會讓後續無關的程式碼執行。預設值由同一節負責。
- **設計上唯讀:** 沒有 `cookie_set` 或 `storage_set` (寫入 httpOnly cookie 有工作階段固定攻擊的風險)。
- **CDP 模式 (選擇啟用, 預設關閉):** `cdpMode` 策略欄位把每個頁面層級工具改經 `chrome.debugger` 在頁面的 MAIN world 中執行, 而非透過內容指令碼。任何工具的契約、權限、確認或遮罩都不會改變; 上述保護仍然適用。
  - **它的兩個代價:** 它繞過頁面 CSP, 所以 `page_eval` 能在嚴格 CSP 的網站上執行; 並且會對分頁保持持續的偵錯工具附加, 所以只要它開著, 「Started debugging this browser」橫幅就會一直顯示。

## 新增或修改工具時

更新此表, 並遵循[審查標準](../../../.github/SECURITY.md#security-relevant-changes-review-bar)。任何擴大工具影響範圍的變更 (新權限、新的敏感讀取、新的寫入、較弱的確認、更寬的遮罩繞過) 也要更新[信任邊界帳冊](trust-boundaries.md), 並經過標記為 security 的審查。
