# Chromium Bridge

Chromium Bridge 讓 MCP 用戶端透過瀏覽器擴充功能與原生訊息主機, 操作你已經登入的 Chromium 瀏覽器, 不需要偵錯埠。程式碼是唯一的事實來源: 當某個頁面描述一項行為時, 擁有該行為的檔案才是權威。安全頁面說明這座橋接承諾什麼、止於何處; 其餘頁面說明如何使用、執行與修改它。

## 我想要...

| 目標 | 閱讀 |
|---|---|
| 安裝執行檔與擴充功能, 並執行第一次工具呼叫 | [快速入門: CLI](quickstart.md#cli-macoslinuxwindows) |
| 檢查安裝是否健康, 或解讀「server not reachable」 | [CLI: doctor 與 status](cli.md#doctor--status-唯讀自我檢查) |
| 向瀏覽器註冊原生訊息主機, 或移除註冊 | [CLI: doctor --fix 與 uninstall](cli.md#doctor---fix--uninstall-原生訊息註冊) |
| 准入一個 MCP 用戶端, 或撤銷一個 | [CLI: 受信任用戶端](cli.md#受信任用戶端-pair-client--revoke-client--list-clients) |
| 立刻停止一切, 稍後再解除停止 | [CLI: 緊急開關 (kill switch)](cli.md#緊急開關-kill--unkill) |
| 變更工具被允許做的事 | [CLI: 主機持有的策略](cli.md#主機持有的策略-policy) |
| 閱讀日誌與稽核日誌 | [CLI: 日誌與稽核](cli.md#日誌與稽核-bb_log--bb_log_format) |
| 解讀一列出乎意料的 `doctor` 輸出, 或復原無法讀取的緊急開關記錄 | [疑難排解](troubleshooting.md) |
| 從 WSL 使用這座橋接 | [疑難排解: 在 WSL 下執行](troubleshooting.md#在-wsl-下執行) |
| 知道這座橋接承諾攻擊者做不到什麼, 以及承諾止於何處 | [安全: 標準線](security.md#一句話說清標準線) |
| 查看每個工具能觸及什麼、會觸發哪種確認 | [工具風險矩陣](security/tool-risk-matrix.md) |
| 回報安全問題 | [事件回應: 回報](security/incident-response.md#回報管道) |
| 在修改某項安全決策前, 先理解當初為何這樣決定 | [安全設計依據](security/rationale.md) |
| 知道擴充功能收集與儲存什麼 | [隱私權政策](privacy-policy.md) |
| 查看各程序如何連接, 以及每一跳之間傳遞什麼 | [架構: 總覽](architecture.md#1-架構總覽) |
| 找到由 Rust 核心擁有、並由 `moon run gen` 產生為 TypeScript 的跨程序契約 (工具目錄、錯誤分類、能力、協定版本、身分、線路封包) | [架構: 協定邊界契約](architecture.md#11-協定邊界契約-錯誤分類與交握) |
| 修改與安全相關的東西 | [審查標準](../../.github/SECURITY.md) |
| 設定工具鏈並執行閘門 | [開發: moon](development.md#moon-標準的命令介面) |
| 對隔離的 Chrome 執行瀏覽器測試套件, 絕不對你自己的瀏覽器執行 | [測試](../../tests/README.md) |
| 新增一個工具 | [貢獻: 新增工具](../../CONTRIBUTING.md#adding-a-tool) |
| 發行一個版本 | [發行](release.md#觸發-合併發行-pr) |
| 知道哪種變更會推動哪個版本號 | [發行: 版本](release.md#版本) |
| 權衡是否將擴充功能發布到 Chrome 線上應用程式商店 | [發行: Chrome 線上應用程式商店](release.md#發布到-chrome-線上應用程式商店) |

## 頁面一覽

### 使用

1. [快速入門](quickstart.md): 安裝、首次使用、建議的強化、解除安裝。
2. [CLI](cli.md): doctor、註冊、登記、受信任用戶端、緊急開關、策略、日誌與稽核, 以及各自對應的疑難排解。
3. [疑難排解](troubleshooting.md): 逐一症狀說明, 從出乎意料的 `doctor` 輸出列, 到緊急開關記錄的復原、版本不一致, 以及兩種 WSL 模式。
4. [隱私權政策](privacy-policy.md): 擴充功能可以存取什麼、儲存什麼, 以及絕不會送出什麼。

### 安全

5. [安全](security.md): 一句話的承諾、利害所在與誰受信任、四個跳點及各由什麼把守、你要確認什麼、止於何處, 按作業系統分述。
6. [信任邊界](security/trust-boundaries.md): 審查者的帳冊, 按跳點分述: 機制細節、每一項已接受的殘餘風險、策略帳冊、不變量。
7. [工具風險矩陣](security/tool-risk-matrix.md): 每個工具的影響範圍與保護措施。
8. [事件回應](security/incident-response.md): 回報、分級處理、緩解、揭露。
9. [安全設計依據](security/rationale.md): 每項決策為何這樣做, 以及否決了什麼。
10. [審查標準](../../.github/SECURITY.md): 需要額外審查的部分、失敗即安全的預設值, 以及在做安全相關變更前該讀什麼。

### 參考

11. [架構](architecture.md): 元件、協定、資料流、安全模型、關鍵限制、技術選型, 以及 Rust 核心產生的契約。

### 貢獻

12. [開發](development.md): 工具鏈、目錄配置、moon 工作、測試、容器、模糊測試。
13. [發行](release.md): release-please 管線、附帶總和檢查碼與來源證明的預先建置壓縮檔、SBOM、何時推動哪個版本, 以及 Chrome 線上應用程式商店的決定。
14. [CONTRIBUTING](../../CONTRIBUTING.md): 開發流程, 從分支、提交與同步規則到壓縮合併。
15. [測試](../../tests/README.md): 各測試套件, 以及瀏覽器測試只對隔離的 Chrome 執行、絕不對你日常使用的瀏覽器執行的規則。
