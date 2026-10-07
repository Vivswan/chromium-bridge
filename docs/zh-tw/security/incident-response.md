# 事件回應手冊

疑似的邊界突破如何回報、分級、遏制、修復與揭露, 按單一維護者專案的規模裁剪。資產與邊界在[安全頁面](../security.md); 修復所要恢復的不變量在[帳冊](trust-boundaries.md#不得倒退的不變量)。

## 什麼算安全事件

[安全頁面](../security.md#利害所在-以及誰受信任)所保護的資產遭到入侵, 或疑似遭到入侵。例如:

- 在未授權的來源 (origin) 上執行了頁面操作, 繞過了網站允許清單或確認提示;
- Cookie、儲存空間、頁面內容或 eval 回傳值未經遮罩就外洩;
- 橋接 socket 接受了未經驗證的本機對端, 或主機資訊清單的 `allowed_origins` 遭到修改;
- 沒有在場證明就解除了緊急開關, 或放寬了策略;
- `page_eval` 或其確認通道被濫用, 造成不可逆的後果。

不算事件: 任何需要先入侵機器才能達成的事, 或使用者自己配對的惡意 MCP 用戶端 (依設計受信任, 見[範圍](../../../.github/SECURITY.md#scope))。

## 回報管道

**不要為安全問題開公開的 issue。** 私下的管道、一份有用的回報應包含什麼, 以及可以期待什麼回應, 見[安全政策](../../../.github/SECURITY.md#reporting-a-vulnerability)。

## 分級處理

用四個問題為回報分級; 它們對應[工具風險矩陣](tool-risk-matrix.md)中的影響範圍:

1. **跨越了哪條邊界?** [帳冊](trust-boundaries.md)中的邊界 1 到 4; 邊界 4, 也就是頁面邊界, 最為關鍵。
2. **能讀取或更改什麼?** 是否觸及憑證 (Cookie 或儲存空間中的權杖)? 是否有寫入或不可逆的後果?
3. **前提條件有多強?** 是否需要使用者已授權某個來源、已安裝擴充功能, 或需要一個同 UID 的本機程序?
4. **可否重現?** 是否有概念驗證?

答案決定「立即緩解」還是「排程修復」。憑證外洩以及允許清單或確認提示的繞過是最高優先。

## 立即緩解 (使用者端, 無需改程式碼)

在修補程式就緒之前, 使用者可以自行縮小影響範圍:

1. **啟用緊急開關:** `chromium-bridge kill`, 或擴充功能的選項頁面。每一次工具呼叫都被拒絕, 每一條瀏覽器連線都在大約一秒內被切斷; 命令與其解除由 [CLI 頁面](../cli.md#緊急開關-kill--unkill)負責。
2. **停用單一工具:** `chromium-bridge policy restrict --disabled-tools <list>` 把它加入主機策略的 `disabledTools`。這個旗標陳述的是完整的、以逗號分隔的停用清單, 所以要保留其中已有的工具。這次寫入是免費的 (沒有在場提示), 因為限制只會移除能力。
   - 主機隨後會在任何橋接流量之前, 以 [`ERROR_SPECS`](../../../src/packages/core/src/error.rs) 中穩定的 `TOOL_DISABLED` 代碼拒絕該工具, 擴充功能也會在自己的邊界上強制執行推送下來的策略。
   - 先停用 `page_eval` 這樣的高風險工具。之後重新啟用它屬於放寬, 需要付出一次在終端機確認之後的已簽章策略寫入, 這是刻意的設計 ([CLI 頁面](../cli.md#主機持有的策略-policy))。
3. **撤銷允許清單, 或關閉所有網站:** 在選項頁面或彈出視窗中移除受影響來源的授權, 並確認 `allowAllSites` 已關閉。移除授權的同時也會撤銷該來源的主機權限。
4. **停止擴充功能:** 在 `chrome://extensions` 停用或移除它。原生訊息主機的 stdin 收到 EOF 並結束, 橋接隨之切斷; 也結束 MCP 用戶端的工作階段, 讓 MCP 伺服器結束, 並用 `doctor` 確認 ([CLI 頁面](../cli.md#doctor--status-唯讀自我檢查))。
5. **解除安裝主機資訊清單:** `chromium-bridge uninstall` 移除原生訊息註冊, 之後 Chrome 就無法再啟動主機 ([CLI 頁面](../cli.md#doctor---fix--uninstall-原生訊息註冊))。

## 修復與驗證

- 找出被跨越的那條[不變量](trust-boundaries.md#不得倒退的不變量)。
- 修復必須通過[審查標準](../../../.github/SECURITY.md#security-relevant-changes-review-bar): [安全變更檢查清單](../../../.github/ISSUE_TEMPLATE/security-change.yml)、[工具風險矩陣](tool-risk-matrix.md), 以及若邊界有變, [帳冊](trust-boundaries.md)。
- 必須有一個負向安全測試來證明邊界再次守住; 只有正向案例並不足夠。

## 發行與揭露

- 依[發行頁面](../release.md)為修復打標籤並發行。1.0 之前只支援最新的發行版 ([支援的版本](../../../.github/SECURITY.md#supported-versions)), 安全修復以新的 patch 或 minor 版本出貨。
- 透過 GitHub Security Advisory 協調揭露: 在公開之前給回報者一段合理的修復期; 發行後在 advisory 中致謝回報者, 並說明受影響的版本與緩解措施。
- 修復透過其 Conventional Commit 主旨進入發行說明; 變更日誌如何產生由[發行頁面](../release.md)負責。
