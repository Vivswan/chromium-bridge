# 事件回應手冊

> 一套適合單一維護者專案的務實安全事件處理流程, 與 [SECURITY.md](../../../.github/SECURITY.md) 中的回報管道, 以及 [threat-model.md](threat-model.md) 中的資產與信任邊界一致。信任邊界在 [trust-boundaries.md](trust-boundaries.md) 中逐一列舉; 工具風險見 [tool-risk-matrix.md](tool-risk-matrix.md)。

## 什麼算安全事件

[threat-model.md](threat-model.md) 所保護的資產遭到入侵, 或疑似遭到入侵。例如:

- 在**未授權的來源 (origin)** 上執行了頁面操作, 繞過了網站允許清單或確認提示;
- Cookie / 儲存空間 / 頁面內容 / eval 回傳值未經遮罩就外洩;
- 橋接 socket 接受了**未經驗證**的本機對等端, 或主機資訊清單的 `allowed_origins` 遭到修改;
- `page_eval` 或其確認通道被濫用, 造成不可逆的後果。

不算事件: 任何需要先入侵機器才能達成的事, 或使用者自己設定的惡意 MCP 用戶端 (依設計受信任, 見 [SECURITY.md 的範圍一節](../../../.github/SECURITY.md#scope))。

## 回報管道

**不要為安全問題開公開的 issue。** 請使用 GitHub 的 **[Report a vulnerability](https://github.com/Vivswan/chromium-bridge/security/advisories/new)** (Security -> Advisories) 私下回報, 內容包含: 攻擊者能做什麼 (影響) 以及跨越了哪條信任邊界、重現步驟或 PoC, 以及受影響的版本/提交。作為一個小型專案, 我們會在幾天內確認收到, 並請求一段合理的修復期。

## 分級處理

收到回報後, 用以下問題為它分級 (這些問題對應 [tool-risk-matrix.md](tool-risk-matrix.md) 中的影響範圍):

1. **跨越了哪條信任邊界?** (見 [trust-boundaries.md](trust-boundaries.md) 中的邊界 1 到 4; 邊界 4, 也就是頁面邊界, 最為關鍵。)
2. **能讀取或更改什麼?** 是否觸及憑證 (Cookie/儲存空間中的權杖)? 是否有寫入或不可逆的後果?
3. **前提條件有多強?** 是否需要使用者已授權某個來源、已安裝擴充功能, 或需要一個同 UID 的本機程序?
4. **可否重現?** 是否有 PoC?

據此決定「立即緩解」還是「排程修復」。憑證外洩以及允許清單/確認提示的繞過是最高優先。

## 立即緩解 (使用者端, 無需改程式碼)

在修補程式就緒之前, 使用者可以自行採取以下行動來**縮小影響範圍**:

- **停用單一工具**: 用 `chromium-bridge policy restrict --disabled-tools <list>` 把受影響的工具加入主機策略的 `disabledTools` (這個旗標陳述的是完整的、以逗號分隔的停用清單, 所以要保留其中已有的工具; 這次寫入是免費的, 不會有 Touch ID 提示, 因為限制只會移除能力 - 見 [cli.md](../cli.md#主機持有的策略-policy))。主機的分派閘門隨後會在任何橋接流量之前, 以 [`ERROR_SPECS`](../../../src/packages/core/src/error.rs) 中穩定的 `TOOL_DISABLED` 代碼拒絕該操作, 擴充功能也會在自己的邊界上強制執行推送下來的策略。像 `page_eval` 這樣的高風險工具應該最先停用。之後重新啟用它屬於放寬, 需要付出一次已簽章、以 Touch ID 為閘門的策略寫入 - 這是刻意的設計。
- **撤銷允許清單 / 關閉所有網站**: 在選項頁面 / 彈出視窗中移除受影響來源的授權, 並確認 `allowAllSites` 已關閉。移除授權的同時也會撤銷該來源的主機權限。
- **緊急開關 (kill switch)**: 在 `chrome://extensions` 停用或移除 Chromium Bridge 擴充功能。擴充功能一停止, 原生訊息主機的 stdin 就會收到 EOF 並結束, 橋接隨之切斷。必要時也結束 MCP 用戶端的工作階段, 讓 MCP 伺服器程序結束 (用 `doctor` 確認 not reachable, 見 [CLI 頁面](../cli.md#doctor--status-唯讀自我檢查))。
- **解除安裝主機資訊清單**: 刪除原生訊息主機資訊清單後, Chrome 就無法再啟動主機 (路徑見 [architecture.md 第 4.3 節](../architecture.md#43-磁碟上的產物))。

> 緩解順序, 由輕到重: 先停用高風險工具, 再撤銷允許清單, 再停用擴充功能, 最後解除安裝資訊清單。

## 修復與驗證

- 找出被跨越的**不變量** (見 [trust-boundaries.md 中的「不得倒退的不變量」](trust-boundaries.md#不得倒退的不變量))。
- 修復必須通過**安全相關變更**閘門: 填寫[安全變更檢查清單](../../../.github/ISSUE_TEMPLATE/security-change.yml), 更新 [tool-risk-matrix.md](tool-risk-matrix.md), 若信任邊界有變, 也要更新 [threat-model.md](threat-model.md)。
- **負向安全測試是必要的**, 用來證明邊界再次守住 (只新增正向案例並不足夠), 依據 [SECURITY.md 的審查標準](../../../.github/SECURITY.md#security-relevant-changes-review-bar)。

## 發行與揭露

- 依 [release.md](../release.md) 為修復打標籤並發行; 1.0 之前只支援最新的發行版 (見 [SECURITY.md 的支援版本一節](../../../.github/SECURITY.md#supported-versions)), 安全修復以新的 patch/minor 版本出貨。
- 透過 GitHub Security Advisory 協調揭露: 在公開之前給回報者一段合理的修復期, 發行後在 advisory 中致謝回報者, 並說明受影響的版本與緩解措施。
- 在 [CHANGELOG.md](../../../CHANGELOG.md) 中記錄這次修復。

## 相關頁面

- 回報管道與審查標準: [SECURITY.md](../../../.github/SECURITY.md)。
- 資產、參與者、非目標: [threat-model.md](threat-model.md)。
- 邊界與不變量: [trust-boundaries.md](trust-boundaries.md)。
- 症狀與復原: [troubleshooting.md](../troubleshooting.md)。
