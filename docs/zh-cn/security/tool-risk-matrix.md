# 工具风险矩阵

本页列出桥接暴露的每一个工具, 包括其风险级别、读取和更改什么、是否触及凭据、需要哪项 Chrome 权限, 以及用户如何受到保护。这是安全审查的参考: 新增或修改工具意味着更新此表, 而[评审标准](../../../.github/SECURITY.md#security-relevant-changes-review-bar)说明该变更还要附带什么。

风险级别: **低** (只读, 无敏感数据)、**中** (读取页面内容或导航)、**高** (写入页面, 或读取凭据)、**严重** (任意代码或最大影响范围)。

所列保护措施均为默认值。确认门禁是主机持有的策略字段 (`confirmHighRiskClick`、`confirmTabClose`、`confirmPageEval`、`presenceConfirm`、`confirmGraceMs`), 用 `genkan policy` 编辑 (`set` 会签署一次授予, `restrict` 无需签名); 扩展的选项页只能收紧它们。放宽任何一项都是显式的、经签名的选择, 其残余风险列在[默认值表](../../../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe)中。

| 工具 | 风险 | 读取 | 写入 / 效果 | 凭据? | Chrome 权限 | 用户保护 |
|------|------|-------|-----------------|--------------|-------------|-----------------|
| `list_browsers` | 低 | 已连接浏览器的标识 + 各自打开的标签页数 | - | 否 | `tabs` (通过按浏览器路由的 `tab_list`) | 由 MCP 服务器应答; 不访问页面 |
| `tab_list` | 低 | 标签页标题/URL | - | 否 | `tabs` | 不要求白名单 (仅元数据) |
| `tab_focus` | 低 | - | 激活一个标签页 | 否 | `tabs` | - |
| `tab_open` | 中 | - | 打开一个 URL (导航) | 否 | `tabs` | 源 (origin) 受白名单门禁 |
| `tab_close` | 高 | 标签页标题/URL | **关闭一个标签页** (数据丢失) | 否 | `tabs` | 扩展窗口确认 |
| `page_snapshot` | 低 | 可交互元素 (无障碍) | - | 否 | `scripting` | 白名单门禁; 注入内容 |
| `page_click` | 高 [1] | ref 所指元素 | 点击 (可能提交/导航) | 否 | `scripting` | 提交/链接需扩展窗口确认 |
| `page_fill` | 高 | - | 向字段输入文本 | 可能 (输入到密码字段) | `scripting` | 回显中的密码值脱敏 |
| `page_text` | 中 | 页面可见文本 | - | 脱敏 | `scripting` | 密码 + 长数字串脱敏 |
| `page_screenshot` | 中 | 视口像素 | - | 可能 (屏幕上的任何内容) | `tabs` | - |
| `page_scroll` | 低 | 滚动位置 | 滚动 | 否 | `scripting` | - |
| `page_wait_for` | 低 | 选择器/文本是否出现 | - | 否 | `scripting` | - |
| `page_navigate` | 中 | - | 在活动标签页中加载一个 http(s) URL | 否 | `tabs` | 目标源受白名单门禁 |
| `page_back` | 低 | - | 活动标签页在历史中后退一步 | 否 | `tabs` | 以当前源做白名单门禁, 而非目标源 ([残余风险](trust-boundaries.md#边界-4-扩展---网页-chrome-api--内容脚本--dom)) |
| `page_forward` | 低 | - | 活动标签页在历史中前进一步 | 否 | `tabs` | 以当前源做白名单门禁, 而非目标源 (同一项残余风险) |
| `page_reload` | 低 | - | 重新加载活动标签页 | 否 | `tabs` | 以当前源做白名单门禁 |
| `page_press` | 高 | - | 向页面发送合成按键或组合键 (可能提交/导航) | 否 | `scripting` | 扩展窗口确认, 每次调用 |
| `page_hover` | 低 | - | 把指针移到某元素上 | 否 | `scripting` | 白名单门禁 |
| `page_select` | 高 | - | 在 `<select>` 中选择一个选项 | 否 | `scripting` | 扩展窗口确认, 每次调用 |
| `console_get` | 中 | 最近的控制台输出, 含网络错误 | - | 脱敏 | `debugger` | 白名单门禁; 输出脱敏; 「正在调试」横幅 |
| `page_handle_dialog` | 高 | - | **接受或关闭**一个 JS 对话框 (alert/confirm/prompt) | 否 | `debugger` | **默认关闭** (需选择启用); 白名单门禁; 「正在调试」横幅 |
| `page_upload` | **严重** | 指定本地文件的字节 | **把本地文件附加**到文件输入框 | 可能 (任何可读文件) | `debugger` | **默认关闭** (需选择启用); 白名单门禁; 每次调用都在扩展窗口确认并显示确切路径; 确认之后重新检查源, 并把附加绑定到那时解析出的文档节点; 见残余风险 |
| `page_eval` | **严重** | 页面能读到的一切 | 在页面中执行**任意 JS** | 是 (可读取令牌/Cookie) | `scripting` (host) | 在主机持有的策略下**默认关闭** (`pageEvalEnabled`, 用 `policy set` 授予); **每次调用**都在扩展窗口确认并显示完整代码; 结果脱敏 |
| `page_snapshot_precise` | 中 | 权威的无障碍树 (CDP) | - | 否 | `debugger` | 预先警告提示; 「正在调试」横幅闪现 |
| `cookie_get` | 高 | Cookie, 含 **httpOnly** | - (只读) | **是** | `cookies` | 限定在白名单范围内; 值脱敏; 刻意不提供 `cookie_set` |
| `storage_get` | 高 | local/sessionStorage | - (只读) | **是** (令牌) | `scripting` | 同源; 值**始终**脱敏 |

[1] `page_click` 对普通元素为中; 当目标是提交按钮或会导航的链接时为**高** (这些会触发确认窗口)。

## 横切保护措施

- **浏览器路由从不猜测:** 连接了多个浏览器时, 工具调用必须通过 `browser` 参数指名其一, 否则失败 (`BROWSER_AMBIGUOUS`); 未知的标识也失败 (`BROWSER_NOT_FOUND`)。每个浏览器的连接都独立认证, 应答了另一个浏览器请求的连接会被断开。
- **白名单:** 页面级工具只在用户批准过的源上运行 (逐站点提示加 `chrome.permissions.request`)。`allowAllSites` 是显式的选择启用。
- **脱敏:** `page_text`、`cookie_get`、`storage_get` 和 `page_eval` 的输出都经过脱敏器 (JWT、长十六进制串、长数字串、类令牌字符串)。`storage_get` 的脱敏不可由用户关闭。
- **确认宽限期:** 在[按标签页键](../../../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe)下重复的提交或链接点击在 `confirmGraceMs` 内跳过提示; `page_eval` 从不跳过, 因此先前的批准绝不会让之后无关的代码运行。默认值由同一节负责。
- **设计上只读:** 没有 `cookie_set` 或 `storage_set` (写入 httpOnly Cookie 有会话固定风险)。
- **CDP 模式 (选择启用, 默认关闭):** `cdpMode` 策略字段把每一个页面级工具改经 `chrome.debugger` 在页面的 MAIN world 中执行, 而不是内容脚本。任何工具的契约、权限、确认或脱敏都不变; 上述保护仍然适用。
  - **它的两个代价:** 它绕过页面 CSP, 因此 `page_eval` 能在严格 CSP 的站点上运行; 并且它为该标签页保持一个持久的调试器附加, 所以只要它开着, 「Started debugging this browser」横幅就一直显示。

## 新增或修改工具时

更新此表, 并遵循[评审标准](../../../.github/SECURITY.md#security-relevant-changes-review-bar)。任何扩大工具影响范围的变更 (新权限、新的敏感读取、新的写入、更弱的确认、更宽的脱敏绕过) 还要更新[信任边界台账](trust-boundaries.md), 并接受带安全标签的审查。
