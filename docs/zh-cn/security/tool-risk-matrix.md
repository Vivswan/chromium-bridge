# 工具风险矩阵

本页列出 chromium-bridge 暴露的每一个工具, 包括其风险级别、能读取/更改什么、是否触及凭据、需要哪项 Chrome 权限, 以及用户如何受到保护。这是安全审查的参考: **新增或修改工具意味着更新此表** (见 [SECURITY.md](../../../.github/SECURITY.md))。

风险级别: **低** (只读, 无敏感数据)、**中** (读取页面内容或导航)、**高** (写入页面, 或读取凭据)、**严重** (任意代码 / 最大爆炸半径)。

所列保护措施均为默认值。确认门禁是主机持有的策略字段 (`confirmHighRiskClick`、`confirmTabClose`、`confirmPageEval`、`touchIdConfirm`、`confirmGraceMs`), 用 `chromium-bridge policy` 编辑 (`set` 会签署一次授予, `restrict` 无需签名), 绝不从扩展编辑; 放宽任何一项都是显式的、经签名的选择, 其残余风险列表见 [SECURITY.md](../../../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe)。

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
| `page_back` | 低 | - | 活动标签页在历史中后退一步 | 否 | `tabs` | 以当前源做白名单门禁 (而非目标源, 见残余风险) |
| `page_forward` | 低 | - | 活动标签页在历史中前进一步 | 否 | `tabs` | 以当前源做白名单门禁 (而非目标源, 见残余风险) |
| `page_reload` | 低 | - | 重新加载活动标签页 | 否 | `tabs` | 以当前源做白名单门禁 |
| `page_press` | 高 | - | 向页面发送合成按键或组合键 (可能提交/导航) | 否 | `scripting` | 扩展窗口确认 |
| `page_hover` | 低 | - | 把指针移到某元素上 | 否 | `scripting` | 白名单门禁 |
| `page_select` | 高 | - | 在 `<select>` 中选择一个选项 | 否 | `scripting` | 扩展窗口确认 |
| `console_get` | 中 | 最近的控制台输出, 含网络错误 | - | 脱敏 | `debugger` | 白名单门禁; 输出脱敏; 「正在调试」横幅 |
| `page_handle_dialog` | 高 | - | **接受或关闭**一个 JS 对话框 (alert/confirm/prompt) | 否 | `debugger` | **默认关闭** (需选择启用); 白名单门禁; 「正在调试」横幅 |
| `page_upload` | **严重** | 指定本地文件的字节 | **把本地文件附加**到文件输入框 | 可能 (任何可读文件) | `debugger` | **默认关闭** (需选择启用); 白名单门禁; 每次调用都确认并显示路径; 在已登记的 Mac 上该确认是 Secure Enclave Touch ID 批准 (`touchIdConfirm`); 见残余风险 |
| `page_eval` | **严重** | 页面能读到的一切 | 在页面中执行**任意 JS** | 是 (可读取令牌/Cookie) | `scripting` (host) | 在主机持有的策略下**默认关闭** (`pageEvalEnabled`, 用 `policy set` 授予); **每次调用**都确认并显示完整代码; 在已登记的 Mac 上该确认是任何页面都无法伪造的 Secure Enclave Touch ID 批准 (`touchIdConfirm`; 选择退出则回退到 DOM 之外的窗口; 同一用户的程序围绕这次轻触仍能做什么, 见[威胁模型的残余风险](./threat-model.md#残余风险-已接受已跟踪)); 结果脱敏; 选项页可启用紧急开关 (kill switch), 且只有 `chromium-bridge unkill` 能解除 |
| `page_snapshot_precise` | 中 | 权威的无障碍树 (CDP) | - | 否 | `debugger` | 预先警告提示; 「正在调试」横幅闪现 |
| `cookie_get` | 高 | Cookie, 含 **httpOnly** | - (只读) | **是** | `cookies` | 限定在白名单范围内; 值脱敏; 刻意不提供 `cookie_set` |
| `storage_get` | 高 | local/sessionStorage | - (只读) | **是** (令牌) | `scripting` | 同源; 值**始终**脱敏 |

[1] `page_click` 对普通元素为中; 当目标是提交按钮或会导航的链接时为**高** (这些会触发确认窗口)。

## 横切保护措施

- **浏览器路由从不猜测**: 连接了多个浏览器时, 工具调用必须通过 `browser` 参数指名其一, 否则失败 (`BROWSER_AMBIGUOUS`); 未知的标识也失败 (`BROWSER_NOT_FOUND`)。每个浏览器的连接都独立认证, 应答了另一个浏览器请求的连接会被断开。
- **站点白名单**: 页面级操作只在用户批准过的源上运行 (逐站点提示 + `chrome.permissions.request`)。`allowAllSites` 是显式的选择启用。
- **脱敏**: `page_text`、`cookie_get`、`storage_get` 和 `page_eval` 的输出都经过脱敏器 (JWT / 长十六进制串 / 长数字串 / 类令牌字符串)。`storage_get` 的脱敏不可由用户关闭。
- **确认宽限期**: 用户允许一次高风险点击之后, 同一标签页、同一源、同一动作类型 (提交或链接) 在 60 s 内跳过再次提示 (`confirmGraceMs`); 同一源上的另一个标签页需要再次确认。`page_eval` **不在**此宽限期之内。它每次调用都重新确认, 因此先前的批准绝不会让之后无关的代码运行。
- **设计上只读**: 没有 `cookie_set` / `storage_set` (写入 httpOnly Cookie 有会话固定风险)。
- **CDP 模式 (选择启用, 默认关闭)**: `cdpMode` 策略字段把**每一个**页面级操作改经 `chrome.debugger` (CDP) 在页面的 MAIN world 中执行, 而不是内容脚本。它**不**改变任何工具的契约、权限、确认或脱敏 - 上述同样的白名单 / 确认 / 脱敏保护仍然适用。它的两个安全取舍: 它**绕过页面 CSP** (因此 `page_eval` 能在 Bing 这类严格 CSP 的站点上运行), 并且它为该标签页保持一个**持久的调试器附加**, 所以只要它开着, 「Started debugging this browser」横幅就一直显示。

## 新增或修改工具时

更新此表, **并且**执行 [SECURITY.md](../../../.github/SECURITY.md) 中的安全变更检查清单。任何扩大工具爆炸半径的变更 (新权限、新的敏感读取、新的写入、更弱的确认、更宽的脱敏绕过) 都需要更新威胁模型并进行带安全标签的审查。
