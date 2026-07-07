# ADR-0004:白名单 + optional host permissions 按需授权

- **状态**:Accepted
- **日期**:2026-07-07

## 背景

AI 要操作用户的真实浏览器,**最危险的事**是它能点/填任意页面——尤其银行、邮箱、已登录的管理后台。一旦 AI 的指令被诱导(提示注入、模型错误),就可能窃取 token、执行转账、泄露隐私。

需要一种权限模型控制"AI 能操作哪些网站"。

## 决策

**采用域名白名单 + 按需授权,通过 `optional_host_permissions` + 运行时 `chrome.permissions.request` 实现:**

1. **manifest 声明**:`host_permissions: []`(初始无任何域名权限)+ `optional_host_permissions: ["<all_urls>"]`(运行时可申请)
2. **不用 manifest content_scripts**:全部用 `chrome.scripting.executeScript` 动态注入(否则静态 matches 在无 host 权限时根本不注入)
3. **首次操作新域名**:扩展弹 popup,用户点 Allow 时**同时**:
   - 调 `chrome.permissions.request({origins: [pattern]})` 申请该域名 host 权限
   - 把域名加入 `chrome.storage.local` 的白名单
4. **白名单可撤销**:popup 显示已授权域名列表,可逐个 revoke
5. **持久化**:白名单存 `chrome.storage.local`,SW 重启后仍在

## 考虑过的替代方案

### 方案 A:静态 host_permissions: ["<all_urls>"](安装时一次授权所有)
- **优点**:实现最简;content script 自动注入所有页面
- **缺点**:
  - 安装时弹"读取和更改所有网站数据"警告,劝退用户
  - 违背"最小权限"原则——AI 能瞬间操作所有网站,包括银行
  - 无按需控制
- **排除**:用户明确选了白名单方案

### 方案 B:黑名单 + 关键动作确认
- **机制**:默认开放所有站点,对银行/支付等建黑名单;高危动作实时确认
- **优点**:体验顺滑,不用每用新站点加权限
- **缺点**:需要维护黑名单(银行域名多且变);默认开放攻击面大;依赖用户保持警觉
- **排除**:用户在决策时选了白名单(更安全)

### 方案 C:全开放(只本地)
- **机制**:不限制域名、不二次确认,反正只在本机
- **缺点**:安全完全靠信任 AI 每条指令;提示注入风险无防护
- **排除**:用户明确不选这个

## 后果

### 正面
- **最小权限**:默认 AI 啥也操作不了,每个新站点要用户主动授权
- **细粒度撤销**:用户随时能在 popup 撤销某域名
- **Chrome 权限模型对齐**:用 Chrome 原生的 `optional_host_permissions` + `permissions.request`,符合 MV3 最佳实践
- **白名单持久**:storage.local 跨 SW 重启

### 负面
- **首次体验有摩擦**:每用新站点要点一下 popup 授权
- **必须用户手势**:`permissions.request` 只能在 popup/action 点击上下文调用,不能在 service worker 后台调——所以授权必须走 popup UI
- **badge 提示机制**:授权请求时设 action badge "!",用户要主动点扩展图标打开 popup(60 秒不响应自动拒绝)
- **不用 manifest content_scripts 的代价**:必须 `injectIfNeeded`(先 ping,失败再 `executeScript`),多一次往返

### 中性
- 白名单的"域名"粒度是 origin glob(如 `https://example.com/*`),不是精确 URL,这对绝大多数场景够用

## 实施细节

- `extension/manifest.json`:`permissions: [tabs, scripting, storage, nativeMessaging]`(无 activeTab,因为要后台注入);`host_permissions: []`;`optional_host_permissions: ["<all_urls>"]`;**无 content_scripts 字段**
- `extension/background.js`:
  - `ensureAllowed(url)`:检查 origin glob 是否在白名单;不在则 `promptUserForAllow`(设 badge + 存 `pendingAllow` + 60s 超时)
  - `injectIfNeeded(tabId)`:ping content script,失败则 `chrome.scripting.executeScript`
- `extension/popup.js`:`resolvePending` 时调 `chrome.permissions.request({origins: [pattern]})` + 记录白名单

## 设计要点

**为什么不用 manifest content_scripts + 静态 matches**:MV3 里,即使 manifest 声明了 content_scripts 的 matches,如果对应域名不在 host_permissions(或已授予的 optional 权限)里,content script **不会注入**。所以静态 matches 配合初始空 host_permissions 等于完全失效。改用动态注入,权限完全跟着 optional 走,授权哪个域就注入哪个域,逻辑清晰。

## 与 ADR-0006 的关系

白名单控制"能操作哪些站点",Toast 确认([ADR-0006](./0006-toast-confirmation-for-high-risk.md))控制"已授权站点内的哪些动作需要二次确认"。两层防御互补:白名单防陌生站点,Toast 防已授权站点的危险动作。
