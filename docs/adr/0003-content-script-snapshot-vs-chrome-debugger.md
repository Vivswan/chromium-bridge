# ADR-0003:snapshot 走 content script 而非 chrome.debugger

- **状态**:Accepted
- **日期**:2026-07-07

## 背景

browser-bridge 的核心能力之一是 `page_snapshot`:返回页面的可访问性树(a11y tree),让 AI 用稳定的 `ref` 引用元素(像 Playwright/chrome-devtools-mcp 那样)。snapshot 的**准确度直接决定后续 click/fill 的稳定性**——这是整个系统的命门。

有两种实现路径:

1. **chrome.debugger API**:attach 到 tab,通过 CDP 调 `Accessibility.getFullAXTree`,拿到 Chrome 内部权威的 a11y 树
2. **content script**:注入 JS,用 TreeWalker 遍历 DOM,自己重新计算 role/accessible-name

调研(详见架构调研报告)发现一个决定性约束。

## 决定性约束:chrome.debugger 强制 infobar

**只要扩展调用 `chrome.debugger.attach`,Chrome 就会在所有标签页顶部强制显示 "Started debugging this browser" 横幅。**

- 无法从扩展内部关闭(Chromium 硬编码的安全特性)
- 唯一的绕过方式是启动 Chrome 时加 `--silent-debugger-extension-api` 命令行参数——**又回到了"特殊启动 Chrome"的老路,违背项目核心目标 G2(零特殊启动)**
- 横幅在所有标签页都显示(不只目标 tab),且会让视口下移约 30px,破坏坐标定位
- 企业强制安装(ExtensionInstallForcelist)在某些场景也能抑制,但要求企业策略,不适用个人用户

这个发现是在选型时通过调研确认的,用户当时明确表达了"做扩展的核心目的就是不要每次特殊启动 Chrome"。

## 决策

**v0.1 的 snapshot 默认走 content script,不调 chrome.debugger:**

- 用 `TreeWalker(SHOW_ELEMENT)` 遍历可见元素
- 重新计算 `role`(优先 `getAttribute('role')`,否则按标签映射:`button→button`、`a[href]→link`、`input→textbox/checkbox/...`)
- 重新计算 `accessible name`(简化版 accname-1.2:`aria-label` → `aria-labelledby` 解析 → `<label for>` → `title` → innerText 截断)
- 给每个有意义节点打 `data-zcb-ref="eN"`,映射存 content script 闭包
- 返回精简树:只含交互节点 + selector 兜底

**阶段二补充**:加 `page_snapshot_precise` 工具,定位失败时 SW 临时 attach → 取 `Accessibility.getFullAXTree` → 立即 detach。期间 infobar 会闪现,**会在工具描述里明确告知用户**。

## 考虑过的替代方案

### 方案 A:纯 chrome.debugger(接受 infobar)
- **优点**:a11y 树权威准确;shadow DOM 自动包含;覆盖率接近 100%
- **缺点**:infobar 永久显示;要么忍受(用户体验差,视口下移破坏自动化),要么加启动参数(违背 G2)
- **排除**:与项目核心目标冲突

### 方案 B:默认 content script,定位失败时临时 attach debugger(用户最终选择)
- **优点**:日常无 infobar;边缘 case 有兜底
- **缺点**:
  - 实现复杂度中等(要处理 attach/detach 时机、错误恢复)
  - 用户会间歇看到 infobar 闪现(已在设计里承诺告知)
- **v0.1 状态**:content script 部分已实现;debugger 回退留到阶段二

### 方案 C:纯 content script(备选,未被选)
- **优点**:无 infobar;用户零感知;不需特殊启动
- **缺点**:shadow DOM 读不到;复杂 ARIA 重新计算会偏;约 10% 边缘 case 不准
- **未被选**:用户选了方案 B,要 debugger 兜底

## 后果

### 正面
- **日常零 infobar**:不调 debugger,用户完全无感知
- **不违背 G2**:不需要特殊启动 Chrome
- **覆盖率约 90%**:对日常交互(button/input/link/menuitem)足够

### 负面
- **shadow DOM 读不到**:closed shadow root 完全不可达;open shadow root 要专门遍历(v0.1 未实现)
- **复杂 ARIA 不准**:aria-hidden 子树、presentational role、`aria-describedby` 等边缘情况,简化版计算会偏
- **accessible name 计算非权威**:Chrome 内部的 `element.computedRole`/`computedName`(AOM)不暴露给 JS,content script 必须重新算,与 Chrome 实际树会有偏差
- **跨域 iframe**:content script 受同源限制读不到
- **阶段二补 debugger 回退**:需要额外实现 `page_snapshot_precise` + 处理 attach/detach 生命周期

## 实施细节(v0.1)

- `extension/content.js` 的 `snapshot()` 函数
- `INTERACTIVE_TAGS` / `INTERACTIVE_ROLES` 决定哪些节点进树
- `roleOf()` / `nameOf()` / `isVisible()` / `cssSelectorOf()` 各自的近似逻辑
- ref 存 DOM 属性 + content script Map,SW 重启后能从 DOM 重建

## 已知漏测

- content.js 的 DOM 操作(snapshot/click/fill)**还没在真实页面上跑过**——协议层 e2e 测试 PASS,但 DOM 层待用户加载扩展后实测
- shadow DOM 支持、复杂 ARIA 准确度,需要真实页面验证后再决定阶段二的 debugger 回退优先级

## 参考

- 调研:Chrome infobar 是 Chromium 硬编码(`chrome/app/generated_resources.grd`),`--silent-debugger-extension-api` 是唯一绕过
- Playwright aria snapshots、chrome-devtools-mcp 都用 CDP 正因如此
- AOM 的 `computedRole`/`computedName` 不暴露给 content script JS,只能重算
