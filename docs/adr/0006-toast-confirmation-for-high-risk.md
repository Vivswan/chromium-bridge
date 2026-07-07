# ADR-0006:高危动作用页面 Toast + 短时免确认

- **状态**:Accepted
- **日期**:2026-07-07

## 背景

即使用户已通过白名单([ADR-0004](./0004-allowlist-with-optional-host-permissions.md))授权了某站点,在该站点内仍有"高危动作"——它们可能造成不可逆的副作用:

- **表单提交**(点击 `type=submit` 按钮):下单、转账、发布、删除
- **链接导航**(点击 `<a href>` / role=link):跳转到新页面,可能触发服务端操作(GET 请求也能改数据)
- **关闭高危域名的标签页**:误关银行/管理后台

这些动作如果让 AI 静默执行,用户可能根本没意识到发生了什么。需要一个二次确认机制。

## 决策

**用页面内 Toast 确认 + 60 秒同源同类免确认窗口:**

1. **触发时机**:content script 在执行 click 前,若目标是 submit/链接类,调 `confirmWithToast()`
2. **Toast UI**:页面右上角注入卡片,显示"Browser Bridge / Click 'xxx'?" + Allow/Deny 按钮
3. **超时**:30 秒不响应自动 Deny(防止工具调用永久挂起)
4. **免确认窗口**:用户 Allow 后,60 秒内同 origin + 同动作类型不再弹(避免连续确认烦人)
5. **关闭高危域名标签**:在 background 的 `tab_close` 里判断(阶段二补充,当前 tab_close 未做高危判断)

## 考虑过的替代方案

### 方案 A:专用确认窗口(独立 popup 窗口)
- **机制**:每次高危动作弹独立窗口,列出动作详情
- **优点**:安全度最高,UI 空间大可显示完整信息
- **缺点**:体验重,每次高危动作要切去点确认;打断 AI 工作流
- **未被选**:用户选了 Toast(轻量)。专用窗口留给未来 `page_eval` 的高危确认([ADR-0005](./0005-page-eval-disabled-by-default.md))

### 方案 B:页面 Toast + 短时免确认(用户选择)
- **优点**:体验轻;连续同类操作不烦人
- **缺点**:可能看漏(Toast 在角落);60 秒窗口内 AI 连续高危动作不再确认
- **v0.1 实现**

### 方案 C:按风险分级(低危静默 / 高危确认)
- **机制**:已授权域名内,低危(普通点击/填表)静默;高危(eval、提交、跳转)才弹
- **优点**:平衡点最好
- **缺点**:实现复杂度高(要维护风险分级表)
- **未被选**:用户当时选了方案 B,但方案 C 其实是方案 B 的自然演进(v0.1 的实现已经隐含分级——只有 submit/link 才弹 Toast,普通 click 静默)

## 后果

### 正面
- **体验轻量**:Toast 不抢焦点,用户可继续操作
- **防永久挂起**:30 秒超时拒绝,工具调用不会卡死
- **连续操作友好**:60 秒免确认窗口,比如连续点 5 个链接不会弹 5 次

### 负面
- **可能看漏**:Toast 在角落,用户注意力在别处可能错过
- **60 秒窗口风险**:窗口内 AI 若被诱导连续做高危动作,只有第一次确认;这是体验/安全的折中
- **仅 click 层**:当前只 gate click,没 gate 表单的 enter 提交、JS 触发的 submit(阶段二补充)

## 实施细节

`extension/content.js`:

```javascript
// 判定高危
function isHighRiskClick(el) {
  const role = roleOf(el);
  if (role === "button" && (el.getAttribute("type") || "").toLowerCase() === "submit") return true;
  if (el.tagName === "A" && el.hasAttribute("href")) return true;
  if (role === "link") return true;
  return false;
}

// 免确认窗口
let lastConfirmed = { key: null, until: 0 };
async function confirmWithToast(question, actionDesc) {
  const key = `${location.origin}:${actionDesc}`;
  if (lastConfirmed.key === key && Date.now() < lastConfirmed.until) return; // 窗口内
  const approved = await showToast(question);
  if (!approved) throw new Error(`user denied: ${actionDesc}`);
  lastConfirmed = { key, until: Date.now() + 60_000 };
}
```

- `showToast()`:注入 DOM 卡片,Promise resolve true/false
- 卡片样式见 `toast.css`,关键样式也 inline 在 `ensureToastHost()`(防 toast.css 没加载)
- z-index 极高(2147483647)确保在最上层

## 已知局限(阶段二改进)

1. **只 gate click**:表单的 Enter 提交、`form.submit()` JS 调用没拦截
2. **不感知 SPA 路由**:pushState/replaceState 的"软导航"不触发(用户感知是跳转,但没拦)
3. **免确认 key 粒度**:当前是 `origin:actionType`,未来可考虑 `origin:actionType:targetSelector` 更细
4. **Toast 可被页面 CSS 干扰**:虽然用了高 z-index + inline 关键样式,但极端情况页面可能用 `!important` 覆盖

## 与其他 ADR 的关系

- 配合 [ADR-0004](./0004-allowlist-with-optional-host-permissions.md):白名单是第一层(站点级),Toast 是第二层(动作级)
- 区别于 [ADR-0005](./0005-page-eval-disabled-by-default.md):Toast 用于 UI 动作(click/fill),page_eval 若实现需更强确认(专用窗口)
