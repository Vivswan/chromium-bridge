# 事件响应手册

> 一套面向单维护者项目的、切合实际的安全事件处理流程, 与 [SECURITY.md](../../../.github/SECURITY.md) 中的报告渠道以及 [threat-model.md](threat-model.md) 中的资产和信任边界保持一致。信任边界在 [trust-boundaries.md](trust-boundaries.md) 中逐一列出; 工具风险见 [tool-risk-matrix.md](tool-risk-matrix.md)。

## 什么算安全事件

对 [threat-model.md](threat-model.md) 所保护的某项资产的攻陷或疑似攻陷。例如:

- 在**未授权的源 (origin)** 上执行了页面操作, 绕过了站点白名单或确认提示;
- Cookie / 存储 / 页面内容 / eval 返回值绕过脱敏泄露出去;
- 桥接套接字接受了**未经认证的**本地对端, 或主机清单的 `allowed_origins` 被修改;
- `page_eval` 或其确认通道被滥用并造成不可逆的后果。

不算事件的情况: 任何需要先攻陷整台机器的情形, 或用户自己配置的恶意 MCP 客户端 (设计上即受信任, 见 [SECURITY.md 的 Scope](../../../.github/SECURITY.md#scope))。

## 报告渠道

**不要为安全问题开公开 issue。** 使用 GitHub 的 **[Report a vulnerability](https://github.com/Vivswan/chromium-bridge/security/advisories/new)** (Security -> Advisories) 进行私密报告, 内容包括: 攻击者能做什么 (影响) 以及跨越了哪条信任边界、复现步骤或 PoC, 以及受影响的版本/提交。作为一个小项目, 我们会在数天内确认收到, 并请求一个合理的修复窗口期。

## 分诊

收到报告后, 用以下问题给它定级 (这些问题对应 [tool-risk-matrix.md](tool-risk-matrix.md) 中的影响范围):

1. **跨越了哪条信任边界?** (见 [trust-boundaries.md](trust-boundaries.md) 中的边界 1 到 4; 边界 4, 即页面边界, 最为关键。)
2. **能读取或更改什么?** 是否触及凭据 (Cookie/存储中的令牌)? 是否有写入或不可逆的后果?
3. **前提条件有多强?** 是否要求用户已授权某个源、已安装扩展, 或存在本地同 UID 进程?
4. **是否可复现?** 有没有 PoC?

据此在「立即缓解」和「排期修复」之间作出决定。凭据泄露以及白名单/确认绕过是最高优先级。

## 立即缓解 (用户侧, 无需改代码)

在补丁就绪之前, 用户可以自行采取以下措施来**缩小影响范围**:

- **禁用单个工具**: 用 `chromium-bridge policy restrict --disabled-tools <list>` 把受影响的工具加入主机策略的 `disabledTools` (该标志给出的是完整的、逗号分隔的禁用列表, 所以要保留其中已有的工具; 这次写入是免费的, 不会弹出 Touch ID 提示, 因为限制只会移除能力 - 见 [cli.md](../cli.md#主机持有的策略-policy))。随后主机的分发门禁会在任何桥接流量之前, 以 [`ERROR_SPECS`](../../../src/packages/core/src/error.rs) 中稳定的 `TOOL_DISABLED` 代码拒绝该操作, 扩展也会在自己的边界上强制执行推送下来的策略。应首先禁用 `page_eval` 这类高风险工具。之后重新启用它属于放宽, 需要付出一次经签名、以 Touch ID 为门槛的策略写入 - 这是有意为之的设计。
- **撤销白名单 / 关闭「所有站点」**: 在选项页 / 弹出窗口中, 移除对受影响源的授权, 并确认 `allowAllSites` 已关闭。移除授权同时也会撤销该源的主机权限 (host permission)。
- **紧急开关 (kill switch)**: 在 `chrome://extensions` 中禁用或移除 Chromium Bridge 扩展。扩展一停止, 原生消息主机的 stdin 就会收到 EOF 并退出, 桥接随之被切断。如有需要, 也结束 MCP 客户端会话, 让 MCP 服务器进程退出 (用 `doctor` 确认不可达, 见 [CLI 页面](../cli.md#doctor--status-只读自检))。
- **卸载主机清单**: 删除原生消息主机清单之后, Chrome 就无法再拉起主机 (路径见 [architecture.md 第 4.3 节](../architecture.md#43-磁盘上的产物))。

> 缓解措施的顺序, 由轻到重: 先禁用高风险工具, 再撤销白名单, 再禁用扩展, 最后卸载清单。

## 修复与验证

- 找到被跨越的那条**不变量** (见 [trust-boundaries.md 中的「不得倒退的不变量」](trust-boundaries.md#不得倒退的不变量))。
- 修复要经过**安全相关变更**门禁: 填写[安全变更检查清单](../../../.github/ISSUE_TEMPLATE/security-change.yml), 更新 [tool-risk-matrix.md](tool-risk-matrix.md), 如果信任边界有变, 还要更新 [threat-model.md](threat-model.md)。
- **必须有一个否定性安全测试**来证明边界重新成立 (只增加正向用例是不够的), 依据是 [SECURITY.md 的评审标准](../../../.github/SECURITY.md#security-relevant-changes-review-bar)。

## 发布与披露

- 按 [release.md](../release.md) 为修复打标签并发布; 1.0 之前只支持最新的发布 (见 [SECURITY.md 的 Supported versions](../../../.github/SECURITY.md#supported-versions)), 安全修复以新的 patch/minor 版本发出。
- 通过 GitHub Security Advisory 协调披露: 在公开之前给报告者一个合理的修复窗口期; 发布之后, 在公告中致谢报告者, 并说明受影响的版本与缓解措施。
- 在 [CHANGELOG.md](../../../CHANGELOG.md) 中记录该修复。

## 相关页面

- 报告渠道与评审标准: [SECURITY.md](../../../.github/SECURITY.md)。
- 资产、参与者、非目标: [threat-model.md](threat-model.md)。
- 边界与不变量: [trust-boundaries.md](trust-boundaries.md)。
- 症状与恢复: [troubleshooting.md](../troubleshooting.md)。
