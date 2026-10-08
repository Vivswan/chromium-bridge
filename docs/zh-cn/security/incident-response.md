# 事件响应手册

疑似的边界突破如何报告、定级、遏制、修复与披露, 按单维护者项目的规模裁剪。资产与边界见[安全页面](../security.md); 修复所要恢复的不变量见[台账](trust-boundaries.md#不得倒退的不变量)。

## 什么算安全事件

对[安全页面](../security.md#利害所在-以及谁受信任)所保护的某项资产的攻陷或疑似攻陷。例如:

- 在未授权的源 (origin) 上执行了页面操作, 绕过了站点白名单或确认提示;
- Cookie、存储、页面内容或 eval 返回值绕过脱敏泄露出去;
- 桥接套接字接受了未经认证的本地对端, 或主机清单的 `allowed_origins` 被修改;
- 没有在场证明就解除了紧急开关, 或放宽了策略;
- `page_eval` 或其确认通道被滥用并造成不可逆的后果。

不算事件的情况: 任何需要先攻陷整台机器的情形, 或用户自己配对的恶意 MCP 客户端 (设计上即受信任, 见[范围](../../../.github/SECURITY.md#scope))。

## 报告渠道

**不要为安全问题开公开 issue。** 私密渠道、一份有用的报告应包含什么, 以及可以期待什么回应, 见[安全策略](../../../.github/SECURITY.md#reporting-a-vulnerability)。

## 分诊

用四个问题给报告定级; 它们对应[工具风险矩阵](tool-risk-matrix.md)中的影响范围:

1. **跨越了哪条边界?** [台账](trust-boundaries.md)中的边界 1 到 4; 边界 4, 即页面边界, 最为关键。
2. **能读取或更改什么?** 是否触及凭据 (Cookie 或存储中的令牌)? 是否有写入或不可逆的后果?
3. **前提条件有多强?** 是否要求用户已授权某个源、已安装扩展, 或存在本地同 UID 进程?
4. **是否可复现?** 有没有概念验证?

答案决定「立即缓解」还是「排期修复」。凭据泄露以及白名单或确认绕过是最高优先级。

## 立即缓解 (用户侧, 无需改代码)

在补丁就绪之前, 用户可以自行缩小影响范围:

1. **启用紧急开关:** `genkan kill`, 或扩展的选项页。每一次工具调用都被拒绝, 每一条浏览器连接都在大约一秒内被切断; 命令及其解除由 [CLI 页面](../cli.md#紧急开关-kill--unkill)负责。
2. **禁用单个工具:** `genkan policy restrict --disabled-tools <list>` 把它加入主机策略的 `disabledTools`。该标志给出的是完整的、逗号分隔的禁用列表, 所以要保留其中已有的工具。这次写入是免费的 (没有在场提示), 因为限制只会移除能力。
   - 随后主机会在任何桥接流量之前, 以 [`ERROR_SPECS`](../../../src/packages/core/src/error.rs) 中稳定的 `TOOL_DISABLED` 代码拒绝该工具, 扩展也会在自己的边界上强制执行推送下来的策略。
   - 先禁用 `page_eval` 这类高风险工具。之后重新启用它属于放宽, 需要付出一次在终端确认之后的经签名策略写入, 这是有意为之的设计 ([CLI 页面](../cli.md#主机持有的策略-policy))。
3. **撤销白名单, 或关闭「所有站点」:** 在选项页或弹出窗口中, 移除对受影响源的授权, 并确认 `allowAllSites` 已关闭。移除授权同时也会撤销该源的主机权限。
4. **停止扩展:** 在 `chrome://extensions` 中禁用或移除它。原生消息主机的 stdin 收到 EOF 并退出, 桥接随之被切断; 也结束 MCP 客户端会话, 让 MCP 服务器退出, 并用 `doctor` 确认 ([CLI 页面](../cli.md#doctor--status-只读自检))。
5. **卸载主机清单:** `genkan uninstall` 移除原生消息注册, 此后 Chrome 无法再拉起主机 ([CLI 页面](../cli.md#doctor---fix--uninstall-原生消息注册))。

## 修复与验证

- 找到被跨越的那条[不变量](trust-boundaries.md#不得倒退的不变量)。
- 修复要经过[评审标准](../../../.github/SECURITY.md#security-relevant-changes-review-bar): [安全变更检查清单](../../../.github/ISSUE_TEMPLATE/security-change.yml)、[工具风险矩阵](tool-risk-matrix.md), 以及如果边界有变, [台账](trust-boundaries.md)。
- 必须有一个否定性安全测试来证明边界重新成立; 只有正向用例是不够的。

## 发布与披露

- 按[发布页面](../release.md)为修复打标签并发布。1.0 之前只支持最新的发布 ([支持的版本](../../../.github/SECURITY.md#supported-versions)), 安全修复以新的 patch 或 minor 版本发出。
- 通过 GitHub Security Advisory 协调披露: 在公开之前给报告者一个合理的修复窗口期; 发布之后, 在公告中致谢报告者, 并说明受影响的版本与缓解措施。
- 修复通过其 Conventional Commit 主题进入发布说明; 变更日志如何生成由[发布页面](../release.md)负责。
