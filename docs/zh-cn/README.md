# Genkan

Genkan 让 MCP 客户端通过一个浏览器扩展和一个原生消息主机, 操作你已经登录的 Chromium 浏览器, 无需调试端口。代码是唯一事实来源: 凡是页面陈述了某个行为, 拥有该行为的文件才是权威。安全页面说明本桥接承诺什么、止步于何处; 其余页面说明如何使用、运行和修改它。

## 我想要...

| 目标 | 阅读 |
|---|---|
| 安装二进制与扩展, 并运行第一次工具调用 | [快速入门: CLI](quickstart.md#cli-macoslinuxwindows) |
| 检查安装是否健康, 或读懂「server not reachable」 | [CLI: doctor 与 status](cli.md#doctor--status-只读自检) |
| 向浏览器注册原生消息主机, 或移除注册 | [CLI: doctor --fix 与 uninstall](cli.md#doctor---fix--uninstall-原生消息注册) |
| 准入一个 MCP 客户端, 或吊销一个 | [CLI: 受信任客户端](cli.md#受信任客户端-pair-client--revoke-client--list-clients) |
| 立刻停下一切, 稍后再解除 | [CLI: 紧急开关 (kill switch)](cli.md#紧急开关-kill--unkill) |
| 改变工具被允许做什么 | [CLI: 主机持有的策略](cli.md#主机持有的策略-policy) |
| 阅读日志与审计日志 | [CLI: 日志与审计](cli.md#日志与审计-genkan_log--genkan_log_format) |
| 读懂一行意料之外的 `doctor` 输出, 或恢复不可读的紧急开关记录 | [故障排除](troubleshooting.md) |
| 在 WSL 中使用本桥接 | [故障排除: 在 WSL 下运行](troubleshooting.md#在-wsl-下运行) |
| 了解本桥接承诺攻击者做不到什么, 以及这一承诺止步于何处 | [安全: 标准线](security.md#一句话说清标准线) |
| 查看每个工具能触及什么、会触发哪种确认 | [工具风险矩阵](security/tool-risk-matrix.md) |
| 报告安全问题 | [事件响应: 报告](security/incident-response.md#报告渠道) |
| 在修改某项安全决策之前理解它为何如此 | [安全设计依据](security/rationale.md) |
| 了解扩展收集和存储什么 | [隐私政策](privacy-policy.md) |
| 查看各进程如何连接、每一跳传递什么 | [架构: 总览](architecture.md#1-架构总览) |
| 找到由 Rust 核心持有、经 `moon run gen` 生成为 TypeScript 的跨进程契约 (工具目录、错误分类、能力、协议版本、身份、传输信封) | [架构: 协议边界契约](architecture.md#11-协议边界契约-错误分类与握手) |
| 修改与安全相关的内容 | [审查标准](../../.github/SECURITY.md) |
| 搭建工具链并运行门禁 | [开发: moon](development.md#moon-规范的命令接口) |
| 针对隔离的 Chrome 运行浏览器测试套件, 绝不针对你自己的浏览器 | [测试](../../tests/README.md) |
| 添加一个工具 | [贡献: 添加工具](../../CONTRIBUTING.md#adding-a-tool) |
| 发布一个版本 | [发布](release.md#触发-合并发布-pr) |
| 了解哪种改动会推动哪个版本号 | [发布: 版本](release.md#版本) |
| 权衡是否把扩展发布到 Chrome 应用商店 | [发布: Chrome 应用商店](release.md#发布到-chrome-应用商店) |

## 页面一览

### 使用

1. [快速入门](quickstart.md): 安装、首次使用、推荐的加固、卸载。
2. [CLI](cli.md): doctor、注册、登记、受信任客户端、紧急开关、策略、日志与审计, 以及各自对应的故障排除。
3. [故障排除](troubleshooting.md): 逐个症状排查, 从意料之外的 `doctor` 输出行到紧急开关记录的恢复、版本不一致, 以及两种 WSL 模式。
4. [隐私政策](privacy-policy.md): 扩展可以访问什么、存储什么, 以及它从不发送什么。

### 安全

5. [安全](security.md): 一句话承诺、利害所在与谁受信任、四跳及各由什么把守、你要确认什么、止步之处, 按操作系统分述。
6. [信任边界](security/trust-boundaries.md): 评审者的台账, 按跳分述: 机制细节、每一项已接受的残余风险、策略台账、不变量。
7. [工具风险矩阵](security/tool-risk-matrix.md): 每个工具的影响范围与保护措施。
8. [事件响应](security/incident-response.md): 报告、分诊、缓解、披露。
9. [安全设计依据](security/rationale.md): 每项决策为何如此, 以及它否决了什么。
10. [审查标准](../../.github/SECURITY.md): 需要额外审查的区域、失败即安全的默认值, 以及在做安全相关改动前应读什么。

### 参考

11. [架构](architecture.md): 组件、协议、数据流、安全模型、关键约束、技术选型, 以及 Rust 核心生成的契约。

### 贡献

12. [开发](development.md): 工具链、目录布局、moon 任务、测试、容器、模糊测试。
13. [发布](release.md): release-please 流水线、带校验和与来源证明的预构建压缩包、SBOM、何时推动哪个版本号, 以及 Chrome 应用商店的决定。
14. [CONTRIBUTING](../../CONTRIBUTING.md): 开发流程, 从分支、提交与同步规则到压缩合并。
15. [测试](../../tests/README.md): 各测试套件, 以及浏览器测试只针对隔离的 Chrome、绝不针对你日常浏览器的规则。
