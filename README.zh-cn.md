# Genkan

你的 AI 在玄关等候。

[![CI](https://github.com/Vivswan/genkan/actions/workflows/ci.yml/badge.svg)](https://github.com/Vivswan/genkan/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Individual%20and%20Small%20Organization%201.1.0-blue)](./LICENSE.md)

[English](./README.md) | 简体中文 | [繁體中文](./README.zh-tw.md)

你安装的程序无法在你不知情的情况下使用你的浏览器。在这条标准线之下, genkan 让任意 MCP 客户端 (Claude Code、Claude Desktop、Codex, 或任何支持 Model Context Protocol 的程序) 通过一个浏览器扩展和一个原生消息主机, 操作你真实的 Chromium 浏览器: 你的标签页、你已登录的会话、你的 Cookie。不需要第二个浏览器, 不需要 CDP 调试端口, 也不需要 `--remote-debugging` 标志。

因为它操作的是你已经登录的浏览器, 代理可以读取需要你的身份验证才能访问的页面、在你已登录的应用中逐步点击操作, 或取出你的框架存放在 `localStorage` 里的令牌。这种能力同时也是风险, 所以安装前请先阅读[安全优先](#安全优先)。这条标准线止步于何处, 写在[安全页面](./docs/zh-cn/security.md)上。

## 特性

- **你真实的浏览器, 而不是无头浏览器:** 覆盖标签页、页面、Cookie 和存储的 26 个工具, 每一个都标明了风险等级和门禁 ([见下文](#你能做什么-26-个工具))。
- **护栏默认开启:** 逐站点批准、在任何页面都无法触及的窗口中确认危险操作、以 WebAuthn 证明在场、紧急开关 (kill switch)、审计日志 ([安全优先](#安全优先))。
- **一座经过身份验证与证明的桥接**, 连接 MCP 服务器与浏览器的主机, 没有监听端口 ([工作原理](#工作原理))。
- **可同时接入多个客户端,** 每一个都经过证明并可单独吊销。
- **一个二进制, 三种角色:** MCP 服务器、原生消息主机, 以及负责安装、配对、紧急中止和审计的 CLI。

## 安全优先

genkan 操作的是一个真实的、已通过身份验证的浏览器。它可以读取页面内容、Cookie (包括 `httpOnly`) 和 Web 存储, 还可以在你的页面中运行 JavaScript。护栏如下:

- **批准每一个站点。** 页面级工具只在你批准过的源 (origin) 上运行, 新的源会提示你; 只有标签页标题和 URL 无需批准 ([矩阵](./docs/zh-cn/security/tool-risk-matrix.md#横切保护措施)、[标准线](./docs/zh-cn/security.md#一句话说清标准线))。
- **确认高风险操作。** 提交与链接点击、按键、选择、关闭标签页、文件上传, 以及每一次 `page_eval`, 都要在一个由扩展拥有、页面既看不到也点不到的窗口上确认; `page_eval` 和 `page_upload` 每次调用都重新确认 ([你要确认什么](./docs/zh-cn/security.md#你要确认什么-以及什么算在场))。同一用户下的程序围绕这个窗口仍能做什么, 见[信任边界台账](./docs/zh-cn/security/trust-boundaries.md#边界-4-扩展---网页-chrome-api--内容脚本--dom)。
- **用 WebAuthn 证明在场。** 解除紧急开关需要在该浏览器下登记的认证器上轻触一次, 登记另一个浏览器则需要在本机已登记的任一认证器上轻触一次; 两者都由主机验证。只有在没有任何已登记的认证器能够应答时, 确认窗口才会顶替上场 ([什么算在场](./docs/zh-cn/security.md#你要确认什么-以及什么算在场))。
- **门禁默认开启。** 每一道门禁都是有文档记录的设置, 放宽任何一道都是一次明确、知情的选择 ([SECURITY.md](./.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe))。
- **Cookie 和 Web 存储只读。** `cookie_get` 和 `storage_get` 返回脱敏后的值, 从不写入 ([矩阵](./docs/zh-cn/security/tool-risk-matrix.md#横切保护措施)); 脱敏能捕获什么、会漏掉什么, 由 [SECURITY.md](./.github/SECURITY.md#masking-is-heuristic-and-best-effort) 负责。
- **经过身份验证与证明的桥接。** 任何操作系统上都没有监听端口: macOS 和 Linux 上是一个私有的 Unix 域套接字, Windows 上是只有你的用户能打开的命名管道。每个连接都要通过同一用户检查、双向可执行文件证明, 以及基于每次运行密钥的 HMAC 质询; 各操作系统的机制见 [SECURITY.md 的平台表](./.github/SECURITY.md#platform-support)。
- **受信任客户端白名单, 在你创建之后生效。** `genkan pair-client` 创建它; 此后只有代码身份经证明且获你批准的 MCP 客户端才会得到服务, 并且任何一个界面都能随时吊销其中一个 ([cli.md](./docs/zh-cn/cli.md#受信任客户端-pair-client--revoke-client--list-clients))。
- **全局紧急开关。** 在 CLI 或扩展中执行一次操作即可中止一切, 直到你以在场证明解除为止 (轻触一次认证器; 在该浏览器未登记任何认证器时, 用确认窗口; 或在终端上键入指定短语; [cli.md](./docs/zh-cn/cli.md#紧急开关-kill--unkill))。安全决策会落入磁盘上的审计日志 ([cli.md](./docs/zh-cn/cli.md#日志与审计-genkan_log--genkan_log_format) 负责事件清单及其两个例外)。

完整细节: [SECURITY.md](./.github/SECURITY.md)、[安全页面](./docs/zh-cn/security.md)、[信任边界](./docs/zh-cn/security/trust-boundaries.md)、[逐工具风险矩阵](./docs/zh-cn/security/tool-risk-matrix.md)。

## 要求

| | 支持情况 |
|---|---|
| macOS | Apple Silicon (arm64) 预构建; Intel 从源码构建 ([构建矩阵](./docs/zh-cn/release.md#构建矩阵与预构建压缩包)) |
| Linux | x64 预构建; 任何基于 Chromium 的浏览器 |
| Windows | x64 预构建 (原生, 无需管理员权限); 带双向证明的用户专属命名管道 ([SECURITY.md](./.github/SECURITY.md#platform-support)) |
| 浏览器 | 任何基于 Chromium 的浏览器, Manifest V3: `chrome`、`chromium`、`brave`、`edge`、`vivaldi`、`opera` 是已知的 `--browser` 键; 在 macOS 和 Linux 上, 其他变体通过 `doctor --fix --manifest-dir <dir>` 注册, 而 Windows 上的注册是针对已知浏览器的一个 HKCU 键 ([cli.md](./docs/zh-cn/cli.md#doctor---fix--uninstall-原生消息注册)) |
| MCP 客户端 | 任何通过 stdio 说 MCP 协议 `2026-07-28` 的客户端 |
| 内部桥接协议 | `1` ([src/packages/core/src/protocol.rs](./src/packages/core/src/protocol.rs) 中的 `BRIDGE_PROTOCOL_VERSION`) |

1.0 之前 ([Cargo.toml](./Cargo.toml)): 协议层由端到端、对抗性和混沌测试覆盖, 线上协议解析器经过模糊测试 ([CHANGELOG.md](./CHANGELOG.md))。

## 快速开始

CLI 除了二进制本身不需要任何东西, 在桌面机、无头机器和 CI 上都一样。完整步骤, 连同各个安装渠道以及每种渠道替你做了什么, 见[快速入门](./docs/zh-cn/quickstart.md); 简版如下:

1. 从[最新发布](https://github.com/Vivswan/genkan/releases/latest)安装: `.pkg`、`.msi`、`.deb`、Homebrew (待 [tap](./docs/zh-cn/release.md#homebrew-tap) 就绪后) 或压缩包。要先校验下载文件, 相关命令见 [SECURITY.md](./.github/SECURITY.md#release-artifact-integrity)。

2. 把二进制注册到你的浏览器, 除非安装程序已经做了: `.pkg`、`.msi` 和 Homebrew 会做, `.deb` 也为安装时已有的浏览器做了 ([快速入门第 3 步](./docs/zh-cn/quickstart.md#cli-macoslinuxwindows))。这条命令是幂等的: 全新安装、修复, 以及移动二进制后的重新注册:

   ```sh
   genkan doctor --fix          # every detected browser
   genkan doctor --fix --browser chrome,brave
   ```

   从压缩包安装时, 以 `./` 前缀从一个稳定的路径运行解压出的二进制: 它是就地注册的, 而 `genkan uninstall` 会精确撤销所注册的内容。

3. 加载扩展: 在 `chrome://extensions` 开启开发者模式, 点「加载已解压的扩展程序」, 选择压缩包里的 `extension/dist` 目录。然后重启浏览器。扩展需要 Chrome 134 或更新版本; 更旧的浏览器会拒绝加载它。

4. 配对, 然后登记 (推荐): `genkan pair` 会打印主机密钥的指纹; 在扩展的选项页上批准它 ([docs/cli.md](./docs/zh-cn/cli.md#登记-pair--revoke--enclave-status))。在同一页面登记你浏览器的认证器是推荐项, 而非必需; [快速入门的加固一节](./docs/zh-cn/quickstart.md#推荐的加固)说明它带来什么。

5. 把你的 MCP 客户端连接到二进制的绝对路径。不带参数运行时, 二进制通过 stdio 说 MCP。

   ```sh
   claude mcp add genkan -- /absolute/path/to/genkan
   ```

   Claude Desktop 以及其他使用 `mcpServers` JSON 的客户端填 `"command": "/ABSOLUTE/PATH/TO/genkan"` 和 `"args": []`; Codex 在 `~/.codex/config.toml` 的 `[mcp_servers.genkan]` 下填同样的两个键。

改为从源码构建: `cargo build --release`, 然后对 `target/release/genkan` 运行同样的 `doctor --fix` ([docs/development.md](./docs/zh-cn/development.md))。在 WSL 上, 安装到浏览器运行的那一侧 ([在 WSL 下运行](./docs/zh-cn/troubleshooting.md#在-wsl-下运行))。

## 你能做什么: 26 个工具

按唯一事实来源, 即 Rust 工具目录 ([`src/packages/core/src/tools/catalogue.rs`](./src/packages/core/src/tools/catalogue.rs)) 分组; 每个工具的影响范围和门禁见[工具风险矩阵](./docs/zh-cn/security/tool-risk-matrix.md)。

| 分组 | 工具 | 风险 |
|---|---|---|
| 浏览器 | `list_browsers` | 低 |
| 标签页 | `tab_list`、`tab_focus`、`tab_open`; `tab_close` 需确认 | 低到高 |
| 导航 | `page_navigate`、`page_back`、`page_forward`、`page_reload` | 低到中 |
| 查看页面 | `page_snapshot`、`page_snapshot_precise`、`page_text`、`page_screenshot`、`console_get` | 低到中 |
| 操作页面 | `page_click`、`page_fill`、`page_press`、`page_select`、`page_hover`、`page_scroll`、`page_wait_for`、`page_handle_dialog`; 提交与链接点击、按键和选择需确认, 对话框处理默认关闭 | 低到高 |
| 运行代码与上传 | `page_eval` (默认关闭; 每次调用都需确认并显示完整代码)、`page_upload` (默认关闭; 每次调用都带路径确认) | 严重 |
| 读取凭据 | `cookie_get` (含 `httpOnly`, 仅限已列入白名单的主机)、`storage_get` (同源); 只读, 始终脱敏 | 高 |

可以同时连接多个浏览器。独自启动其清单的浏览器以自己的标签接入, 共享同一份清单的浏览器则共用中介的默认槽位 ([cli.md](./docs/zh-cn/cli.md#doctor---fix--uninstall-原生消息注册) 说明哪些浏览器共享); 其他每个工具都接受一个可选的 `browser` 参数, 连接了多个浏览器时未指定目标的调用会失败, 而不是去猜测 ([矩阵](./docs/zh-cn/security/tool-risk-matrix.md#横切保护措施))。

Cookie 和 Web 存储按设计只读: 没有 `cookie_set` 或 `storage_set`, 因为伪造的 `httpOnly` Cookie 是会话固定风险 ([矩阵](./docs/zh-cn/security/tool-risk-matrix.md#横切保护措施))。

## 工作原理

一个 Rust 二进制, 两种模式, 由一个经过身份验证的本地套接字连接; CLI 负责管理状态。

```text
MCP client A --stdio--> genkan (broker: first MCP server instance)
MCP client B --stdio--> genkan ----attach----^   |
(each client attested against the trusted-client         | bridge socket
 allowlist before it is served)                          | (Unix-domain socket,
                                                          | or a user-only named pipe
                                                          | on Windows; attestation + HMAC)
                                                          v
                             genkan --native-host   <-- spawned by
                                       |                         each browser
                                       | chrome.runtime.connectNative
                                       v
                             Genkan extension (MV3) --> your page
```

- **MCP 服务器 (默认模式):** 由你的 MCP 客户端通过 stdio 启动; JSON-RPC 2.0, MCP 协议 `2026-07-28`, 无状态, 并为较旧的客户端程序 (harness) 保留临时的旧版兼容 ([architecture.md 3.2](./docs/zh-cn/architecture.md#32-mcp-json-rpc-mcp-服务器---mcp-客户端))。第一个实例持有套接字并成为中介 (broker); 之后的实例作为中继接入 ([5.3](./docs/zh-cn/architecture.md#53-第二个-mcp-客户端接入))。
- **`--native-host`:** 由浏览器通过主机清单启动, 每个浏览器一个, 标签由 [cli.md](./docs/zh-cn/cli.md#doctor---fix--uninstall-原生消息注册) 为该清单给定; 一个薄桥接, 把 Chrome 的原生消息帧转换为套接字上的 NDJSON。
- **CLI:** 基于同一核心的管理界面 (注册、配对、吊销、紧急开关、审计)。它不是信任根; 授予能力的操作最终都要经过用户在场门禁。

浏览器启动原生主机, MCP 客户端启动服务器, 两者不是父子进程, 所以需要 IPC; 主机保持轻薄, 这样 MV3 Service Worker 的回收 (大约每 5 分钟一次) 和主机重启都不会丢失会话状态。深入了解见 [docs/architecture.md](./docs/zh-cn/architecture.md)。

## 配置

启动时读取的环境变量:

| 变量 | 取值 | 默认 | 效果 |
|-----|--------|---------|--------|
| `GENKAN_LOG` | `error` \| `warn` \| `info` \| `debug` | `info` | stderr 日志 / 审计阈值 |
| `GENKAN_LOG_FORMAT` | `text` \| `json` | `text` | 审计行格式; `json` 每行输出一个对象 |

持久化的审计日志 (`genkan audit`) 独立于这些变量进行记录 ([docs/cli.md](./docs/zh-cn/cli.md#日志与审计-genkan_log--genkan_log_format))。

## 文档

文档发布在 <https://vivswan.github.io/genkan/docs/zh-cn/>, 提供英文、简体中文和繁体中文版本; 同样的页面也位于 [docs/](./docs/zh-cn/README.md) 下。

| 我想 | 页面 |
|---|---|
| 安装并连接客户端 | [快速入门](https://vivswan.github.io/genkan/docs/zh-cn/quickstart) |
| 了解某个工具可以做什么 | [工具风险矩阵](https://vivswan.github.io/genkan/docs/zh-cn/security/tool-risk-matrix) |
| 运行 CLI: doctor、配对、受信任客户端、紧急开关、策略、审计 | [CLI](https://vivswan.github.io/genkan/docs/zh-cn/cli) |
| 排查某个症状 | 先运行 `genkan doctor`, 再看[故障排除](https://vivswan.github.io/genkan/docs/zh-cn/troubleshooting); 如果两者都正常, 查看你的 MCP 客户端的服务器界面 (Claude Code 中的 `/mcp`) 和扩展在 `chrome://extensions` 中的 Service Worker 控制台 (`[genkan]` 日志) |
| 知道什么是受信任的, 什么不是 | [安全](https://vivswan.github.io/genkan/docs/zh-cn/security)、[信任边界](https://vivswan.github.io/genkan/docs/zh-cn/security/trust-boundaries)、[设计依据](https://vivswan.github.io/genkan/docs/zh-cn/security/rationale) |
| 看各部分如何组合 | [架构](https://vivswan.github.io/genkan/docs/zh-cn/architecture) |
| 构建、测试或发布它 | [开发](https://vivswan.github.io/genkan/docs/zh-cn/development)、[发布](https://vivswan.github.io/genkan/docs/zh-cn/release) |

## 贡献与治理

[CONTRIBUTING.md](./CONTRIBUTING.md) 是工作流, [GOVERNANCE.md](./GOVERNANCE.md) 说明变更如何产生, [SECURITY.md](./.github/SECURITY.md) 是报告渠道和评审标准, [tests/README.md](./tests/README.md) 则是各测试套件和浏览器安全规则。

## 许可证

[Individual and Small Organization License 1.1.0](./LICENSE.md)。包含来自 [browser-bridge](https://github.com/whg517/browser-bridge) 的代码, 采用 Apache-2.0 许可; 见 [LICENSE-APACHE](./LICENSE-APACHE) 和 [NOTICE](./NOTICE)。
