# chromium-bridge

> English: [README.md](./README.md)

让任意 MCP 客户端 (Claude Code、Claude Desktop、Codex, 或任何支持 Model Context Protocol 的程序) 通过一个浏览器扩展和一个原生消息主机, 操作你真实的 Chromium 浏览器: 你的标签页、你已登录的会话、你的 Cookie。不需要第二个浏览器, 不需要 CDP 调试端口, 也不需要 `--remote-debugging` 标志。

因为它操作的是你已经登录的浏览器, 代理能做到全新无头浏览器做不到的事:

- 读取需要你的身份验证才能访问的页面;
- 在你已登录的应用中逐步点击操作;
- 取出你的框架存放在 `localStorage` 里的令牌。

这种能力同时也是风险。安装前请先阅读[安全优先](#安全优先)。

本项目给自己定下的标准线: 你安装的程序无法在你不知情的情况下使用你的浏览器; 这条线今天在 macOS、Linux 和 Windows 上都成立 ([安全页面](./docs/zh-cn/security.md)阐述了它, 以及它止步于何处)。

## 安全优先

chromium-bridge 操作的是一个真实的、已通过身份验证的浏览器。它可以读取页面内容、Cookie (包括 `httpOnly`) 和 Web 存储, 还可以在你的页面中运行 JavaScript。护栏如下:

- **批准每一个站点。** 新的源 (origin) 会触发提示; 未经你批准的站点上什么都不会运行。
- **确认高风险操作。** 提交点击、按键、关闭标签页、文件上传, 以及每一次 `page_eval`, 都要在一个由扩展拥有、页面既看不到也点不到的窗口上确认。`page_eval` 和 `page_upload` 每次调用都重新确认。同一用户下的程序围绕这个窗口仍能做什么, 见[信任边界台账](./docs/zh-cn/security/trust-boundaries.md#边界-4-扩展---网页-chrome-api--内容脚本--dom)。
- **门禁默认开启。** 每一道门禁都是有文档记录的设置, 放宽任何一道都是一次明确、知情的选择 ([SECURITY.md](./.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe))。
- **凭据只读。** Cookie 和存储可以读取 (始终脱敏: JWT、长十六进制串、长数字串), 但永远不能写入。按设计就没有 `cookie_set` 或 `storage_set`。
- **经过身份验证与证明的桥接。** 在 macOS 和 Linux 上, 主机进程之间通过一个私有的 Unix 域套接字通信 (没有监听端口)。每个连接都必须通过内核对端 UID 检查、由内核证明的可执行文件身份, 以及基于每次运行密钥的 HMAC 质询。
- **受信任客户端白名单。** MCP 客户端按一份以经证明的代码身份为键的白名单准入, 任何一方都可以随时吊销信任。
- **全局紧急开关 (kill switch)。** 在 CLI 或扩展中执行一次操作即可中止一切, 直到你以在场证明解除为止。每一个安全决策都会落入磁盘上的审计日志。

**平台如实说明。** 桥接的保证在 macOS、Linux 和 Windows 上都成立; 各系统背后的机制各不相同 ([SECURITY.md](./.github/SECURITY.md#platform-support))。

| 平台 | 桥接传输 | 连接的门禁 |
|---|---|---|
| macOS、Linux | 私有 Unix 域套接字, 无监听端口 | 对端 UID 检查、内核证明、HMAC 质询 |
| Windows | 只有你的用户能打开的命名管道, 无监听端口 | 管道的描述符 (内核强制)、双向证明、HMAC 质询 |

完整细节: [SECURITY.md](./.github/SECURITY.md)、[安全页面](./docs/zh-cn/security.md)、[信任边界](./docs/zh-cn/security/trust-boundaries.md)、[逐工具风险矩阵](./docs/zh-cn/security/tool-risk-matrix.md)。

## 使用 CLI 快速入门 (macOS、Linux、Windows)

CLI 除了二进制本身不需要任何东西, 在桌面机、无头机器和 CI 上都一样。今天唯一的例外是 macOS 上的配对, 它需要一个带应用标识符代码签名的构建; WebAuthn 在场方案将移除这一要求。

1. 从[最新发布](https://github.com/Vivswan/chromium-bridge/releases/latest)下载你平台对应的压缩包并解压。可以先校验一下; 在 macOS/Linux 上 (Windows 压缩包是 `.zip`, 用你自己的 sha256 工具检查):

   ```sh
   shasum -a 256 -c chromium-bridge-<tag>-<platform>-<arch>.tar.gz.sha256
   gh attestation verify chromium-bridge-<tag>-<platform>-<arch>.tar.gz --repo Vivswan/chromium-bridge
   ```

   完整的校验说明见 [SECURITY.md](./.github/SECURITY.md#release-artifact-integrity)。

2. 把解压出的二进制注册到你的浏览器。注册是幂等的, 所以同一条命令既是全新安装, 也是修复, 也是移动二进制后的重新注册:

   ```sh
   ./chromium-bridge doctor --fix          # every detected browser
   ./chromium-bridge doctor --fix --browser chrome,brave
   ```

   把二进制放在一个稳定的路径上 (它是就地注册的)。在 Linux 上, `~/.local/lib/chromium-bridge/` 是个不错的位置。`chromium-bridge uninstall` 会精确撤销所注册的内容。

3. 加载扩展: 在 `chrome://extensions` 开启开发者模式, 点「加载已解压的扩展程序」, 选择压缩包里的 `extension/dist` 目录。然后重启浏览器。扩展需要 Chrome 134 或更新版本; 更旧的浏览器会拒绝加载它。

4. 在 macOS 上进行配对: 运行 `chromium-bridge pair` (Touch ID), 然后在扩展的选项页上批准指纹; 扩展默认要求在那里完成登记。Linux 和 Windows 跳过这一步。

5. 按下文所述, 把你的 MCP 客户端连接到解压出的二进制 (绝对路径)。

改为从源码构建: `cargo build --release`, 然后对 `target/release/chromium-bridge` 运行同样的 `doctor --fix` (见 [docs/development.md](./docs/zh-cn/development.md))。

完整的 CLI (doctor、配对、吊销、紧急开关、审计) 记录在 [docs/cli.md](./docs/zh-cn/cli.md) 中。

## 连接你的 MCP 客户端

把你的客户端指向已安装的二进制。不带参数运行时, 它通过 stdio 说 MCP。使用绝对路径; 大多数客户端不会展开 `~`。

Claude Code:

```sh
claude mcp add chromium-bridge -- "$HOME/.local/bin/chromium-bridge"
```

Claude Desktop 以及其他使用 `mcpServers` JSON 的客户端:

```json
{
  "mcpServers": {
    "chromium-bridge": {
      "command": "/ABSOLUTE/PATH/TO/chromium-bridge",
      "args": []
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.chromium-bridge]
command = "/absolute/path/to/chromium-bridge"
args = []
```

可以同时连接多个客户端: 第一个服务器实例成为中介 (broker), 之后的实例接入它, 每一个都经过证明并可单独吊销。

在 WSL 上, 安装到浏览器运行的那一侧 ([在 WSL 下运行](./docs/zh-cn/troubleshooting.md#在-wsl-下运行)):

- 日常使用 Windows Chrome: 安装在 Windows 上, 让 WSL 客户端通过 `/mnt/c` 指向 `.exe`; 不要安装 Linux 主机。
- WSLg 下的 Chrome: 在 Linux 中原生安装。

## 你能做什么: 26 个工具

按唯一事实来源, 即 Rust 工具目录 ([`src/packages/core/src/tools/catalogue.rs`](./src/packages/core/src/tools/catalogue.rs)) 分组。每个工具完整的影响范围细节见[工具风险矩阵](./docs/zh-cn/security/tool-risk-matrix.md)。

### 浏览器

| 工具 | 作用 | 风险 |
|------|------|------|
| `list_browsers` | 列出连接到桥接的浏览器 (标签 + 打开的标签页数) | 低 |

可以同时连接多个浏览器; 在 macOS/Linux 上, 每个浏览器都有自己的原生消息主机和标签 (例如 `chrome` 和 `brave`)。其他每个工具都接受一个可选的 `browser` 参数来指定其一。连接了多个浏览器时, 未指定目标的调用会以明确的错误失败, 而不是去猜测该在哪个已登录的浏览器里操作。

### 标签页

| 工具 | 作用 | 风险 |
|------|------|------|
| `tab_list` | 列出打开的标签页 (id、标题、url、是否活动) | 低 |
| `tab_focus` | 把一个标签页带到前台 | 低 |
| `tab_open` | 在新标签页中打开 URL (主机名必须在白名单中) | 中 |
| `tab_close` | 关闭一个标签页 (确认窗口) | 高 |

### 导航

| 工具 | 作用 | 风险 |
|------|------|------|
| `page_navigate` | 在活动标签页中加载一个 http(s) URL | 中 |
| `page_back` / `page_forward` | 在历史记录中前进后退 | 低 |
| `page_reload` | 重新加载活动标签页 | 低 |

### 查看页面

| 工具 | 作用 | 风险 |
|------|------|------|
| `page_snapshot` | 交互元素的无障碍风格树, 每个元素带一个稳定的 `ref` | 低 |
| `page_snapshot_precise` | 通过 `chrome.debugger` 获取权威的 a11y 树 (shadow DOM / 复杂 ARIA); ref 使用 `p` 前缀 | 中 |
| `page_text` | 页面可见文本 (密码和类似卡号的数字已脱敏) | 中 |
| `page_screenshot` | 可见视口的 PNG 截图 | 中 |
| `console_get` | 最近的控制台输出, 已脱敏 | 中 |

### 操作页面

| 工具 | 作用 | 风险 |
|------|------|------|
| `page_click` | 按 `ref` 或 `selector` 点击; 提交/链接点击需要确认 | 高 |
| `page_fill` | 向字段输入文本 (使用原生 setter, 因此 React/Vue 能检测到) | 高 |
| `page_press` | 发送一个按键或组合键 (确认) | 高 |
| `page_select` | 在 `<select>` 中选择一个选项 (确认) | 高 |
| `page_hover` | 把指针移到某个元素上 | 低 |
| `page_scroll` | 上 / 下 / 顶部 / 底部 / N 像素 | 低 |
| `page_wait_for` | 等待选择器、文本或导航 | 低 |
| `page_handle_dialog` | 接受或关闭 JS 对话框 (默认关闭) | 高 |

### 运行代码与上传 (风险最高)

| 工具 | 作用 | 风险 |
|------|------|------|
| `page_eval` | 执行任意 JS。每次调用都要确认并显示完整代码; 已登记的 Mac 上需要 Touch ID。返回值默认脱敏。优先使用上面的工具。 | 严重 |
| `page_upload` | 把指定的本地文件附加到文件输入框 (默认关闭; 每次调用都带路径确认) | 严重 |

### 读取凭据 (只读, 始终脱敏)

| 工具 | 作用 | 风险 |
|------|------|------|
| `cookie_get` | 读取活动标签页的 Cookie, 含 `httpOnly`; 仅限白名单中的主机名 | 高 |
| `storage_get` | 读取页面的 `localStorage` / `sessionStorage` (同源) | 高 |

按设计没有写入工具; Cookie/存储的写入不在范围内: 伪造的 httpOnly Cookie 是会话固定风险 ([工具风险矩阵](./docs/zh-cn/security/tool-risk-matrix.md)给出了完整理由)。

## 工作原理

一个 Rust 二进制, 两种模式, 由一个经过身份验证的本地套接字连接。CLI 负责管理状态。

```
MCP client A --stdio--> chromium-bridge (broker: first MCP server instance)
MCP client B --stdio--> chromium-bridge ----attach----^   |
(each client attested against the trusted-client         | bridge socket
 allowlist before it is served)                          | (Unix-domain socket,
                                                          | or a user-only named pipe
                                                          | on Windows; attestation + HMAC)
                                                          v
                             chromium-bridge --native-host   <-- spawned by
                                       |                         each browser
                                       | chrome.runtime.connectNative
                                       v
                             Chromium Bridge extension (MV3) --> your page
```

- **MCP 服务器 (默认模式)**: 由你的 MCP 客户端通过 stdio 启动。说 JSON-RPC 2.0 (MCP 协议 `2026-07-28`, 无状态, 并为较旧的客户端程序 (harness) 保留临时的旧版兼容)。
  - 第一个实例持有套接字并成为中介; 之后的实例作为中继接入, 因此多个客户端可以并发共享浏览器。
- **`--native-host`**: 由浏览器通过主机清单启动。一个薄桥接, 把 Chrome 的原生消息帧转换为套接字上的 NDJSON。
  - 每个已安装的浏览器都启动自己的主机并带有自己的标签, 因此一个中介可以按名称寻址多个浏览器。
- **CLI**: 基于同一核心的管理界面 (注册、配对、吊销、紧急开关、审计)。它不是信任根; 授予能力的操作最终都要经过用户在场门禁。

**为什么是两个进程?** 浏览器启动原生消息主机, MCP 客户端启动服务器, 两者不是父子进程, 所以需要 IPC。原生消息主机保持轻薄, 这样 MV3 Service Worker 的回收 (大约每 5 分钟一次) 和主机重启都不会丢失会话状态。

深入了解: [docs/architecture.md](./docs/zh-cn/architecture.md)。

## 兼容性

| | 支持情况 |
|---|---|
| macOS | Apple Silicon (arm64) 预构建; Touch ID 门禁在这里。Intel 从源码构建。 |
| Linux | x64 预构建; 任何基于 Chromium 的浏览器; CLI 管理界面。 |
| Windows | x64 预构建 (原生, 无需管理员权限)。桥接是带双向证明的用户专属命名管道; 见 [SECURITY.md](./.github/SECURITY.md#platform-support)。 |
| 浏览器 | 任何基于 Chromium 的浏览器, Manifest V3 |
| MCP 协议 | `2026-07-28` |
| 内部桥接协议 | `1` ([src/packages/core/src/protocol.rs](./src/packages/core/src/protocol.rs) 中的 `BRIDGE_PROTOCOL_VERSION`) |

已知浏览器 (`--browser` 键): `chrome`、`chromium`、`brave`、`edge`、`vivaldi`、`opera`。所有 Chromium 浏览器读取同一份原生消息清单; 只有每用户的 `NativeMessagingHosts` 位置不同, 核心中的共享解析器全都认识。

对于不在该列表中的 Chromium 变体, `doctor --fix --manifest-dir <dir>` 可以显式指定其目录 (macOS/Linux; 在 Windows 上注册是一个 HKCU 注册表键)。见 [docs/cli.md](./docs/zh-cn/cli.md)。

## 配置

启动时读取的环境变量:

| 变量 | 取值 | 默认 | 效果 |
|-----|--------|---------|--------|
| `BB_LOG` | `error` \| `warn` \| `info` \| `debug` | `info` | stderr 日志 / 审计阈值 |
| `BB_LOG_FORMAT` | `text` \| `json` | `text` | 审计行格式; `json` 每行输出一个对象 |

持久化的审计日志 (`chromium-bridge audit`) 独立于这些变量进行记录; 见 [docs/cli.md](./docs/zh-cn/cli.md#日志与审计-bb_log--bb_log_format)。

## 故障排除

先运行内置的只读自检:

```sh
chromium-bridge doctor    # or: chromium-bridge status
```

它会报告服务器是否可达、锁文件状态、紧急开关, 以及每个浏览器的注册状态; `doctor --fix` 会就地修复注册。如果这些都正常, 再检查:

- 你的 MCP 客户端的服务器界面 (在 Claude Code 中通过 `/mcp` 重新连接);
- 扩展在 `chrome://extensions` 中的 Service Worker 控制台 (查找 `[bb]` 日志)。

完整手册: [docs/cli.md](./docs/zh-cn/cli.md) 和 [docs/troubleshooting.md](./docs/zh-cn/troubleshooting.md)。

## 文档地图

| 文档 | 内容 |
|-----|--------------|
| [docs/quickstart.md](./docs/zh-cn/quickstart.md) | 安装与首次使用 |
| [docs/architecture.md](./docs/zh-cn/architecture.md) | 组件、数据流、协议、安全模型、关键约束 |
| [docs/security/](./docs/zh-cn/security/) | 信任边界台账、工具风险矩阵、设计依据、事件响应; 面向读者的页面是 [docs/security.md](./docs/zh-cn/security.md) |
| [docs/cli.md](./docs/zh-cn/cli.md) | 完整的 CLI: doctor/--fix、uninstall、配对、吊销、紧急开关、审计 |
| [docs/troubleshooting.md](./docs/zh-cn/troubleshooting.md) | 逐个症状排查: doctor 各行、紧急开关记录恢复、版本不一致、两种 WSL 模式 |
| [docs/release.md](./docs/zh-cn/release.md) | release-please 发布、预构建压缩包 + 校验和、SBOM、哪个版本何时变动 |
| [docs/security/rationale.md](./docs/zh-cn/security/rationale.md) | 每个安全决策为何如此, 以及否决了什么 |

<details>
<summary>测试与项目布局</summary>

跨两种语言的独立测试套件 ([tests/README.md](./tests/README.md)):

| 套件 | 位置 | 作用 |
|---|---|---|
| 协议 | `tests/protocol/e2e.py` (加上 `adversarial.py` 和 `chaos.py`) | 通过真实的线上协议驱动真实的二进制 |
| DOM | `tests/browser/dom_test.ts` | 通过 CDP 把真实的内容脚本注入隔离的 Chrome, 对真实 DOM 逐个运行每种操作 |
| 冒烟 | `tests/browser/ext_test.ts` | 用构建好的扩展启动一个隔离的 Chrome |
| 真实集成 (可选启用) | `tests/browser/integration_e2e.ts` 配合 `BB_REAL_E2E=1` | 对真实环境做端到端测试 |

布局:

| 路径 | 内容 |
|---|---|
| `src/apps/host` | Rust 二进制 |
| `src/apps/extension` | MV3 扩展 (WXT) |
| `src/packages/core` | Rust 库, 以及跨进程契约的唯一来源 |
| `src/packages/shared` | 生成的 TS 契约 + 校验器 |

</details>

## 项目状态

1.0 之前 ([Cargo.toml](./Cargo.toml))。协议层由端到端、对抗性和混沌测试覆盖; 线上协议解析器经过模糊测试。见 [CHANGELOG.md](./CHANGELOG.md)。

## 贡献与治理

[CONTRIBUTING.md](./CONTRIBUTING.md) (工作流)、[GOVERNANCE.md](./GOVERNANCE.md) (变更如何产生)、[SECURITY.md](./.github/SECURITY.md) (报告 + 评审标准)、[docs/development.md](./docs/zh-cn/development.md) (构建/测试/发布循环)。

## 许可证

[Individual and Small Organization License 1.0.0](./LICENSE.md)。包含来自 [browser-bridge](https://github.com/whg517/browser-bridge) 的代码, 采用 Apache-2.0 许可; 见 [LICENSE-APACHE](./LICENSE-APACHE) 和 [NOTICE](./NOTICE)。
