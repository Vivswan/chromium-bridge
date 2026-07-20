# chromium-bridge

> 本文是英文 [README](./README.md) 的简体中文翻译。以英文版为准;
> 繁體中文版见 [README.zh_TW.md](./README.zh_TW.md)。

让任何 MCP 客户端 (Claude Code、Claude Desktop、Codex, 或任何支持
Model Context Protocol 的程序) 驱动你真实的 Chromium 浏览器: 你的标签页、
你已登录的会话、你的 Cookie, 通过一个浏览器扩展加一个原生消息主机
(native messaging host) 实现。不需要第二个浏览器, 不需要 CDP 调试端口,
不需要 `--remote-debugging` 参数。

因为它操作的是你已经登录的浏览器, 代理 (agent) 能做到全新无头浏览器做不到
的事: 读取需要登录才能看的页面、在你已登录的应用里点击操作、取出前端框架
存在 `localStorage` 里的令牌。这份能力同时也是风险所在。安装前请先阅读下面
的安全部分。

## 安全第一

chromium-bridge 驱动的是一个真实的、已通过身份验证的浏览器。它能读取页面
内容、Cookie (包括 `httpOnly`) 和 Web 存储, 并能在你的页面里执行
JavaScript。相应的防护措施:

- **逐站点批准。** 新的源 (origin) 会触发确认提示; 未经你批准的站点上什么
  都不会执行。
- **高风险操作需确认。** 提交点击、按键、关闭标签页、文件上传, 以及每一次
  `page_eval`, 都要在一个页面无法看见、无法点击的扩展自有窗口中确认。在已
  完成 Touch ID 注册的 Mac 上, `page_eval` 和 `page_upload` 的批准是一次
  Secure Enclave 的 Touch ID 触按, 任何页面或程序都无法伪造
  ([ADR-0031](./docs/adr/0031-touch-id-confirmations-and-presence-grants.md))。
- **凭据只读。** Cookie 和存储只能读取 (且始终脱敏: JWT、长十六进制串、长
  数字串), 永远不能写入。设计上不存在 `cookie_set` 或 `storage_set`。
- **经过认证与证明的桥接。** 在 macOS 和 Linux 上, 主机进程之间的桥接是一
  个私有的 Unix 域套接字 (没有监听端口)。每个连接都必须通过内核对端 UID
  检查、内核认证的可执行文件身份, 以及基于每次运行随机密钥的 HMAC 质询。
  MCP 客户端本身要对照一份以认证代码身份为键的受信客户端允许列表获得准入,
  任何一方都可以随时吊销信任
  ([ADR-0024](./docs/adr/0024-multi-client-attested-pairing-and-broker.md)、
  [ADR-0025](./docs/adr/0025-any-side-revocation-epoch.md))。
- **全局紧急停止开关。** 在 CLI、扩展或桌面应用中的一个动作即可停止一切,
  直到你以在场证明 (proof of presence) 显式解除
  ([ADR-0030](./docs/adr/0030-global-kill-switch-and-audit.md))。每一个安全
  决策都会写入磁盘上的审计日志。

平台差异, 如实说明: 强桥接保证 (无端口套接字、对端 UID 检查、身份证明) 仅
存在于 macOS 和 Linux。在 Windows 上, 桥接是一个仅由 HMAC 密钥把守的环回
TCP 套接字, 服务器启动时会对此发出警告。Windows 支持是尽力而为。详见
[SECURITY.md](./SECURITY.md#platform-support)。

完整细节: [SECURITY.md](./SECURITY.md)、
[威胁模型](./docs/security/threat-model.md)、
[信任边界](./docs/security/trust-boundaries.md)、
[逐工具风险矩阵](./docs/security/tool-risk-matrix.md)。

## 使用桌面应用快速上手 (macOS)

Chromium Bridge 桌面应用是首选安装路径。它内置了已签名的主机二进制和扩展;
这条路径里唯一的命令, 是把服务器注册给 MCP 客户端的那一条。

> 应用安装包尚未发布 (当前发布版只含 CLI 压缩包)。在此之前, 请在源码检出
> 中用 `moon run run-app` 构建并启动应用, 或使用下面的 CLI 路径。

1. **安装应用。** 获取 `Chromium Bridge.app` (见上面的说明) 并打开。首次启
   动时它会向检测到的每一个 Chromium 系浏览器 (Chrome、Brave、Edge 等) 注
   册原生消息主机, 并展示它写入了什么。
2. **加载扩展。** 在应用的 Setup 页点击 "Reveal folder" 打开内置扩展目录,
   然后在浏览器中打开 `chrome://extensions`, 启用开发者模式, 点击
   "加载已解压的扩展程序", 选择该目录。重启浏览器使注册生效。
3. **用 Touch ID 配对。** 在应用的 Pairing 页点击 Pair (会弹出 Touch ID),
   然后在扩展的选项页核对并批准密钥指纹。macOS 上扩展默认要求完成此注册,
   在指纹匹配之前拒绝执行任何操作
   ([ADR-0021](./docs/adr/0021-enrollment-ceremony.md))。
4. **接入你的 MCP 客户端。** 在 Setup 页点击 Install, 将 `chromium-bridge`
   命令安装到 `~/.local/bin`, 然后在客户端里注册它。以 Claude Code 为例:

   ```sh
   claude mcp add chromium-bridge -- "$HOME/.local/bin/chromium-bridge"
   ```

   其他客户端以同一个二进制作为 `mcpServers` 条目; 见英文 README 的
   [Connect your MCP client](./README.md#connect-your-mcp-client)。

让客户端"列出我的浏览器标签页"试试。第一次操作新站点时, 点击 Chromium
Bridge 工具栏图标并批准该站点。

装好之后应用仍然有用: 它是配对、受信客户端、紧急停止开关和审计日志的控制
面板, 危险操作在已注册的 Mac 上由 Touch ID 把守。见
[docs/desktop-app.md](./docs/desktop-app.md)。

## 使用 CLI 快速上手 (macOS、Linux、Windows)

CLI 与桌面应用地位对等: 应用能做的它都能做, 只依赖二进制本身。在 Linux、
Windows、无界面机器和 CI 上它是自然选择。

1. 从[最新发布版](https://github.com/Vivswan/chromium-bridge/releases/latest)
   下载对应平台的压缩包并解压。建议先校验; macOS/Linux 示例如下 (Windows
   压缩包是 `.zip`, 请用你自己的 sha256 工具核对; 详见
   [SECURITY.md](./SECURITY.md#release-artifact-integrity)):

   ```sh
   shasum -a 256 -c chromium-bridge-<tag>-<platform>-<arch>.tar.gz.sha256
   gh attestation verify chromium-bridge-<tag>-<platform>-<arch>.tar.gz --repo Vivswan/chromium-bridge
   ```

2. 把解压出的二进制注册给你的浏览器。注册是幂等的, 同一条命令既是全新安装,
   也是修复, 也是移动二进制后的重新注册:

   ```sh
   ./chromium-bridge doctor --fix          # 每一个检测到的浏览器
   ./chromium-bridge doctor --fix --browser chrome,brave
   ```

   把二进制放在一个稳定路径 (注册指向它所在的位置)。在 Linux 上,
   `~/.local/lib/chromium-bridge/` 是个好去处。`chromium-bridge uninstall`
   会精确撤销注册过的内容。

3. 加载扩展: 通过 `chrome://extensions` (开发者模式, "加载已解压的扩展程
   序") 加载压缩包里的 `extension/dist/` 目录。重启浏览器。

4. 在 macOS 上配对: 运行 `chromium-bridge pair` (会弹出 Touch ID), 然后在
   扩展的选项页批准指纹; macOS 上扩展默认要求完成此注册。Linux 和 Windows
   跳过这一步。

5. 将你的 MCP 客户端指向解压出的二进制 (绝对路径), 方法同上。

从源码构建: `cargo build --release`, 然后用
`target/release/chromium-bridge` 运行同样的 `doctor --fix` (见
[docs/development.md](./docs/development.md))。

完整的 CLI (doctor、配对、吊销、紧急停止开关、审计) 见
[docs/cli.md](./docs/cli.md)。安装与首次使用的完整指南 (含翻译) 见
[docs/quickstart.zh_CN.md](./docs/quickstart.zh_CN.md)。

## 你能做什么: 26 个工具

以 Rust 工具目录
([`src/packages/core/src/tools/catalogue.rs`](./src/packages/core/src/tools/catalogue.rs))
为唯一事实来源。逐工具的影响范围详见
[工具风险矩阵](./docs/security/tool-risk-matrix.md)。

### 浏览器

| 工具 | 作用 | 风险 |
|------|------|------|
| `list_browsers` | 列出连接到桥的浏览器 (标签 + 打开的标签页数) | 低 |

可以同时连接多个浏览器 (在 macOS/Linux 上每个浏览器有自己的原生主机和标
签, 例如 `chrome` 和 `brave`)。其他每个工具都接受可选的 `browser` 参数来指
定; 连接多个时, 未指定的调用会以明确错误失败, 而不是猜测该在哪个已登录浏览
器里操作。见 [ADR-0022](./docs/adr/0022-multi-browser-label-routing.md)。

### 标签页

| 工具 | 作用 | 风险 |
|------|------|------|
| `tab_list` | 列出打开的标签页 (id、标题、url、是否活动) | 低 |
| `tab_focus` | 将标签页切到前台 | 低 |
| `tab_open` | 在新标签页打开 URL (主机必须在允许列表内) | 中 |
| `tab_close` | 关闭标签页 (确认窗口) | 高 |

### 导航

| 工具 | 作用 | 风险 |
|------|------|------|
| `page_navigate` | 在活动标签页加载 http(s) URL | 中 |
| `page_back` / `page_forward` | 在历史记录中前进/后退 | 低 |
| `page_reload` | 重新加载活动标签页 | 低 |

### 检查页面

| 工具 | 作用 | 风险 |
|------|------|------|
| `page_snapshot` | 交互元素的无障碍树近似, 每个元素带稳定 `ref` | 低 |
| `page_snapshot_precise` | 经 `chrome.debugger` 的权威无障碍树 (shadow DOM / 复杂 ARIA); ref 用 `p` 前缀 | 中 |
| `page_text` | 页面可见文本 (密码和类似卡号的数字脱敏) | 中 |
| `page_screenshot` | 可见视口的 PNG 截图 | 中 |
| `console_get` | 最近的控制台输出 (脱敏) | 中 |

### 操作页面

| 工具 | 作用 | 风险 |
|------|------|------|
| `page_click` | 按 `ref` 或 `selector` 点击; 提交/链接点击需确认 | 高 |
| `page_fill` | 在输入框中输入 (原生 setter, React/Vue 能感知) | 高 |
| `page_press` | 发送按键或组合键 (需确认) | 高 |
| `page_select` | 在 `<select>` 中选择选项 (需确认) | 高 |
| `page_hover` | 将指针移到元素上 | 低 |
| `page_scroll` | 上 / 下 / 顶部 / 底部 / N 像素 | 低 |
| `page_wait_for` | 等待选择器、文本或导航 | 低 |
| `page_handle_dialog` | 接受或关闭 JS 对话框 (默认关闭) | 高 |

### 运行代码与上传 (最高风险)

| 工具 | 作用 | 风险 |
|------|------|------|
| `page_eval` | 执行任意 JS。每次调用都确认并显示完整代码; 已注册的 Mac 上是 Touch ID。返回值默认脱敏。优先使用上面的工具。 | 危急 |
| `page_upload` | 把指定的本地文件附加到文件输入框 (默认关闭; 每次调用都确认并显示路径) | 危急 |

### 读取凭据 (只读, 始终脱敏)

| 工具 | 作用 | 风险 |
|------|------|------|
| `cookie_get` | 读取活动标签页的 Cookie, 含 `httpOnly`; 仅限允许列表内的主机 | 高 |
| `storage_get` | 读取页面的 `localStorage` / `sessionStorage` (同源) | 高 |

设计上没有写入工具; Cookie/存储写入不在范围内
([ADR-0010](./docs/adr/0010-cookie-storage-readonly.md))。

## 工作原理

一个 Rust 二进制、两种模式, 由一条经过认证的本地套接字连接。桌面应用和
CLI 管理同一份状态。

- **MCP 服务器 (默认模式)**: 由你的 MCP 客户端通过 stdio 启动, 说
  JSON-RPC 2.0 (MCP 协议 `2025-06-18`)。第一个实例持有套接字并成为
  broker (中枢); 后续实例作为中继接入, 多个客户端并发共享浏览器。
- **`--native-host`**: 由浏览器按主机清单启动, 是把 Chrome 原生消息帧转成
  套接字上 NDJSON 的薄桥。每个安装的浏览器用自己的标签启动自己的主机, 一个
  broker 可以按名字寻址多个浏览器。
- **桌面应用 / CLI**: 基于同一个核心的对等管理面 (注册、配对、吊销、紧急停
  止开关、审计)。两者都不是信任根; 授予能力的操作最终都落在一次用户在场
  验证上。

为什么是两个进程? 浏览器负责拉起原生主机, MCP 客户端负责拉起服务器。两者
不是父子进程, 所以需要一条 IPC。原生主机保持轻薄, 这样 MV3 服务工作线程的
回收 (约每 5 分钟) 和主机重启都不会丢失会话状态。

深入阅读: [docs/architecture.md](./docs/architecture.md)。

## 兼容性

| | 支持情况 |
|---|---|
| macOS | Apple Silicon (arm64) 预编译; 桌面应用和 Touch ID 门在这里。Intel 需从源码构建。 |
| Linux | x64 预编译; 任何 Chromium 系浏览器; 用 CLI 管理。 |
| Windows | x64 预编译 (原生, 无需管理员)。桥接安全性为尽力而为; 见 [SECURITY.md](./SECURITY.md#platform-support)。 |
| 浏览器 | 任何 Chromium 系浏览器, Manifest V3 |
| MCP 协议 | `2025-06-18` ([ADR-0007](./docs/adr/0007-mcp-protocol-version-2025-06-18.md)) |
| 内部桥协议 | `1` ([src/packages/core/src/protocol.rs](./src/packages/core/src/protocol.rs) 中的 `BRIDGE_PROTOCOL_VERSION`) |

已知浏览器 (`--browser` 键): `chrome`、`chromium`、`brave`、`edge`、
`vivaldi`、`opera`。不在表内的 Chromium 变体可用
`doctor --fix --manifest-dir <dir>` 显式指定其目录。见
[docs/compatibility.md](./docs/compatibility.md) 和
[docs/cli.md](./docs/cli.md)。

## 配置

启动时读取的环境变量:

| 变量 | 取值 | 默认 | 作用 |
|------|------|------|------|
| `BB_LOG` | `error` \| `warn` \| `info` \| `debug` | `info` | stderr 日志 / 审计阈值 |
| `BB_LOG_FORMAT` | `text` \| `json` | `text` | 审计行格式; `json` 每行一个对象 |

持久审计日志 (`chromium-bridge audit`) 独立于这两个变量记录; 见
[docs/cli.md](./docs/cli.md#logging-and-audit-bb_log--bb_log_format)。

## 排障

先运行内置的只读自检:

```sh
chromium-bridge doctor    # 或: chromium-bridge status
```

它报告服务器是否可达、锁文件状态、紧急停止开关状态, 以及每个浏览器的注册
状态; `doctor --fix` 就地修复注册。然后检查 MCP 客户端的服务器界面 (Claude
Code 里用 `/mcp` 重连) 和 `chrome://extensions` 里扩展的 Service Worker 控
制台 (找 `[bb]` 日志)。完整手册: [docs/cli.md](./docs/cli.md) 和
[docs/operations.md](./docs/operations.md)。

## 文档地图

| 文档 | 内容 |
|------|------|
| [docs/quickstart.zh_CN.md](./docs/quickstart.zh_CN.md) | 安装与首次使用 (应用 + CLI) |
| [docs/architecture.md](./docs/architecture.md) | 组件、数据流、协议、安全模型、关键约束 |
| [docs/security/](./docs/security/) | 威胁模型、信任边界、工具风险矩阵、事件响应 |
| [docs/cli.md](./docs/cli.md) | 完整 CLI: doctor/--fix、uninstall、配对、吊销、紧急停止开关、审计 |
| [docs/desktop-app.md](./docs/desktop-app.md) | 桌面应用: 管理什么、如何验证 |
| [docs/operations.md](./docs/operations.md) | 二进制模式、日志/审计、运行时目录、重连 |
| [docs/privacy-policy.zh_CN.md](./docs/privacy-policy.zh_CN.md) | 扩展的隐私政策 |
| [docs/adr/](./docs/adr/) | 架构决策记录: 每一个"为什么这么选" |

## 项目状态

1.0 之前 ([Cargo.toml](./Cargo.toml))。协议层由端到端、对抗性和混沌测试覆
盖; 线格式解析器经过模糊测试。见 [CHANGELOG.md](./CHANGELOG.md)。

## 贡献与治理

[CONTRIBUTING.md](./CONTRIBUTING.md) (工作流)、
[GOVERNANCE.md](./GOVERNANCE.md) (变更如何发生)、
[SECURITY.md](./SECURITY.md) (报告 + 审查标准)、
[docs/development.md](./docs/development.md) (构建/测试/发布)。

## 许可证

[Apache-2.0](./LICENSE)。版权归 browser-bridge 贡献者所有。
