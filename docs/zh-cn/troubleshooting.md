# 故障排除

每个条目都从只读自检开始, 它不会改变任何东西:

```sh
chromium-bridge doctor    # or: chromium-bridge status
```

`doctor` 每一行输出的含义见 [CLI 页面](cli.md#doctor--status-只读自检)。

## doctor 显示「server not reachable」

- **你看到:** `doctor` 从锁文件读到了一个端点, 但它的「连接即断开」探测失败了。
- **含义:** 没有任何 MCP 客户端会话在运行, 因此没有进程在监听; 或者之前的中介 (broker) 留下了一个过期的锁文件。
- **怎么做:** 在你的 MCP 客户端中打开或重新连接一个会话。下一个服务器实例会在启动时替换过期的锁; `doctor` 从不清理它、杀死进程或重启服务器 ([CLI 页面解释了这个探测](cli.md#如何理解server-not-reachable))。

## doctor 显示某个注册缺失或过期

- **你看到:** 某个浏览器的注册行显示 `missing` 或 `stale`。
- **含义:** 那个浏览器无法启动原生消息主机: 没有为它注册任何内容, 或者已注册的内容已损坏, 该行会说明是哪一种 (悬空的启动路径, 或在 Windows 上缺失的注册表键)。
- **怎么做:** 运行 `chromium-bridge doctor --fix`, 然后重启浏览器 ([CLI 页面上的注册说明](cli.md#doctor---fix--uninstall-原生消息注册))。

## doctor 显示紧急开关状态或信任记录不可读

- **你看到:** `kill state unreadable - failing closed`, 或者 `kill` 与 `unkill` 拒绝写入; `doctor` 以非零状态退出。
- **含义:** 运行时目录中的 `trust.json` 无法读取; 这个文件保存着紧急开关 (kill switch) 的闩锁状态和受信任客户端白名单, 无法读取的原因可能是 JSON 损坏、未知字段或权限错误。每个执行点读取它时都失败即关闭, 因此工具调用会以 `BRIDGE_KILLED` 被拒绝, 浏览器连接被切断, 新实例拒绝启动。
- **怎么做:** 按下面的顺序手动恢复。从一个你无法读取的状态解除开关会变成失败即开放, 而静默重建文件会掩盖篡改, 所以这两件事都不会替你自动完成。

1. 运行 `chromium-bridge doctor` 确认状态并找到运行时目录。
2. 在动手之前先查看 `trust.json`。无法解释的损坏 (没有写入途中的崩溃, 也没有磁盘故障) 可能是篡改的迹象: 先阅读[事件响应](security/incident-response.md)。
3. 删除 `trust.json`。这相当于把客户端程序 (harness) 信任恢复出厂设置, 回到会大声记录日志的未登记引导状态; 已配对的客户端也随之清除。
4. 重新配对每个受信任客户端 (`chromium-bridge pair-client`), 如果之前启用了紧急开关, 也重新启用它。扩展的登记固定不受影响: 主机密钥从未存放在这条记录里。

## doctor 报告 `policy baseline: none yet`

- **你看到:** `policy baseline:` 这一行显示 `none yet`。
- **含义:** 这是切换前的健康状态。尚未写入任何已签名的基线, 因此扩展执行拒绝基线: 所有能力授予关闭, 所有确认开启。这一行从不改变 `doctor` 的退出码。
- **怎么做:** 什么都不用做, 除非你想要授予: `chromium-bridge policy set` 会写入第一个基线 ([CLI 页面上的策略说明](cli.md#主机持有的策略-policy))。已存在的策略存储会报告它的修订号、`signed` 或 `unsigned`, 以及是否有未签名的限制覆盖层处于活动状态; 主机只报告是否已签名, 从不声称「有效」, 因为只有扩展才能用自己固定的密钥验证签名。

## doctor 报告 `policy baseline: UNREADABLE`

- **你看到:** `UNREADABLE (...) - failing closed`, 且 `doctor` 以非零状态退出。
- **含义:** 策略存储存在, 但无法读取或解析。每个使用方都失败即关闭: 主机的分发门禁拒绝所有工具, 扩展继续执行它存储的有效策略或拒绝基线。
- **怎么做:** 先检查这个存储, 再做其他任何事。它从不会被替换为默认值, 因为默认值可能比你收紧过的策略更宽松, 而由垃圾数据构成的放松杠杆算不上杠杆。

## 原生消息主机每隔几分钟退出一次

- **你看到:** 主机进程结束并重启, 扩展的连接状态大约每五分钟闪烁一次。
- **含义:** Chromium 大约每五分钟强制重启 MV3 Service Worker, 这会关闭原生消息端口; 主机在 stdin 上收到 EOF 后退出, 扩展在两秒后重连 ([重连流程](architecture.md#52-原生消息主机重连))。
- **怎么做:** 什么都不用做。正在关闭的连接上进行中的调用会以 `CONNECTION_LOST` 失败; 下一次调用会重新解析活动标签页, 而会话簿记位于 MCP 服务器而非 Service Worker 中, 所以重连不需要重新配对。

## 扩展与主机版本不一致

主机持有的策略帧是在没有提升桥接协议版本的情况下加入的: 它们是增量的且由主机处理, 所以两种版本偏差的行为如下表所示。哪个数字在何时变动, 见[发布页面](release.md#版本)。

| 偏差 | 行为 |
| --- | --- |
| 新扩展, 旧主机 | 主机从不推送策略帧, 所以扩展也从不发送 (旧主机会把未知帧归类为可转发, 而服务器的严格解析会拆掉浏览器这一侧的连接)。扩展停留在切换前状态, 执行拒绝基线。 |
| 旧扩展, 新主机 | 旧扩展丢弃它不认识的 `policy_current` 推送 (有测试固定此行为), 保留本地设置; 新主机仍在分发时应用自己的策略, 所以合并后的执行力度绝不会比旧扩展单独执行时更宽松。 |
| 新扩展, 没有选项页帧的主机 | 选项页会按需发送 `registration_status`、`registration_repair`、`policy_restrict`、`audit_read` 和 `doctor_report`, 所以「绝不先开口」规则不覆盖它们: 中介的严格解析会拆掉浏览器这一侧的连接。在首次发布前这是可接受的, 因为没有任何已发布的主机缺少这些帧; 日后要覆盖它, 需要推迟的握手宣告主机的控制帧, 并让扩展据此决定是否发送。 |

## 没有 Secure Enclave 的 Mac 无法登记

- **你看到:** `chromium-bridge pair` 在 T2 之前的 Intel Mac 上拒绝执行。
- **含义:** 每个授予和策略签名都依赖 Secure Enclave 密钥, 而那种硬件无法持有它, 并且 `requireEnrollment` 退出选项已被移除。桥接在那里保持阻塞, 这是有意为之, 且没有恢复路径。
- **怎么做:** 使用 Apple Silicon 或 T2 Mac, 或者使用不要求登记的 Linux 或 Windows。

## 在 WSL 下运行

Chrome、它启动的原生消息主机和 MCP 服务器必须属于同一个操作系统。根据 Chrome 运行在哪里来选择模式。

### WSL 客户端搭配 Windows Chrome

常见的配置: MCP 客户端运行在 WSL 中, 日常使用的浏览器是 Windows Chrome。不需要安装 Linux 版本, WSL 中也不需要 Chrome。

1. 在 Windows 上解压 Windows 发布压缩包 (或从源码构建), 在那里运行 `chromium-bridge.exe doctor --fix`, 并把压缩包里的 `extension/dist` 加载到 Windows Chrome 中。
2. 在 WSL 的 MCP 配置中直接运行 Windows 的 `.exe`。WSL 互操作会把它作为 Windows 进程启动, 因此它与 Windows Chrome 共享注册表、`%LOCALAPPDATA%` 锁文件和原生消息主机。

对于 Codex, 在 `~/.codex/config.toml` 中:

```toml
[mcp_servers.chromium-bridge]
command = "/mnt/c/Users/YOUR_WINDOWS_USER/AppData/Local/chromium-bridge/chromium-bridge.exe"
args = []
```

替换 `YOUR_WINDOWS_USER` 并确认路径存在; 示例假定二进制位于 `%LOCALAPPDATA%\chromium-bridge`。

### WSLg 搭配 Linux Chrome 或 Chromium

当浏览器本身运行在 WSLg 内时, 在 Linux 中原生安装: 把 Linux 版 `chromium-bridge` 二进制放到 WSL 文件系统中的稳定路径并注册它。

```sh
./chromium-bridge doctor --fix                    # every detected browser
./chromium-bridge doctor --fix --browser chrome   # Google Chrome only
./chromium-bridge doctor --fix --browser chromium # Chromium only
```

| 什么 | 在哪里 |
| --- | --- |
| 清单 | `~/.config/google-chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json`, `~/.config/chromium/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json` |
| 锁文件 | `$XDG_RUNTIME_DIR/chromium-bridge/run.lock`; 没有 `XDG_RUNTIME_DIR` 时为 `$XDG_CACHE_HOME/chromium-bridge/run.lock` 或 `~/.cache/chromium-bridge/run.lock` |

在 Linux 浏览器的 `chrome://extensions` 中加载发布压缩包里的 `extension/dist` (或构建出的 `build/extension/chrome-mv3`), 然后把 MCP 客户端指向 Linux 二进制 (仍以 Codex 为例, 在 `~/.codex/config.toml` 中):

```toml
[mcp_servers.chromium-bridge]
command = "/home/YOUR_WSL_USER/.local/lib/chromium-bridge/chromium-bridge"
args = []
```

### 不要混用两套系统

- **Windows Chrome** 无法读取 WSL 内的 Linux 原生消息清单, 也无法启动 Linux ELF 二进制。
- **WSLg 中的 Linux Chrome** 不读取 Windows 注册表, 也无法使用 Windows Chrome 的注册。
- **从 WSL 启动 Windows `.exe` 不算混用:** 那个进程仍然是 Windows 进程, 这正是第一种模式能工作的原因。

当 WSL 下连接失败时, 先确认 Chrome、原生消息主机和 MCP 服务器都落在同一侧, 然后检查锁文件: Windows 上是 `%LOCALAPPDATA%\chromium-bridge\run.lock`, Linux 上是上面的 XDG 路径。

## 崩溃后留下了锁文件

- **你看到:** 在某个中介异常退出后, `doctor` 报告一个端点不可达的锁文件。
- **含义:** 锁文件 (运行时目录中的 `run.lock`) 比它的中介活得更久。对于活着的持有者没有强制接管: 第二个实例发现活着的中介时会附加到它上面。
- **怎么做:** 启动一个客户端会话。下一个服务器实例会探测过期端点并在启动时替换锁; `doctor` 只读取它。
