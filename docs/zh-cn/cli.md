# CLI 与故障排除: chromium-bridge

> 本文档是 `chromium-bridge` 二进制各子命令的参考, 也汇总了常见的故障排除路径。CLI 是核心之上的管理界面。组件与进程边界见 [architecture.md](./architecture.md); 磁盘路径见 [architecture.md 第 4.3 节](./architecture.md#43-磁盘上的产物)。

## 子命令总览

`chromium-bridge` 是一个单一二进制, 通过子命令分发:

| 调用方式 | 模式 | 说明 |
|------|------|------|
| `chromium-bridge` (无参数) | MCP 服务器 | 默认模式, 由 MCP 客户端启动。第一个实例成为中介 (broker); 之后的实例接入它。 |
| `chromium-bridge --native-host [--label <browser>]` | 原生消息主机 | 轻量桥接, 由浏览器通过主机清单启动。从不手动调用。 |
| `chromium-bridge doctor [--json]` (别名 `status`) | 只读诊断 | 环境与连通性自检; 不改动任何东西。`--json` 把报告打印为一个带版本号的对象。 |
| `chromium-bridge doctor --list` | 只读诊断 | 每个已知浏览器与作用域一行: 检测与注册状态。 |
| `chromium-bridge doctor --paths` | 只读诊断 | 打印当前环境解析出的运行时目录与锁文件路径, 两者都不会创建。 |
| `chromium-bridge doctor --fix` | 修复 / 安装 | 为你的账户把这个二进制注册 (或重新注册) 为原生消息主机。doctor 唯一会写入的形式。 |
| `chromium-bridge doctor --fix --system` | 修复 / 安装 (root) | 同样的操作, 但是机器级的: 写入每个账户的浏览器都会读取的、归 root 所有的目录。`.deb` 安装后运行的就是它。 |
| `chromium-bridge uninstall [--system]` | 移除 | 只移除本项目在该作用域写入的注册, 不动其他任何东西。 |
| `chromium-bridge pair [--reset] [--file-store]` | 登记 | 在终端键入确认之后, 生成扩展所固定的主机密钥; 密钥保存在操作系统的凭据存储中, 或在使用 `--file-store` 时保存在一个 0600 文件里。 |
| `chromium-bridge revoke <browser>` | 登记 | 忘记该浏览器已登记的认证器; 不需要证明, 该浏览器可从其选项页重新登记。 |
| `chromium-bridge revoke --all` | 登记 | 从头来过: 删除主机密钥与签名的策略基线, 忘记每一个浏览器和每一个受信任客户端。不带参数的 `revoke` 会被拒绝并显示用法。 |
| `chromium-bridge enclave-status [--json]` | 只读 | 打印主机密钥的状态、所在位置及其指纹。 |
| `chromium-bridge pair-client --name <label> (--this-parent \| --hash <hex> \| --signer <id>)` | 受信任客户端 | 把一个 MCP 客户端程序 (harness) 加入受信任客户端白名单; 需要在场验证。 |
| `chromium-bridge revoke-client --name <label>` | 受信任客户端 | 移除一个客户端; 运行中的中介会立即断开它。 |
| `chromium-bridge list-clients` | 只读 | 打印受信任客户端白名单。 |
| `chromium-bridge kill` | 紧急开关 | 启用全局紧急开关 (kill switch): 停止所有桥接活动, 直到显式解除。 |
| `chromium-bridge unkill` | 紧急开关 | 在证明用户在场之后解除紧急开关: 在交互式终端键入一段确认 (管道传入的 stdin 会被拒绝)。 |
| `chromium-bridge policy show [--json]` | 只读 | 打印主机持有的策略状态与生效策略。 |
| `chromium-bridge policy set <field flags> [--json]` | 策略 (授予通道) | 在键入终端确认之后生成一份全新的已签名策略基线。仅限签名; 没有主机密钥时会预先拒绝。 |
| `chromium-bridge policy restrict <field flags>` | 策略 (自由通道) | 应用一层未签名的限制覆盖层; 不弹提示, 因为它只能削减能力。 |
| `chromium-bridge policy history [--json]` | 只读 | 打印已被取代的修订环。 |
| `chromium-bridge policy rollback --revision <n> [--entry <id>] [--json]` | 策略 | 把过去某个修订的生效策略重新推导为一次全新写入, 绝不重放; 当同一修订出现不止一次时, 用 `--entry` 指名其中一条记录。 |
| `chromium-bridge audit [--limit <n>]` | 只读审计 | 打印磁盘上的审计日志, 最旧的在前 (默认: 最近 200 条记录)。 |
| `chromium-bridge lang [show \| set <value>]` | 显示语言 | 读取或设置选项页显示的语言; 单独的 `lang` 等同于 `show`。 |
| `chromium-bridge --help` | 帮助 | 用法信息。 |

选项页提供同样的操作。按设计只在终端上: `uninstall` (见下文), 以及 `--system` 和 `--manifest-dir` 两种修复形式。选项页的审计视图只有默认的那一页; 更长的日志用 `audit --limit <n>`。站点白名单、全部允许和标签页分组留在选项页上。它们是浏览器本地的扩展存储 (见[隐私政策](./privacy-policy.md)), 没有任何子命令读写它们。

## doctor / status (只读自检)

`doctor` (`status` 是等价别名) 是只读子命令: 它不绑定套接字, 不写锁文件, 也不启动任何子进程。它只探测当前环境并打印结论, 用来回答「为什么我连不上」这个问题。

它报告:

- **版本 / 平台**: 二进制版本 (以 Cargo 为准) 与运行平台。
- **锁文件**: 运行时目录中是否存在桥接锁文件, 以及其中记录的端点与 pid。
- **服务器可达性**: 对我们自己的桥接套接字做一次被动的连接即断开探测 (不发送任何字节), 报告 `reachable` / `not reachable`。
- **紧急开关**: 已启用、未启用, 或不可读。开关启用期间或其状态无法读取时, `doctor` 以非零退出码退出。
- **原生消息主机注册**: 对每个已知浏览器 (chrome、chromium、brave、edge、vivaldi、opera), 报告它在这台机器上是否看起来已安装, 以及它对 `com.vivswan.chromium_bridge.host` 在 `user` 与 `system` 两个作用域各自的注册状态: `ok`、`missing`、`stale` (是我们写的, 但其启动路径已失效), 或者不是我们写的。
- **裁决遵循浏览器的查找顺序**: 有按用户条目时取它, 没有时才取系统条目。诊断来自 `--fix` 修复时使用的同一个解析器, 因此 doctor 报告的内容与 `--fix` 产出的内容完全一致。

选项页的「主机注册」区显示同样的几行 (锁文件、服务器、紧急开关、策略基线、裁决), 措辞来自主机; 其身份区显示主机密钥存放在哪里, 与 `enclave-status` 打印的一致。

`doctor --json` 把同一份报告作为一个 JSON 对象打印到 stdout, 退出码相同。和这个二进制的每一份 `--json` 报告一样, 先检查其 `v` 字段, 遇到更新的值就拒绝, 然后再读取其他内容 (失败即关闭)。

### 如何理解「server not reachable」

「Server not reachable」表示 `doctor` 从锁文件读到了端点, 但探测失败。常见原因:

1. **没有 MCP 服务器在运行。** 服务器由 MCP 客户端 (例如 Claude Code) 在其会话内启动, 所以没有客户端会话时就没有任何进程在监听, 「not reachable」是预期状态。请确认客户端已配置 chromium-bridge 服务器, 并且有一个会话处于打开状态。
2. **过期的锁文件。** 之前的中介异常退出, 留下了锁文件。下一个服务器实例会在启动时检测并替换过期的锁; 只需开启一个新的客户端会话。

> `doctor` 只探测, 不修复。它不会杀进程、删除锁文件或重启服务器。看到「not reachable」时, 请从 MCP 客户端一侧重新建立会话, 而不是手动干预进程。

如果你使用的某个浏览器的注册缺失或过期, 该浏览器就无法启动原生消息主机。运行 `chromium-bridge doctor --fix`, 然后重启浏览器。

## doctor --fix / uninstall (原生消息注册)

下面的 CLI 通过同一个引擎 (`registration.rs`) 从终端注册原生消息主机。它只需要主机二进制本身, 在桌面、无头机器和 CI 上都一样。

`chromium-bridge doctor --fix` 把你用来调用它的那个二进制 (重新) 注册为原生消息主机: 对每个目标浏览器, 它把 `com.vivswan.chromium_bridge.host.json` 清单写到该浏览器查找清单的位置, 并在旁边写入扩展指针 (见下文)。

- **幂等的重新注册:** 在全新机器上 `--fix` 同时就是首次注册; 移动二进制之后它会刷新过期的注册。
- **不构建、不下载、不复制任何东西:** 清单指向这个二进制自身解析出的路径, 在 macOS/Linux 上经由一个小的按浏览器区分的包装脚本。
- **那个包装脚本** 把 `--native-host` 固化在内, 因为 Chrome 的清单格式没有 `args` 字段; 当只有一个浏览器会启动该清单时再加上 `--label <browser>` (`run-host-<browser>.sh`); 多个浏览器共读的清单得到不带标签的 `run-host.sh` (规则由 `registration.rs` 中的 `Target` 负责)。
- **会覆盖另一个工具以我们的主机 id 写下的清单** (报告会点名它原本启动的是什么), 拒绝读不了的清单, 也拒绝外来的指针; `uninstall` 会留下外来的清单。

选择浏览器:

```text
chromium-bridge doctor --fix                      # every browser detected for this user
chromium-bridge doctor --fix --browser chrome,brave
chromium-bridge doctor --fix --all                # every known browser, detected or not
chromium-bridge doctor --fix --manifest-dir DIR   # exact NativeMessagingHosts dir
                                                  # (absolute; repeatable), for a Chromium
                                                  # variant we do not know by name
sudo chromium-bridge doctor --fix --system        # machine-wide, for every account (root only)
chromium-bridge doctor --list                     # read-only: detection + registration state
```

作用域属于命令: `--system` 写入每个账户的浏览器都会读取的目录 (`/etc/opt/chrome/native-messaging-hosts`、`/Library/Google/Chrome/NativeMessagingHosts`、`HKLM`), 需要 root; 不带它时 root shell 会被拒绝, 因为 root 没有自己的浏览器。

Opera, 以及 macOS 和 Linux 上的 Brave, 读取的是 Chrome 的系统目录而非自己的目录, 而 macOS 上的 Brave 还读取 Chrome 的按用户目录。对它们, `doctor --fix` 在该作用域注册 Chrome 的清单, `doctor` 则在它们的行上把它报告为 Chrome 的。

- **共享清单不带标签:** 任一浏览器都可能启动它, 所以它的连接占用中介的默认槽位, 与 `--manifest-dir` 注册的连接一样。
- **每个浏览器各自的指针, 在 macOS 上按用户:** Chrome 和 Brave 在那里各自保有自己的扩展指针, 所以两者都会提示启用扩展 (机器级时, macOS 为所有浏览器只有一个指针目录)。

已知浏览器键: `chrome`、`chromium`、`brave`、`edge`、`vivaldi`、`opera`。「已检测到」表示浏览器确实已安装, 以一次廉价的本地检查所能判断为准:

| 平台 | 检测检查 | 含义 |
| --- | --- | --- |
| macOS | `/Applications` 或 `~/Applications` 下的应用程序包 | 仅有残留的按用户配置目录不算 (已卸载的浏览器会永远留着这些目录, 某些开发工具也会创建它们); 刚安装、尚未首次运行的浏览器算 |
| Linux | 按用户的配置目录; 带 `--system` 时为厂商软件包的安装目录 (`/opt/google/chrome`、`/usr/lib/chromium` 之类) | 按用户的修复注册此账户运行过的浏览器; `.deb` 的安装后步骤以 root 身份注册为所有账户安装的浏览器 |
| Windows | 按用户的 profile 目录 | 那里最好的廉价信号 |

- **macOS 上的非标准安装** 会被判为「未检测到」; 仍可用 `--browser <key>` 或 `--manifest-dir` 显式注册。
- **不带参数的 `doctor` 只统计检测到的浏览器,** 所以非标准安装的一份健康的显式注册仍会让下方的汇总达不到「OK」, 即便桥接可以工作 - 各浏览器行才说明真实情况。
- **什么都没检测到:** `--fix` 会拒绝并要求显式选择, 而不是猜测, 并以退出码 3 而非 1 退出, 让安装程序能区分「还没有浏览器」与失败。
- **选项页的「主机注册」区**以同样的两种方式为此账户修复: 每个检测到的浏览器, 或从其所在行指名的一个浏览器。`--manifest-dir` 和 `--system` 留在终端: 目录要键入, root 权限要持有, 而选项页两者都没有。

`chromium-bridge uninstall` 在一个作用域内精确撤销本项目 (通过 `--fix`) 注册的内容: 各浏览器的清单、扩展指针和包装脚本。你注册时传过的任何 `--manifest-dir` 都要再传一次, 机器级注册则 (以 root 身份) 再传 `--system`。

删除清单或指针之前, 它会验证内容是我们的 (我们的主机 id 与描述标记; 指针则只看 Web Store 更新 url)。其他任何内容, 或任何读不了的内容, 都会被报告并原样留下, 作为警告而非失败, 这样软件包的移除能够完成; 旁边属于我们的其他产物照样移除, 只有属于我们却无法移除的东西才会让命令失败。

它从不触碰这个二进制或你的浏览器。浏览器会在下次启动时丢弃它从指针安装的扩展; 未打包的扩展则由你自己移除。

`uninstall` 按设计没有选项页上的对应物。请求它的那个帧, 会删除启动了正在应答它的主机的那份清单。

扩展指针, 位于每个清单旁边:

| 操作系统 | `--fix` 写到哪里 | 浏览器如何处理它 |
| --- | --- | --- |
| macOS | `<user data dir>/External Extensions/<extension id>.json`, 指向 Web Store; 带 `--system` 时为所有浏览器写入 `/Library/Application Support/Google/Chrome/External Extensions/` (Chromium 唯一的机器级目录) | 下次启动时询问「Enable Chromium Bridge?」 |
| Windows | `HKCU\<vendor>\Extensions\<extension id>`, 值为 `update_url`; 带 `--system` 时为 `HKLM` | 同样的提示 |
| Linux | 不写; `doctor` 打印 `pointer n/a` | 它会从指针静默安装, 而威胁模型拒绝这种行为: 请自行从 Web Store 添加扩展 |

Chrome 自身的位置来自其文档。其他厂商的位置由它们存放清单的同一个用户数据根目录和注册表根推导而来, Edge 也被指向 Chrome 应用商店 (一项残余风险: 在那些浏览器上未经验证)。

指针只为 `doctor` 提供信息, 从不决定其结论: 桥接在未打包扩展且没有指针的情况下也能工作。它只为 `--fix` 指定或检测到的浏览器写入; `--manifest-dir` 注册不会得到指针, 因为无法指认其浏览器。

商店条目是否已经存在, 以及在它存在之前该加载什么, 由 [quickstart.md](./quickstart.md#cli-macoslinuxwindows) 的第 4 步说明。

平台说明:

- **Linux AppImage / 临时路径**: 指向 AppImage 的 FUSE 挂载点 (或任何临时目录) 的注册会在该路径消失时失效。`--fix` 检测到这种情况时会发出警告。请先把二进制复制到一个稳定位置, 例如 `~/.local/lib/chromium-bridge/chromium-bridge`, 再从那里运行 `doctor --fix`。
- **Windows**: 注册是每个浏览器一个 `HKCU` 注册表键, 外加 `%LOCALAPPDATA%\chromium-bridge` 下的一个清单文件 (带 `--system` 时为 `HKLM` 与 `%ProgramFiles%\chromium-bridge`)。这条代码路径可以编译, 并复刻了已退役的 `install.ps1` 脚本的行为, 但尚未在真实的 Windows 机器上验证; 在此之前请把 Windows 注册视为尽力而为。Windows 上的浏览器检测 (按用户的 profile 目录; Opera 在漫游 profile 下) 也有同样的保留。

## 登记: pair / revoke / enclave-status

主机密钥仪式给扩展一个可供固定的主机身份:

- `chromium-bridge pair` 要求你在终端键入一段确认 (管道传入的 stdin 在任何提示出现之前就被拒绝), 生成一把 P-256 主机密钥, 把它保存在操作系统的凭据存储中 (钥匙串、凭据管理器或 Secret Service), 并打印该密钥的 SHA-256 指纹。把这个指纹与扩展在登记界面上显示的指纹比对; 不一致意味着两者之间有东西插在中间。
- `chromium-bridge pair --file-store` 改为把密钥保存在运行时目录中的一个 0600 文件里, 供没有可用凭据存储的机器使用。这个选择是显式的: 存储失败会被报告, 绝不会悄悄改写到文件。
- `chromium-bridge pair --reset` 先要求确认, 然后移除之前的密钥 (无论哪个存储持有它) 并生成一把新的; 扩展必须重新固定。浏览器登记和客户端配对保持不变。
- 当凭据存储没有响应时, `--file-store` 的重置会继续进行, 并警告存储中可能仍留有一条条目。等存储恢复响应后再运行一次 `pair --reset`; `revoke --all` 也可以, 但它还会忘记每一个浏览器和客户端。
- `chromium-bridge enclave-status [--json]` 以只读方式报告当前状态: 是否存在密钥、哪个存储持有它, 以及它的指纹。

浏览器自身操作 (解除紧急开关、登记第二个浏览器) 的用户在场证明, 是在浏览器认证器上的一次 WebAuthn 触碰, 由主机验证。选项页的身份区登记该认证器; 其紧急开关面板、策略编辑器和受信任客户端表单, 各自以下文紧急开关表所述的证明应答主机的在场请求。

忘记操作没有额外门槛, 因为它只移除能力:

- `chromium-bridge revoke <browser>` 忘记在该标识下登记的每一个认证器。该浏览器的操作回退到确认窗口, 直到它从自己的选项页重新登记; 当它是最后一个已登记的浏览器时, 下一次登记重新成为首次登记。
- 标识是浏览器主机清单的 `--label` (`brave`、`chrome`); 共享一份未设置标识的清单的所有浏览器 (Windows、共享的 Chrome 清单) 都使用 `default`, 所以 `revoke default` 会把它们全部忘记。未知的标识会被拒绝, 并列出记录中持有的标识。
- 选项页为它自己的浏览器提供同样的操作: 身份区认证器块中的「忘记此浏览器」。它作用于该主机的标识, 所以共享一份清单的浏览器会被一起忘记。
- `chromium-bridge revoke --all` 一步从头来过: 删除主机密钥, 策略记录随之消失 (签名的基线和任何限制覆盖层), 忘记每一个浏览器, 吊销每一个受信任客户端, 所以已配对的机器在 `pair-client` 再次信任某个客户端之前不准入任何客户端。紧急开关不受影响; 用 `unkill` 解除它。
- `revoke --all` 之后, 已连接的扩展无论如何都失败即关闭: 当凭据存储确认密钥已消失且记录写入落地时, 通过吊销推送; 否则在它下一次密钥验证时。`revoke <browser>` 不触碰主机密钥和固定。
- 不带参数的 `chromium-bridge revoke` 两者都没有指名, 会被拒绝并显示用法。

CLI 从不弹出那个提示: 它自己的授予 (`pair`、`pair-client`、`unkill`、`policy set`) 由在真实终端上键入的短语确认。

## 受信任客户端: pair-client / revoke-client / list-clients

默认情况下 (未登记), 任何启动服务器的进程都会得到服务, 并且每次启动都会以 ERROR 级别记录这种开放姿态。创建受信任客户端白名单即可关闭它:

```text
chromium-bridge pair-client --name claude-code --this-parent
chromium-bridge pair-client --name codex --hash <sha256-hex>
chromium-bridge pair-client --name claude-desktop --signer <signer-id>
chromium-bridge list-clients
chromium-bridge revoke-client --name codex
```

- `--this-parent` 测量启动这次 CLI 调用的进程 (在你想信任的客户端内部运行它)。仅限 Unix: 在 Windows 上服务器以其 stdin 管道的创建者作为客户端程序的键, 而控制台命令没有这样的管道, 所以请用 `--hash` 或 `--signer` 配对, 取值用服务器在未登记状态下启动时记录的值。
- 授权以经证明的锚点为键, 从不以 `--name` 标签为键; 标签只用于标注日志和吊销。各平台测量什么见[信任边界页面](security/trust-boundaries.md#边界-1-mcp-客户端---rust-mcp-服务器-stdio-json-rpc-20)。
- 哈希锚点会在客户端更新时改变; 用同一个名字重新运行 `pair-client` 即可替换条目 (重新配对路径)。
- 添加客户端是一次能力授予, 所以需要在场验证: 在交互式终端键入一段确认, 管道传入的 stdin 会被拒绝。吊销刻意做到无阻力; 运行中的中介会断开被吊销的客户端并拒绝其重新接入。
- 选项页的「受信任的 MCP 客户端」区以同样的方式配对客户端 (一个名字加一个哈希或签名者锚点), 以此浏览器的在场证明为门槛; `--this-parent` 只存在于 CLI, 因为页面没有可测量的父进程。

白名单一旦存在, 任何不匹配的都失败即关闭, 包括无法测量的身份和不可读的白名单。Windows 上的测量见 [SECURITY.md](../../.github/SECURITY.md#platform-support)。

## 紧急开关 (kill / unkill)

`chromium-bridge kill` 是紧急刹车: 一条命令, 让每个 MCP 客户端同时停止操作每个已连接的浏览器。

- 活跃的浏览器连接在大约一秒内被切断, 新连接被拒绝。进行中的工具调用以 `CONNECTION_LOST` 快速失败。
- 之后来自每个已接入客户端的每次工具调用都以稳定的 `BRIDGE_KILLED` 错误码被拒绝。客户端保持连接, 以便向你显示拒绝原因, 而不是悄无声息地死掉。
- 该状态持久化 (在锁文件旁边的 `trust.json` 中), 能在重启、重连和重新开机后保留。
- 扩展的选项页显示该状态; 从任何界面都能启用开关。从选项页解除时, 主机会以一次在场请求应答, 页面以 WebAuthn 触碰 (或只在没有已登记凭据的浏览器上提供的软件确认) 完成它; 网页看不到、也碰不到其中任何东西。

没有任何东西会自行解除开关。解除在两种界面上都要求证明用户在场:

| 界面 | 一次解除要求的证明 |
| --- | --- |
| CLI 上的 `chromium-bridge unkill` | 在真实终端上键入的显式确认; 管道传入的 stdin 会被直接拒绝, 因此没有任何脚本或后台程序能悄悄通过 CLI 重新打开桥接 |
| 扩展 | 来自该浏览器下已登记凭据的一次 WebAuthn 断言; 只有在浏览器没有已登记凭据时才用浏览器的确认窗口 |

每次解除尝试都会记入审计: 已授予的解除附上做出决定的认证路径 (`auth=tty`、`auth=webauthn:<fingerprint>`、`auth=confirm_window`), 在在场门禁处的拒绝附上在场错误, 在场验证通过后因记录不可写而拒绝的则两者都附上。

如果任一命令报告信任记录不可读, 见[恢复步骤](./troubleshooting.md#doctor-显示紧急开关状态或信任记录不可读); 在此之前, 一切继续失败即关闭。

`doctor` 打印紧急开关状态, 并在开关启用期间或其状态不可读时以非零退出码退出。

## 主机持有的策略 (policy)

`chromium-bridge policy` 是主机持有的策略界面。相关概念 (已签名的基线、未签名的限制覆盖层、扩展侧的棘轮) 见 [architecture.md 第 11.3 节](./architecture.md#113-主机持有的策略与语言同步); doctor 的 `policy baseline:` 这一行在[故障排除页面](./troubleshooting.md#doctor-报告-policy-baseline-none-yet)解读。

```text
chromium-bridge policy show [--json]              # read-only: store state + effective policy
chromium-bridge policy set <field flags> [--json] # GRANT lane: sign a fresh baseline (terminal confirmation)
chromium-bridge policy restrict <field flags>     # FREE lane: unsigned restriction overlay
chromium-bridge policy history [--json]           # read-only: superseded revisions
chromium-bridge policy rollback --revision <n> [--entry <id>] [--json]
```

**字段标志。** `set` 与 `restrict` 共用一组标志, 每个策略字段一个, 拼写为其 camelCase 线路名的 kebab-case 形式: `--cdp-mode`、`--file-upload`、`--handle-dialog`、`--page-eval`、`--confirm-high-risk-click`、`--confirm-page-eval`、`--presence-confirm`、`--confirm-tab-close`、`--warn-precise-snapshot`、`--eval-mask`、`--host-reverify-ms`、`--confirm-grace-ms`、`--click-toast-timeout-ms`、`--eval-toast-timeout-ms` 和 `--disabled-tools`。

| 标志类型 | 取值 |
| --- | --- |
| 布尔标志 | `on` 或 `off` |
| 四个 `*-ms` 标志 | 非负整数 |
| `--disabled-tools` | 逗号分隔的工具列表, 表示完整的禁用集合 (添加一个工具时要保留已在其中的工具) |

- **`--disabled-tools ""` 是空集:** 空条目会被丢弃, 所以这是一次完全清空; 在 `set` 通道上这是一次放宽, 和其他放宽一样需要一次触碰。
- **含逗号或前后带空白的工具名** 无法忠实地通过逗号拼接的传输: 每个写入接缝都直接拒绝这样的名字, 而不是签署一份被悄悄篡改的列表。
- **解析是严格的:** 未知子命令、多余参数、重复标志或格式错误的值都是错误, 从不猜测; 并且 `set`/`restrict` 要求至少一个字段标志。

**两条通道刻意不对称。**

- **`policy set` 是授予通道:** 它把编辑折叠到当前基线之上 (未触碰的字段沿用基线值, 而非生效值), 把被触碰的字段集合嵌入文档, 并在键入的终端确认通过后, 用主机密钥对精确的文档字节签名。
- **没有主机密钥, 就没有授予:** 在没有运行过 `pair` 的机器上, CLI 会在任何提示出现之前预先拒绝, 这样就不会存在扩展的固定指纹无法校验的基线。
- **`policy restrict` 是自由通道:** 不弹提示、不签名, 并且接缝的方向检查会拒绝任何会放宽生效策略的编辑, 所以脚本化或伪造的限制至多是对你自己的桥接的一次拒绝服务。
- **选项页的「安全策略」区走同样的两条通道:** 收紧立即生效, 放宽则以此浏览器的在场证明为门槛签署一份新基线, 没有密钥的主机会用同样的措辞预先拒绝。在任何基线存在之前, 那里的每一次编辑都是授予, 因为还没有可限制的内容。

**回滚从不重放。** `policy rollback --revision <n>` 重新推导该修订的生效策略, 与当前策略做差异比较, 再把差异作为一次全新写入应用。

- **只收紧的回滚** 走自由的 restrict 通道, 不弹提示。
- **放宽了任何内容的回滚** 需要一次新的终端确认和签名, 与任何其他授予完全一样。
- **旧的已签名产物从不被写回:** 更低的修订号必须持续通不过扩展的棘轮, 这正是防重放属性, 而不是限制。
- **一个修订, 多条记录:** 某修订处于当前状态期间所做的每一次限制, 都会推入一条处于该修订的记录, 所以 `policy history` 列出每条记录的 `entry` 编号, `--entry <id>` 指名要恢复的那一条; 存在歧义时, 只带 `--revision` 会被拒绝。页面上的回滚按钮以同样的方式指名记录。
- **回滚进行中存储被改动** 会被拒绝: 差异是基于对存储的一次读取规划的, 所以若另一界面在那次读取与回滚自身写入之间落下了一次写入 (比如来自选项页的一次限制), 这次回滚就作为冲突被拒绝, 什么也不写; 「已经如此」的结果也以同样的方式确认。请基于新状态再运行一次回滚。
- **选项页的「历史版本」列表** 显示与 `policy history` 相同的环, 并以同样的方式回滚, 走由方向决定的通道; 每条记录都带着它当时持有的策略, 页面则为它显示 CLI 的 `effective=` 行, 并标出回滚会改变的字段。

**`--json` 契约。** `show`、`history`、`set` 与 `rollback` 都接受 `--json`, 它把文字输出换成 stdout 上的一份带版本号的报告 (对写入通道而言, 拒绝时则是一个带版本号的错误对象)。先检查 `v` 字段, 遇到更新的值就拒绝, 然后再读取其他内容 (失败即关闭)。

每次策略转换都会记入审计, 附上发起界面, 对于授予还附上授权该签名的在场路径: 来自 CLI 的 `auth=tty`, 来自选项页的 `auth=webauthn:<fingerprint>` 或 `auth=confirm_window`。[store_tests.rs](../../src/packages/core/src/policy/store/store_tests.rs) 与 [presence/tests.rs](../../src/packages/core/src/native_host/presence/tests.rs) 固定这三种写法。

## 显示语言 (lang)

扩展的显示语言是由主机保存的共享状态 (运行时目录中的 `lang.json`), 并推送给每一个已连接的浏览器, 所以一次选择就同步到所有已连接的浏览器。选项页在其页眉用「显示语言」选择器设置它; 终端上的对应物是:

```text
chromium-bridge lang              # the current value (same as `lang show`)
chromium-bridge lang set zh_TW    # one of: auto, en, zh_CN, zh_TW
```

- **语言不是策略:** 不签名、不棘轮, 也无法影响任何安全决策, 这正是它在两种界面上都不需要确认的原因。
- **列表之外的值会被拒绝**, 在 argv 和选项页的帧上一样, 先前的值保持不变; 设置为当前值什么都不改变, 也不推送任何东西。
- **已连接的浏览器在主机的下一次推送时切换** (在其轮询间隔内); 离线的浏览器在下次连接时采用该值。

## 日志与审计 (BB_LOG / BB_LOG_FORMAT)

两种模式下的诊断信息都写到 **stderr** (stdout 承载协议帧)。两个环境变量控制输出:

| 变量 | 取值 | 效果 |
|------|------|------|
| `BB_LOG` | `error` \| `warn` \| `info` (默认) \| `debug` | 日志阈值。`info` 及以上会打印审计行; 设为 `warn`/`error` 可关闭审计输出。 |
| `BB_LOG_FORMAT` | `text` (默认) \| `json` | 审计行的格式。`json` 每行输出一个 JSON 对象, 便于机器采集。 |

**审计事件 (stderr)**: 每个安全决定都输出一条审计行: 工具调用 (带 `req`、`tool`、`outcome`, 出错时还有来自 [`ERROR_SPECS`](../../src/packages/core/src/error.rs) 的稳定 `code`, 以及 `dur_ms`)、客户端程序的准入与拒绝、客户端配对与吊销、主机密钥吊销、紧急开关转换、WebAuthn 登记与在场裁决、策略写入, 以及扩展的确认与登记决定 (通过端口转发而来)。

同样的事件会以严格 JSON 记录的形式追加到一个持久、大小受限的 `audit.log` (权限 0600, 位于运行时目录中锁文件旁边), 它比写入它的那些短命进程活得更久。每条记录在 `event_kind` 中标明其事件; JSON 形式的 stderr 输出把记录包在一个 `"kind":"audit"` 信封里, 所以采集器以 `kind` 为键, 再从 `event_kind` 读取事件。

- **不记录任何敏感内容:** 没有页面文本、cookie 或存储值、eval 返回值或表单填写值; 脱敏在扩展一侧进行 ([信任边界](./security/trust-boundaries.md))。
- **关联:** 一条工具调用行带有其请求 id (`req`) 和该调用被路由到的浏览器连接的代数 (`conn`); 代数在每次重新接入时递增, 所以一次重连会开始新的 `conn`。
- **两种扩展本地的事件类型从不进入 `audit.log`:** `policy_refused` 与 `policy_compromised` 按设计留在扩展自己的审计环中, 在转发白名单之外; 主机把每次策略转换记录为 `policy_write`。

```text
# BB_LOG_FORMAT default (text)
[AUDIT] 2026-10-03 23:12:44.302Z  kill_engage     surface=cli outcome=ok
# BB_LOG_FORMAT=json
{"kind":"audit","v":1,"ts_ms":1791069164310,"event_kind":"kill_engage","surface":"cli","outcome":"ok"}
```

用只读子命令读取持久日志:

```text
$ chromium-bridge audit --limit 20
2026-07-17 19:04:11.201Z  kill_engage     surface=cli outcome=ok
2026-07-17 19:04:12.480Z  tool_call       tool=tab_list outcome=error code=BRIDGE_KILLED dur_ms=0
2026-07-17 19:05:02.913Z  kill_release    surface=cli outcome=ok
```

读取器无法解析的记录显示为 `UNRECOGNIZED RECORD` 并计数, 从不猜测; `dropped=n` 字段标记因写入失败 (例如磁盘已满) 而丢失的记录。记录从不阻塞或使操作失败: 日志观察决定, 不对决定把关。

选项页读取同一份日志: 其「最近活动」区在本浏览器的本地决策环旁边列出主机日志 (上文的默认页, 每行都是主机自己的措辞)。

错误码与错误分类见 [architecture.md 第 11.1 节](./architecture.md#111-错误分类-error_specs)。

## 相关页面

- 安装与首次使用: [quickstart.md](./quickstart.md)。
- 连接生命周期与断开/重连语义: [architecture.md 第 5.2 节](./architecture.md#52-原生消息主机重连)。
- 错误分类 (`NOT_CONNECTED` / 断开类): [architecture.md 第 11.1 节](./architecture.md#111-错误分类-error_specs)。
