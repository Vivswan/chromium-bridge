# 快速入门: 安装与首次使用

本指南带你把 chromium-bridge 从一个下载文件, 变成在 MCP 客户端里能正常运行的「列出我的浏览器标签页」。入口是 CLI (macOS、Linux、Windows)。

开始之前, 请先阅读 [README](../../README.zh-cn.md#安全优先) 中的安全摘要: 本工具操作的是你已登录的浏览器, 它向你展示的确认就是安全模型本身, 而不是阻碍。

扩展需要 Chrome 134 或更新版本; 更旧的浏览器会拒绝加载它。

## CLI (macOS、Linux、Windows)

CLI 只需要二进制本身, 在桌面机、无头机器和 CI 上都一样。

1. **安装。** 从[最新发布](https://github.com/Vivswan/chromium-bridge/releases/latest)中任选一种; 若想先校验下载文件, 命令见 [SECURITY.md](../../.github/SECURITY.md#release-artifact-integrity)。

   | 渠道 | 命令或点击 | 作用 |
   | --- | --- | --- |
   | macOS `.pkg` | 右键, 打开 (目前未签名) | 安装 `/usr/local/bin/chromium-bridge`, 并替你完成第 3 步 |
   | Windows `.msi` | 双击 (目前未签名; SmartScreen 会警告) | 为你的账户安装到 `%LOCALAPPDATA%\Programs\chromium-bridge`, 把它加入你的 PATH, 并替你完成第 3 步 |
   | Linux `.deb` | `sudo dpkg -i chromium-bridge-<tag>-linux-x64.deb` | 安装 `/usr/bin/chromium-bridge`, 并替你完成第 3 步, 机器级 |
   | Homebrew | `brew install vivswan/tap/chromium-bridge`, 待 tap 就绪后 ([release.md](./release.md#homebrew-tap)) | 安装二进制, 并替你完成第 3 步 |
   | 压缩包 | 解压 `chromium-bridge-<tag>-<platform>-<arch>.tar.gz` (Windows 上为 `.zip`) | 得到二进制与 `extension/dist`; 第 2、3 步需自行完成 |

   或者用 `cargo build --release` 从源码构建。Windows 上的注册尚未在用户机器上试过 ([cli.md 的 Windows 说明](./cli.md#doctor---fix--uninstall-原生消息注册))。
2. **仅压缩包: 放到稳定的位置。** 注册指向二进制所在的位置, 所以要选一个不会消失的路径: Linux 上是 `~/.local/lib/chromium-bridge/`, macOS 上是你主目录下的任意位置。AppImage 挂载点或临时目录都不稳定, 你若这样做, `doctor --fix` 会发出警告。
3. **向你的浏览器注册。** .pkg、.msi 和 Homebrew 已经做过了, .deb 也为安装时已有的浏览器做过了; 压缩包需要这一步 (请在解压目录中以 `./` 前缀运行二进制):

   ```sh
   chromium-bridge doctor --fix                       # every detected browser
   chromium-bridge doctor --fix --browser chrome,brave
   chromium-bridge doctor --fix --manifest-dir DIR    # an unlisted Chromium
                                                      # variant (macOS/Linux)
   ```

   重复运行无害, `chromium-bridge doctor --list` 以只读方式显示状态, `chromium-bridge uninstall` 精确撤销所写入的内容; 细节由 [cli.md](./cli.md#doctor---fix--uninstall-原生消息注册) 负责。

4. **加载扩展。** 扩展的 Web Store 条目尚未发布 ([release.md 的 Web Store 一节](./release.md#发布到-chrome-应用商店)): 通过 `chrome://extensions`, 开发者模式, 「加载已解压的扩展程序」, 加载发布压缩包中的 `extension/dist` (在源码检出中, 先构建再加载 `build/extension/chrome-mv3`)。重启浏览器。

   条目上线后, [cli.md 的指针表](./cli.md#doctor---fix--uninstall-原生消息注册) 会说明哪些浏览器会根据第 3 步留下的指针提供该扩展, 以及哪些浏览器不会写入指针。

5. **配对。** 运行 `chromium-bridge pair`: 它要求你在终端上键入一段确认, 铸造主机密钥, 并打印出密钥指纹。在扩展的选项页上批准该指纹; 在固定就位之前, 扩展在每个平台上都拒绝执行任何操作 ([cli.md](./cli.md#登记-pair--revoke--enclave-status) 负责说明这一仪式及其参数)。

6. **登记 (推荐)。** 在选项页的身份区域登记你浏览器的认证器。机器上的第一次登记是首次使用即信任; 之后的每一次都需要一个已登记认证器的触碰。

7. **连接你的 MCP 客户端**到二进制的绝对路径。对 Claude Code:

   ```sh
   claude mcp add chromium-bridge -- /absolute/path/to/chromium-bridge
   ```

   对 Claude Desktop 及其他以 JSON 配置的客户端, 添加一个 `mcpServers` 条目, 指向同一个绝对路径, 不带参数。

完整的命令参考见 [cli.md](./cli.md), 涵盖配对、受信任客户端、吊销、紧急开关 (kill switch) 与审计日志。

## 你应该看到什么

- `chromium-bridge doctor` 报告你浏览器的注册为 `ok`, 并在你的 MCP 客户端打开会话后报告服务器可达。
- 扩展的工具栏图标显示连接状态。
- 对新站点的第一次工具调用会在浏览器中弹出批准提示; 高风险操作会弹出确认窗口。

## 推荐的加固

配对 (第 5 步) 在每个平台上都是必需的。登记 (第 6 步) 是推荐项: 没有已登记认证器的浏览器会在确认窗口中回答在场请求 (例如解除紧急开关), 而不是用触碰回答。还有一个可选的仪式用来绑定 MCP 客户端一侧:

- `chromium-bridge pair-client` 创建受信任客户端白名单。它一旦存在, 只有代码身份经证明且获你批准的 MCP 客户端才会得到服务, 并且任何一个界面都能随时吊销其中一个。

三者均在 [cli.md](./cli.md) 与[安全页面](./security.md)中有说明。

## 卸载

`chromium-bridge uninstall` 精确移除 `--fix` 写入的内容 ([cli.md](./cli.md#doctor---fix--uninstall-原生消息注册) 说明了移除什么、拒绝移除什么)。然后按二进制的安装方式移除它:

| 渠道 | 移除二进制 |
| --- | --- |
| macOS `.pkg` | `sudo rm /usr/local/bin/chromium-bridge && sudo pkgutil --forget io.github.vivswan.chromium-bridge` |
| Windows `.msi` | 设置, 应用, Chromium Bridge, 卸载 (它会替你运行 `chromium-bridge uninstall`) |
| Linux `.deb` | `sudo dpkg -r chromium-bridge` |
| Homebrew | `brew uninstall chromium-bridge` |
| 压缩包 | 删除解压出的目录 |

配对状态是独立的: `chromium-bridge revoke --all` 删除主机密钥并忘记每一个浏览器和受信任客户端, 扩展的选项页清除其固定的指纹。

第 6 步登记的认证器保存在 `trust.json` 中。`revoke <browser>` 忘记在该浏览器标识下登记的认证器; 在共享一份未设置标识的清单时, 这个标识对每个浏览器都是 `default`, 如 [cli.md](./cli.md#登记-pair--revoke--enclave-status) 所说明。`revoke --all` 从头来过, 而 `doctor` 读不了的 `trust.json` 是[故障排除页面](./troubleshooting.md#doctor-显示紧急开关状态或信任记录不可读)的情形。
