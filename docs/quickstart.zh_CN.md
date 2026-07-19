# 快速上手: 安装与首次使用

> 本文是 [quickstart.md](./quickstart.md) 的简体中文翻译。以英文版为准;
> 繁體中文版见 [quickstart.zh_TW.md](./quickstart.zh_TW.md)。

本指南带你从下载走到在 MCP 客户端里成功执行"列出我的浏览器标签页"。有两条
对等的路径: 桌面应用 (macOS, 无需终端) 和 CLI (macOS、Linux、Windows)。
两者驱动同一个引擎、写入相同的注册信息, 所以可以用其中一个开始, 用另一个
修复或卸载。

开始之前, 请先阅读 [README](../README.zh_CN.md) 里的安全摘要: 这个工具驱动
的是你已登录的浏览器, 它向你展示的确认提示就是安全模型本身, 而不是麻烦。

## 路径 A: 桌面应用 (macOS)

> 应用安装包尚未发布 (当前发布版只含 CLI 压缩包)。在此之前, 请在源码检出
> 中用 `just app-run` 构建并启动应用, 或使用路径 B。

1. **安装应用。** 获取 `Chromium Bridge.app` (见上面的说明) 并打开。首次启
   动时它会向检测到的每一个 Chromium 系浏览器注册内置的原生消息主机, 并逐
   条列出写入的内容。系统里的其他东西一概不碰。
2. **加载扩展。** 在应用的 Setup 页点击 "Reveal folder"。在浏览器中打开
   `chrome://extensions`, 开启开发者模式, 点击"加载已解压的扩展程序", 选
   择刚才打开的目录。然后重启浏览器, 使它重新读取原生消息注册。
3. **用 Touch ID 配对。** 在应用的 Pairing 页点击 Pair; Touch ID 弹出后,
   页面会显示新密钥的指纹。在扩展的选项页批准同一枚指纹。macOS 上扩展默认
   要求完成此注册 (`requireEnrollment`), 在钉定完成之前拒绝执行任何操作
   ([ADR-0021](./adr/0021-enrollment-ceremony.md))。
4. **把命令交给 MCP 客户端。** 在 Setup 页点击 Install, 将
   `chromium-bridge` 命令放到 `~/.local/bin/chromium-bridge`, 然后在客户端
   里注册。对 Claude Code 来说, 这是整条路径中唯一的一条命令:

   ```sh
   claude mcp add chromium-bridge -- "$HOME/.local/bin/chromium-bridge"
   ```

   Claude Desktop 等使用 JSON 配置的客户端, 在 `mcpServers` 里添加一个指向
   同一绝对路径、不带参数的条目即可。

5. **试一试。** 让客户端"列出我的浏览器标签页"。第一次操作新站点时, 点击
   Chromium Bridge 工具栏图标并批准该源。

装好之后应用依然有用: 它是浏览器注册、Touch ID 注册、受信 MCP 客户端、紧
急停止开关和审计日志的控制面板。见 [desktop-app.md](./desktop-app.md)。

## 路径 B: CLI (macOS、Linux、Windows)

CLI 只需要二进制本身。在 Linux、Windows、无界面机器和 CI 上它是自然选择。

1. **获取二进制。** 从[最新发布版](https://github.com/Vivswan/chromium-bridge/releases/latest)
   下载对应平台的压缩包并解压。想先校验的话, 核对发布的 SHA-256 和构建来源
   证明; 命令见 [SECURITY.md](../SECURITY.md#release-artifact-integrity)。
   也可以从源码构建: `cargo build --release`。
2. **放到稳定的位置。** 注册指向二进制当前所在的路径, 所以位置不能消失。
   Linux 上 `~/.local/lib/chromium-bridge/` 很合适; macOS 上放在家目录下任
   意位置都可以。 (AppImage 挂载点或临时目录不稳定, `doctor --fix` 检测到
   会发出警告。)
3. **注册给浏览器:**

   ```sh
   ./chromium-bridge doctor --fix                       # 每一个检测到的浏览器
   ./chromium-bridge doctor --fix --browser chrome,brave
   ./chromium-bridge doctor --fix --manifest-dir DIR    # 表外的 Chromium 变体
                                                        # (macOS/Linux)
   ```

   修复即幂等的重新注册: 全新机器上它就是安装, 移动二进制后它就是修复, 跑
   两遍也无害。`chromium-bridge doctor --list` 只读地显示状态,
   `chromium-bridge uninstall` 精确撤销写入过的内容。

4. **加载扩展。** 发布压缩包内含 `extension/dist/`; 通过
   `chrome://extensions` (开发者模式, "加载已解压的扩展程序") 加载 (源码
   检出则先构建, 再加载 `build/extension/chrome-mv3`)。重启浏览
   器。

5. **在 macOS 上配对。** 运行 `chromium-bridge pair` (Touch ID 弹出, 并打
   印密钥指纹), 然后在扩展的选项页批准该指纹。macOS 上扩展默认要求完成此
   注册, 在钉定完成之前拒绝执行任何操作。Linux 和 Windows 没有 Secure
   Enclave, 跳过这一步。

6. **接入 MCP 客户端**, 指向二进制的绝对路径, 方法同路径 A。

完整命令参考 (配对、受信客户端、吊销、紧急停止开关、审计日志) 见
[cli.md](./cli.md)。

## 两条路径之后: 你应该看到什么

- `chromium-bridge doctor` 报告你的浏览器注册状态为 `ok`; MCP 客户端会话
  打开后, 报告服务器可达。
- 扩展的工具栏图标显示连接状态。
- 对新站点的第一次工具调用会在浏览器里弹出批准提示; 高风险操作弹出确认窗
  口; 已注册的 Mac 上, `page_eval` 和 `page_upload` 会弹出 Touch ID。

## 推荐的加固

配对 (路径 A 第 3 步 / 路径 B 第 5 步) 在 macOS 上是必需的, 也是把最高风
险确认升级为硬件 Touch ID 的机制。另有一个可选仪式绑定 MCP 客户端一侧:

- `chromium-bridge pair-client` (或应用的 Clients 页) 创建受信客户端允许列
  表。列表一旦存在, 只有代码身份经过认证且被你批准的 MCP 客户端才会被服
  务, 任何一方都可以随时吊销。

两者的细节见 [cli.md](./cli.md) 和
[威胁模型](./security/threat-model.md)。

## 卸载

- 应用路径: 退出应用, 删除 `Chromium Bridge.app`, 并在
  `chrome://extensions` 移除扩展。注册指向应用包内部; 用
  `chromium-bridge uninstall` (Setup 页安装的 CLI 或任意一份二进制) 清理注
  册。
- CLI 路径: `chromium-bridge uninstall` 移除本项目写入的清单和包装脚本,
  且仅移除这些。然后删除二进制, 并在浏览器里移除扩展。

注册状态是独立的: `chromium-bridge revoke` 删除 Secure Enclave 密钥, 扩展
的选项页清除其钉定。
