# 快速上手: 安装与首次使用

> 本文是 [quickstart.md](./quickstart.md) 的简体中文翻译。以英文版为准;
> 繁體中文版见 [quickstart.zh_TW.md](./quickstart.zh_TW.md)。

本指南带你从下载走到在 MCP 客户端里成功执行"列出我的浏览器标签页"。入口
是 CLI (macOS、Linux、Windows)。

开始之前, 请先阅读 [README](../README.zh_CN.md) 里的安全摘要: 这个工具驱动
的是你已登录的浏览器, 它向你展示的确认提示就是安全模型本身, 而不是麻烦。

## CLI (macOS、Linux、Windows)

CLI 只需要二进制本身, 在桌面机器、无界面机器和 CI 上都一样。目前唯一的例外
是 macOS 上的配对 (第 5 步), 它需要一个带应用标识符签名的构建。

1. **获取二进制。** 从[最新发布版](https://github.com/Vivswan/chromium-bridge/releases/latest)
   下载对应平台的压缩包并解压。想先校验的话, 核对发布的 SHA-256 和构建来源
   证明; 命令见 [SECURITY.md](../.github/SECURITY.md#release-artifact-integrity)。
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
   印密钥指纹), 然后在扩展的选项页批准该指纹。macOS 上扩展无条件要求完成
   此注册 (ADR-0032 第 5 阶段移除了旧的 `requireEnrollment` 开关), 在钉定
   完成之前拒绝执行任何操作。目前配对需要一个带应用标识符签名的构建: 未签
   名的发布二进制无法创建 Enclave 密钥, WebAuthn 在场验证轨道将取消这一要
   求。Linux 和 Windows 没有 Secure Enclave, 跳过这一步。

6. **接入 MCP 客户端**, 指向二进制的绝对路径。以 Claude Code 为例:

   ```sh
   claude mcp add chromium-bridge -- /absolute/path/to/chromium-bridge
   ```

   Claude Desktop 等使用 JSON 配置的客户端, 在 `mcpServers` 里添加一个指向
   同一绝对路径、不带参数的条目即可。

完整命令参考 (配对、受信客户端、吊销、紧急停止开关、审计日志) 见
[cli.md](./cli.md)。

## 你应该看到什么

- `chromium-bridge doctor` 报告你的浏览器注册状态为 `ok`; MCP 客户端会话
  打开后, 报告服务器可达。
- 扩展的工具栏图标显示连接状态。
- 对新站点的第一次工具调用会在浏览器里弹出批准提示; 高风险操作弹出确认窗
  口; 已注册的 Mac 上, `page_eval` 和 `page_upload` 会弹出 Touch ID。

## 推荐的加固

配对 (第 5 步) 在 macOS 上是必需的, 也是把最高风
险确认升级为硬件 Touch ID 的机制。另有一个可选仪式绑定 MCP 客户端一侧:

- `chromium-bridge pair-client` 创建受信客户端允许列表。列表一旦存在, 只有代码身份经过认证且被你批准的 MCP 客户端才会被服
  务, 任何一方都可以随时吊销。

两者的细节见 [cli.md](./cli.md) 和
[威胁模型](./security/threat-model.md)。

## 卸载

- `chromium-bridge uninstall` 移除本项目写入的清单和包装脚本,
  且仅移除这些。然后删除二进制, 并在浏览器里移除扩展。

注册状态是独立的: `chromium-bridge revoke` 删除 Secure Enclave 密钥, 扩展
的选项页清除其钉定。
