# 发布: release-please 流水线

> 合并发布 PR 会创建一个草稿发布, 并在同一次 CI 运行中构建预构建产物、安装程序、校验和、来源证明和 SBOM 并附加到草稿上, 然后发布它并在 Homebrew tap 上打开版本提升的拉取请求。哪个版本号因哪种变更而变动, 见下文的[版本](#版本); 磁盘上的注册路径见 [architecture.md 第 4.3 节](./architecture.md#43-磁盘上的产物); 这些作业背后的工具链见 [development.md](./development.md)。

## 触发: 合并发布 PR

发布由 **release-please** 驱动。`main` 上的约定式提交会累积到一个滚动的发布 PR (`chore(main): release X.Y.Z`) 中; 合并它就会创建发布。GitHub 发布一旦公开就不可变 (标签和资产会冻结), 所以每次发布都走同样的三个步骤, 始终先草稿, 全部在一次 CI 运行中完成:

1. release-please 以**草稿**形式创建发布, 其标签已被强制打在合并 SHA 上 (`release-please-config.json` 中的 `draft` + `force-tag-creation`)。发布正文是 release-please 的变更日志条目; 不会添加 GitHub 自动生成的说明。
2. 下面的打包作业 - 本仓库在仓库自有的 `.github/workflows/update-release.yml` 钩子中的作业 - 修改草稿: 它们从标签构建, 并用 `gh release upload` 附加各自的资产。钩子中的 `mark-prerelease` 作业在发布仍是草稿时把带后缀的标签标记为预发布。
3. 舰队 (fleet) 的 `publish-release` 阶段等待每个钩子作业完成, 为草稿上的每个资产证明构建来源并汇总到单个 `attestation.json` 资产中, 然后把草稿转为正式发布。发布在结构上是最后一步: 钩子无法重排或跳过它。

如果流水线在草稿创建之后中断, 重新运行无法重新创建它 (release-please 会看到已强制创建的标签); 请重新运行失败的作业, 或者用 `gh release upload <tag> <assets> --clobber` 和 `gh release edit <tag> --draft=false` 手动完成 (手动发布的版本不带 `attestation.json`)。

这套机制是由平台管理的 `.github/workflows/ci.yml`, 位于 all-green 门禁的下游, 所以发布只可能从绿色的 `main` 上创建, 打包作业也在同一次 CI 运行中执行。它的作业按顺序为:

- **`release`** 调用舰队的 `fleet-release.yml`: release-please 创建草稿。
- **`update-release`** 调用本仓库的钩子, 仅当 release-please 报告 `release_created` 时。
- **`publish-release`** 调用舰队的 `fleet-release-publish.yml`: 先证明, 再发布。
- **`site`** 在发布之后、同一次运行中部署站点。
- **`update-release-pr`** 在 release-please 创建或刷新发布 PR 时调用仓库自有的 `update-release-pr.yml` 钩子。

`update-release.yml` 内的最后一个作业 `release-ready` 只有在每个打包作业都成功时才通过: 被跳过或取消的作业会阻止发布, 而 `continue-on-error` 的作业 (SBOM、Homebrew) 在那里算作成功。由平台管理的发布阶段只看到钩子的汇总结果, 所以正是这个作业防止意外跳过的作业流入正式发布。

当版本提升改变了锁文件时, 发布 PR 会在 release-please 自己的提交之外多带一个提交: `update-release-pr` 钩子为提升后的版本重新锁定 `Cargo.lock`、`src/packages/core/fuzz/Cargo.lock` 和 `bun.lock`, 并把这个提交推送到 PR 分支, 因为 release-please 只提升清单文件, 而每个 `--locked` 步骤都会拒绝落后的锁文件。

由平台管理的工作流只使用 `github.token` 运行; 不涉及任何仓库密钥。它的限制:

- **PR 的 CI 运行不会自行启动。** release-please 用那个令牌创建发布 PR, 钩子的推送也用它, 所以需要关闭再重新打开 PR (或向它推送) 才能运行它的检查。
- **工作流文件变更可能导致创建失败**: 如果在发布 PR 合并和创建作业之间有工作流文件变更落到 `main` 上, 就会失败, 因为 `github.token` 无法在工作流文件与 `main` 不同的提交上创建引用。下一次合并到 `main` 会再次运行 release-please 并完成创建, 或者手动创建发布。

每个打包作业的第一步是**版本一致性检查**: 去掉标签开头的 `v` 和任何 `-dev`/`-rc` 预发布后缀之后, 其核心版本必须等于 `Cargo.toml` 中的 `version`, 否则运行立即失败。Cargo 是唯一的版本来源。带后缀的标签 (例如 `v0.1.0-rc.1`) 会被标记为预发布。

## 构建矩阵与预构建压缩包

update-release.yml 在一个矩阵上构建 `binaries` 作业 (目前为 `macos-14/arm64`、`ubuntu-22.04/x64` 和 `windows-2022/x64`; Intel macOS 被**有意省略**, 因为托管运行器稀缺, Linux 则使用较旧的 glibc 基线以扩大兼容性)。对每个目标:

1. `bun scripts/build-repro.ts` 生成确定性的发布二进制。
2. `bun install --frozen-lockfile && bun run --cwd src/apps/extension build` 生成扩展包。
3. 所有内容打包为 `chromium-bridge-<tag>-<platform>-<arch>.tar.gz` (Windows 上为 `.zip`), 包含二进制、`extension/dist`、`RELEASE.txt`、`LICENSE.md` 和 `README.md`。
4. 同一个二进制被封装进该平台的安装程序 (见下一节)。
5. 生成压缩包的 `.sha256`、压缩包内二进制单独的 `.binary.sha256` 以及安装程序的 `.sha256`, 并由一个构建来源证明覆盖全部三个文件; 它的 Sigstore 捆绑包成为 `chromium-bridge-<tag>-<platform>-<arch>.attestation.jsonl` 资产。独立的扩展 zip 和 SBOM 以同样方式附带 `<asset>.attestation.jsonl` 捆绑包; `--bundle` 验证方式记录在 [SECURITY.md](../../.github/SECURITY.md#release-artifact-integrity) 中。
6. `gh release upload` 把资产附加到草稿发布; 随后舰队的 `publish-release` 阶段为草稿上的每个资产生成证明并汇总到发布级的 `attestation.json` 中, 并在所有钩子作业完成后发布。

因此用户**不需要 Rust/bun 工具链**即可安装: 注册就是二进制自己的 `chromium-bridge doctor --fix`, 见 [quickstart.md](./quickstart.md)。本仓库的工作流和舰队的发布环节中, 第三方 Action 都固定到提交 SHA; 平台自己的 action 和可复用工作流取自 `@stable`, 这是一个指向平台绿色 `main` 提交的移动标签 (信任模型见 repo-platform 的 [build-provenance.md](https://github.com/Vivswan/repo-platform/blob/main/docs/platform/build-provenance.md))。

## 安装程序: .pkg、.deb 与 .msi

每个环节把自己的二进制原样封装进该平台的安装程序。安装后步骤就是二进制自己的 `doctor --fix`, 绝不是第二套实现; 它写入的内容见 [cli.md](./cli.md#doctor---fix--uninstall-原生消息注册)。

| 环节 | 资产 | 安装到 | 安装后步骤 |
| --- | --- | --- | --- |
| macos-arm64 | `chromium-bridge-<tag>-macos-arm64.pkg` | `/usr/local/bin/chromium-bridge` | 以控制台登录用户 (`/dev/console` 的所有者) 的身份运行 `doctor --fix`, 在 Installer.app 和 `sudo installer` 下都一样; 没有人登录时失败 |
| linux-x64 | `chromium-bridge-<tag>-linux-x64.deb` | `/usr/bin/chromium-bridge` | 以 root 身份运行 `doctor --fix --system`: 每个账户的浏览器都会读取的机器级注册, 通过厂商软件包的安装目录检测; 还没有浏览器时打印提示, 安装照样成功; `dpkg -r` 会先运行 `uninstall --system` |
| windows-x64 | `chromium-bridge-<tag>-windows-x64.msi` | `%LOCALAPPDATA%\Programs\chromium-bridge\` (按用户安装, 无需提权, 加入用户的 PATH) | 以安装用户身份运行 `doctor --fix`; 首次安装失败时用 `uninstall` 回滚其注册, 升级失败时恢复之前的配置; 卸载时运行 `chromium-bridge uninstall` |

- **.deb 做机器级注册**, 因为 Debian 维护者脚本以 root 身份运行且没有用户上下文, 不得写入家目录; 二进制在 root 下拒绝按用户作用域 ([cli.md](./cli.md#doctor---fix--uninstall-原生消息注册))。
- **未检测到浏览器会导致 .pkg 和 .msi 安装失败**, 安装程序日志中会记录 `doctor --fix` 给出的原因。请先安装一个 Chromium 系浏览器, 或改用压缩包。
- **这种情况下 .deb 照样安装** (`doctor --fix` 退出码 3, 没有可注册的东西), 因为失败的维护者脚本会让 dpkg 停在半配置状态, 比 .pkg 的拒绝更糟; 因其他原因失败的注册仍会让安装失败。
- **源码:** `packaging/pkg/scripts/postinstall`、`packaging/deb/{postinst,prerm}`、`packaging/msi/chromium-bridge.wxs`, 以及 `src/apps/host/Cargo.toml` 中的 `[package.metadata.deb]` 表。`scripts/release-package.ts installer` 运行 pkgbuild、cargo-deb (`--no-build --no-strip`, 这样 .deb 携带的是经过证明的字节) 以及 WiX 3 的 candle 和 light。
- **每个拉取请求上的验证:** `.github/workflows/installers.yml` 由 `checks.yml` 在 all-green 门禁内调用, 从分支构建全部三种安装程序, 并通过 `scripts/installer-smoke.ts` 在各自的运行器上安装。Windows 环节是 HKCU 注册真正运行的地方, 也是迄今唯一运行过的地方。

**目前未签名。** Gatekeeper 会要求用户右键点击并打开 .pkg, SmartScreen 会对 .msi 发出警告。签名只需加入两个仓库密钥以及使用它们的步骤, 这些目前都还不存在:

| 平台 | 需要添加的密钥 | 需要添加到该环节的步骤 |
| --- | --- | --- |
| macOS | 一个 Developer ID Installer 证书 (`.p12` 及其密码) 和一个 App Store Connect API 密钥 | 用 `productsign` 签名 .pkg, 然后 `xcrun notarytool submit --wait` 和 `xcrun stapler staple` |
| Windows | 一个 Authenticode 证书 | 在 candle 之前对二进制、在 light 之后对 .msi 运行 `signtool sign /fd SHA256 /tr <timestamp url>` |

## Homebrew tap

`homebrew` 作业根据两个 `.tar.gz.sha256` 资产渲染 `Formula/chromium-bridge.rb` (`scripts/release-package.ts brew-formula`), 并用 `REPO_PLATFORM_TOKEN` 在 `Vivswan/homebrew-tap` 上打开一个拉取请求。

- **tap 仓库由所有者创建, 拉取请求也由所有者合并。** 在它存在之前该作业会失败, 而 `continue-on-error` 使其不会阻塞发布, 与 SBOM 相同; 在合并之前, tap 提供的是上一个 formula。
- **tap 只接收正式发布。** Homebrew 把 `1.2.3-dev` 排在 `1.2.3` 之上, 所以预发布标签不渲染 formula, 也不打开拉取请求。
- **formula 的 `post_install` 是 `doctor --fix`。** 那里失败时安装仍保留, 并带有 brew 的警告; `brew postinstall chromium-bridge` 可重试。

## SBOM: 附加到草稿的 CycloneDX

update-release.yml 中的 `sbom` 作业与打包作业并行运行 (它曾是一个解耦的 `release: published` 工作流, 但已发布的版本不可变, 所以 SBOM 必须落在草稿上):

- 它使用 `anchore/sbom-action` 从**已提交的锁文件** (`Cargo.lock` + `bun.lock`) 生成 CycloneDX JSON (`chromium-bridge.cdx.json`), 扫描声明的依赖而非已安装的目录树 (全新检出没有 `node_modules`/`target`)。
- 它为 SBOM 的构建来源生成证明 (与二进制相同的 `actions/attest-build-provenance` 步骤), 所以 `gh attestation verify chromium-bridge.cdx.json --repo <repo>` 对下载的资产有效。
- 它把 SBOM 及其 `.attestation.jsonl` 捆绑包附加到该标签的草稿发布上。

SBOM 工具故障仍然**绝不阻塞**二进制发布: 该作业是 `continue-on-error`, 所以舰队的发布阶段 (它等待每个钩子作业) 仍会运行。发布会在没有 SBOM 的情况下进行, 运行上标注的失败会提示这一点。

- **证明服务中断同样会让 SBOM 资产丢失。** 证明步骤在上传之前运行, 因为没人能验证的资产不得发布。
- **对于该标签, 这种丢失是永久的。** 已发布的版本不可变, 所以之后无法再附加 SBOM。下一次发布会重新带上。

## 版本

有三个数字都带着「版本」二字; 每个都有唯一来源和唯一含义。

| 版本 | 值 | 唯一来源 | 变更意味着什么 |
|------|------|------|----------|
| MCP JSON-RPC 版本 | 日期字符串 `2026-07-28` | [`src/packages/core/src/protocol.rs`](../../src/packages/core/src/protocol.rs) 中的 `MCP_PROTOCOL_VERSION` | MCP 客户端与 MCP 服务器之间的外部协议; 无状态, 按请求门禁, 并对使用上一修订版的客户端程序 (harness) 提供临时的旧版支持 |
| 内部桥接协议版本 | 单调递增整数 (目前为 `1`) | [`src/packages/core/src/protocol.rs`](../../src/packages/core/src/protocol.rs) 中的 `BRIDGE_PROTOCOL_VERSION` | MCP 服务器、原生消息主机与扩展之间的线路契约 |
| 扩展/二进制发布版本 | SemVer (例如 `0.1.0`) | `Cargo.toml` | 发布产物的版本, 按下文的 SemVer 规则变动 |

内部桥接协议版本只在桥接线路契约 (`BridgeReq`/`BridgeResp` 的形状、认证握手、操作与能力语义) 发生不兼容变更时才变动。新的可选字段、新工具、新能力以及增量的、由主机处理的控制帧不会提升它; 按 SemVer, 它们落在发布版本的次版本号中。两侧版本不一致时的行为见[故障排除页面](./troubleshooting.md#扩展与主机版本不一致)。

有一次平台层面的破坏性变更没有提升版本号: 移除 `requireEnrollment` 退出选项, 这使得没有 Secure Enclave 的 Mac 无法登记。线路契约没有变, 所以这个数字也没有变。

## SemVer 规则

兼容性纪律在 1.0 之前同样适用; `0.x` 不被视为可以随意破坏兼容性的许可:

- **补丁版本**: 错误修复、内部重构、日志改进; 不改变工具参数或安全语义。
- **次版本**: 新工具、新的可选字段、新能力、新配置; 向后兼容。
- **主版本**: 移除/重命名工具、改变字段含义、改变默认权限、放松安全边界, 或不兼容的桥接协议或扩展版本 (对应内部桥接协议版本的提升, 见[版本](#版本))。

## 尚未就绪 (如实说明)

- macOS **发布门禁中的真实集成测试**: 它们需要真实浏览器, 目前还不是发布门禁的一部分。
- 指引中提到的 **Web Store 上架**: 其状态与 [quickstart.md](./quickstart.md#cli-macoslinuxwindows) 第 4 步相同。

## 发布到 Chrome 应用商店

尚未完成, 也尚未决定。发布到商店会消除最大的采用障碍 (加载未打包的扩展), 但它涉及分发和安全边界, 所以按照 [GOVERNANCE](../../GOVERNANCE.md), 这是 RFC 级别的决策: 先开 issue, 绝不走快速 PR。该决策需要的事实:

- **固定 ID 陷阱。** 每次安装都依赖一个固定的扩展 ID `mkjjlmjbcljpcfkfadfmhblmmddkdihf`, 它由 [`src/packages/core/src/identity.rs`](../../src/packages/core/src/identity.rs) 中固定的清单密钥推导而来, 并由注册引擎写入主机清单的 `allowed_origins`。商店在首次上传时分配自己的 ID 并忽略清单中的 `key`, 所以商店版构建无法连接只信任固定 ID 的主机。
- **需要规划的缓解措施。** 同时信任两个 ID: 商店用户用商店的 ID, 未打包加载用固定的 ID。`PINNED_EXTENSION_ID` 是单数, 注册引擎据此只写一条 `allowed_origins` 条目, 所以要先让身份契约和 Registrar 支持多个 ID, 再由 `moon run gen` 把结果带到每份生成的副本。把商店的公钥回填到清单 `key` 是可选的, 且会改变今天的固定 ID。
- **它解决什么, 不解决什么。** 不再需要开发者模式和「加载已解压的扩展程序」; 一键安装, 能在 Chrome 重启后保留, 也适合受管 Chrome。主机安装仍然保留: 商店只分发扩展, `chromium-bridge doctor --fix` 仍然是原生消息主机的注册方式。
- **前置条件。** 一个开发者账号 (一次性费用, 由所有者注册)、一个隐私政策 URL ([隐私政策](./privacy-policy.md) 符合要求), 以及上架素材: 一到五张截图 (1280x800 或 640x400)、`moon run gen-icons` 从 `assets/icon/` 中的 SVG 源渲染到扩展公共图标目录的 128px `icon128.png`、简短和详细描述、一个分类, 以及支持和主页 URL。
- **打包。** 发布流水线已经输出 `chromium-bridge-extension-<tag>.zip`; 确认它就是可上传的包。`scripts/check-version.ts` 已经强制清单版本等于 Cargo 的版本。决定 `key` 字段是保留 (保证未打包加载的 ID 一致) 还是交给商店。
- **提交审核。** 上传, 填写数据使用披露和隐私政策, 然后提交。审核需要数天到数周, 之后的每次更新也都要经过审核。
- **发布之后。** 通过 `identity.rs` 把商店 ID 接入 `allowed_origins`; 把 README 中的「加载扩展」改为「从 Chrome 应用商店添加」, 未打包加载作为开发者路径; 更新文档; 在落地 PR 中记录这个决策, 因为按 GOVERNANCE 分发变更属于主版本变更; 可选地在 CI 中自动化上传。

审核会聚焦四个点, 每个都需要书面说明:

| 审核点 | 如实的回答 |
| --- | --- |
| `page_eval` 执行任意 JS (被拒风险最高) | 一个开发者工具, 每次调用都在扩展自有窗口中确认; 考虑让商店版构建默认禁用该工具 |
| `page_snapshot_precise` 使用的 `chrome.debugger` | 一个敏感权限, 需要单独说明 |
| 宽泛的主机权限和可选权限, 加上原生消息 | 桥接仅限 localhost, 由每次运行的密钥保护, 站点逐个授权; 链接到[安全页面](./security.md) |
| 「是否使用远程代码」 | `page_eval` 运行用户提供的 JS, 绝不运行远程获取的代码; 表单措辞要精确 |
