// Simplified Chinese bundle. Keys must mirror en.ts exactly; the
// Record<MessageKey, string> type makes a missing or extra key a compile
// error.
import type { MessageKey } from "./en";

export const zh_CN: Record<MessageKey, string> = {
  "app.title": "Chromium Bridge",

  "nav.overview": "概览",
  "nav.browsers": "浏览器",
  "nav.pairing": "配对",
  "nav.clients": "客户端",
  "nav.audit": "审计",
  "nav.setup": "设置",

  "common.refresh": "刷新",
  "common.copy": "复制",
  "common.copied": "已复制",
  "common.cancel": "取消",
  "common.error": "错误",
  "common.working": "处理中...",
  "common.loading": "加载中...",

  "auth.touch_id": "Touch ID",
  "auth.app_confirm": "应用内确认",
  "auth.cli_confirm": "终端确认",
  "auth.extension_confirm": "扩展确认",

  "lang.label": "显示语言",
  "lang.auto": "跟随系统",

  "overview.version": "版本",
  "overview.platform": "平台",
  "overview.kill_title": "紧急停止开关",
  "overview.kill_off": "关闭 - 桥接活动被允许",
  "overview.kill_engaged": "已启用 - 所有桥接活动均被拒绝",
  "overview.kill_unreadable": "状态不可读 - 所有执行点均按失败关闭处理",
  "overview.kill_engage": "启用紧急停止",
  "overview.kill_release": "解除紧急停止",
  "overview.kill_release_dialog_title": "解除紧急停止开关？",
  "overview.kill_release_dialog_body":
    "解除后，MCP 客户端可以再次驱动你的浏览器。在支持 Touch ID 的 Mac 上会要求你验证指纹。",
  "overview.kill_release_confirm": "解除",
  "overview.kill_released": "紧急停止已解除（由$1授权）。",
  "overview.kill_engage_hint":
    "一键生效，无需确认：启用只会减少桥接的能力。活动的浏览器连接会在一秒内断开，且状态在重启后仍然保持。",
  "overview.kill_release_hint": "解除会恢复能力，因此需要用户在场证明。",
  "overview.server_title": "MCP 服务器",
  "overview.server_running": "锁文件存在",
  "overview.server_not_running": "未运行（没有锁文件）。请启动你的 MCP 客户端。",
  "overview.server_lock_unreadable": "锁文件存在但不可读：$1",
  "overview.server_reachable": "可达（套接字连接正常）",
  "overview.server_unreachable": "不可达",
  "overview.server_endpoint": "端点",
  "overview.server_pid": "进程号",
  "overview.enclave_title": "Enclave 注册",
  "overview.host_title": "主机二进制",
  "overview.browsers_title": "浏览器注册",
  "overview.browsers_summary": "已检测到的浏览器中 $2 个里有 $1 个已注册",
  "overview.extension_note":
    "以上检查涵盖应用、主机和 MCP 服务器，但无法确认扩展已加载并连接 - 请通过扩展的工具栏图标确认。",
  "overview.first_run_title": "首次启动",
  "overview.first_run_registered": "已为检测到的浏览器写入原生消息清单。",
  "overview.first_run_none": "未检测到 Chromium 系浏览器。请在“浏览器”页面手动添加。",
  "overview.first_run_errors": "部分注册被拒绝：",

  "browsers.title": "浏览器",
  "browsers.intro":
    "每个 Chromium 浏览器都会读取一个指向内置主机二进制的原生消息清单。注册只写入该清单（外加一个小的包装脚本）；浏览器本身不会被修改，且不是我们写入的清单会被拒绝，绝不覆盖。",
  "browsers.detected": "已检测到",
  "browsers.not_detected": "未检测到",
  "browsers.state": "注册状态",
  "browsers.location": "位置",
  "browsers.register": "注册",
  "browsers.repair": "修复",
  "browsers.unregister": "移除",
  "browsers.restart_note":
    "注册后请重启浏览器，让它重新读取注册信息，然后加载扩展（见“设置”页面）。",
  "browsers.custom_title": "自定义浏览器（清单目录）",
  "browsers.custom_hint":
    "针对我们无法按名称识别的 Chromium 构建：请给出其 NativeMessagingHosts 目录的绝对路径。",
  "browsers.custom_register": "注册目录",
  "browsers.custom_unregister": "移除目录注册",

  "pairing.title": "配对",
  "pairing.intro":
    "配对会在这台 Mac 的 Secure Enclave 中生成签名密钥。扩展固定其公钥，因此只有这台机器 - 且经你亲自批准 - 才能完成注册。",
  "pairing.key_present": "注册密钥已存在",
  "pairing.key_none": "未注册",
  "pairing.key_invalid": "密钥被拒绝 - 请视为不可信，并在下方替换",
  "pairing.key_unsupported": "此平台不支持 Secure Enclave",
  "pairing.key_error": "注册状态不可读",
  "pairing.fingerprint": "密钥指纹（SHA-256）",
  "pairing.compare": "扩展的注册界面必须显示与此完全一致的指纹。只有逐字符匹配时才在那里批准。",
  "pairing.pair": "配对（Touch ID）",
  "pairing.repair": "替换密钥并重新配对",
  "pairing.revoke": "撤销注册",
  "pairing.touch_hint": "你的 Mac 会要求 Touch ID（或密码）。拒绝则这台机器保持未注册状态。",
  "pairing.revoke_hint": "撤销会删除密钥：已固定公钥的扩展将按失败关闭处理，直到你重新配对。",
  "pairing.transcript": "最近一次操作",

  "clients.title": "受信任的客户端",
  "clients.intro":
    "一旦开始强制执行注册，只有此列表中经过证明的 MCP 客户端才能驱动桥接。名称只是标签；准入实际检查的是锚点（二进制哈希或签名 Team ID）。",
  "clients.posture_unenrolled":
    "尚无允许列表：客户端准入未被强制。配对你的第一个客户端即可将桥接锁定到它。",
  "clients.posture_enforced": "准入已强制：不在此列表中的一律拒绝。",
  "clients.name": "名称",
  "clients.anchor": "锚点",
  "clients.added": "添加时间",
  "clients.revoke": "撤销",
  "clients.empty": "暂无受信任的客户端。",
  "clients.add_title": "添加客户端",
  "clients.add_hint":
    "添加客户端等于把你的浏览器交给它，因此需要用户在场证明 - 你运行的程序永远无法悄悄注册自己。",
  "clients.anchor_hash": "二进制哈希",
  "clients.anchor_team": "macOS 签名 Team ID",
  "clients.name_placeholder": "例如 claude-code",
  "clients.value_placeholder_hash": "小写十六进制哈希",
  "clients.value_placeholder_team": "例如 3ZMH96L4V9",
  "clients.add": "添加客户端（用户在场）",
  "clients.add_dialog_title": "信任这个 MCP 客户端？",
  "clients.add_dialog_body":
    "信任“$1”意味着它可以驱动你的浏览器 - 你的标签页和登录状态。在支持 Touch ID 的 Mac 上会要求你验证指纹。",
  "clients.add_confirm": "信任客户端",
  "clients.add_done": "客户端已添加（由$1授权）。",
  "clients.hint_cli":
    "提示：在客户端自己的终端里运行 `chromium-bridge pair-client --name <label> --this-parent`，可一步完成测量并固定。",

  "audit.title": "审计记录",
  "audit.intro":
    "每一个安全相关的决定，从最早开始：工具调用、准入、拒绝、配对、撤销、紧急停止开关的切换，以及扩展中的确认。",
  "audit.empty": "暂无审计记录。",
  "audit.unrecognized": "有 $1 条记录无法解析；请将该记录链视为可疑。",
  "audit.unrecognized_row": "无法识别的记录（损坏、被篡改或更新的格式）",
  "audit.time": "时间",
  "audit.kind": "事件",
  "audit.details": "详情",
  "audit.reveal": "显示文件",

  "setup.title": "设置",
  "setup.mcp_title": "连接你的 MCP 客户端",
  "setup.mcp_hint":
    "在终端中运行以下命令，将桥接注册到 Claude Code。任何 MCP 客户端都可以不带参数启动同一个二进制。",
  "setup.cli_title": "命令行工具",
  "setup.cli_hint":
    "在 $1 放置一个 chromium-bridge 符号链接，让终端可以运行 doctor、kill、pair-client 等命令。显式且可逆 - 随时可在此移除。",
  "setup.cli_installed": "已安装",
  "setup.cli_installed_stale": "已安装，但指向另一个构建",
  "setup.cli_missing": "未安装",
  "setup.cli_foreign": "已阻止：该路径被非 chromium-bridge 符号链接占用；不会去动它。",
  "setup.cli_install": "安装",
  "setup.cli_update": "指向此应用",
  "setup.cli_uninstall": "移除",
  "setup.cli_path_note": "请确认 $1 在你的 PATH 中。",
  "setup.ext_title": "加载扩展",
  "setup.ext_hint": "桥接通过扩展驱动浏览器。每个浏览器加载一次：",
  "setup.ext_step1": "打开 chrome://extensions 并启用开发者模式。",
  "setup.ext_step2": "点击“加载已解压的扩展程序”，选择下方的文件夹。",
  "setup.ext_step3": "固定 Chromium Bridge 图标，并批准它可以访问的站点。",
  "setup.ext_reveal": "显示文件夹",
  "setup.ext_missing": "此构建中未找到已解压的扩展文件夹。",
  "setup.language_title": "语言",
};
