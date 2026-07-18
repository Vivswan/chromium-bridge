// Traditional Chinese bundle. Keys must mirror en.ts exactly; the
// Record<MessageKey, string> type makes a missing or extra key a compile
// error.
import type { MessageKey } from "./en";

export const zh_TW: Record<MessageKey, string> = {
  "app.title": "Chromium Bridge",

  "nav.overview": "總覽",
  "nav.browsers": "瀏覽器",
  "nav.pairing": "配對",
  "nav.clients": "用戶端",
  "nav.audit": "稽核",
  "nav.setup": "設定",

  "common.refresh": "重新整理",
  "common.copy": "複製",
  "common.copied": "已複製",
  "common.cancel": "取消",
  "common.error": "錯誤",
  "common.working": "處理中...",
  "common.loading": "載入中...",

  "auth.touch_id": "Touch ID",
  "auth.app_confirm": "應用程式內確認",
  "auth.cli_confirm": "終端機確認",
  "auth.extension_confirm": "擴充功能確認",

  "lang.label": "顯示語言",
  "lang.auto": "跟隨系統",

  "overview.version": "版本",
  "overview.platform": "平台",
  "overview.kill_title": "緊急停止開關",
  "overview.kill_off": "關閉 - 允許橋接活動",
  "overview.kill_engaged": "已啟用 - 所有橋接活動均被拒絕",
  "overview.kill_unreadable": "狀態無法讀取 - 所有執行點均以失敗關閉處理",
  "overview.kill_engage": "啟用緊急停止",
  "overview.kill_release": "解除緊急停止",
  "overview.kill_release_dialog_title": "解除緊急停止開關？",
  "overview.kill_release_dialog_body":
    "解除後，MCP 用戶端可以再次驅動你的瀏覽器。在支援 Touch ID 的 Mac 上會要求你驗證指紋。",
  "overview.kill_release_confirm": "解除",
  "overview.kill_released": "緊急停止已解除（由$1授權）。",
  "overview.kill_engage_hint":
    "一鍵生效，無需確認：啟用只會減少橋接的能力。使用中的瀏覽器連線會在一秒內中斷，且狀態在重新啟動後仍然保持。",
  "overview.kill_release_hint": "解除會恢復能力，因此需要使用者在場證明。",
  "overview.server_title": "MCP 伺服器",
  "overview.server_running": "鎖定檔存在",
  "overview.server_not_running": "未執行（沒有鎖定檔）。請啟動你的 MCP 用戶端。",
  "overview.server_lock_unreadable": "鎖定檔存在但無法讀取：$1",
  "overview.server_reachable": "可連線（socket 連接正常）",
  "overview.server_unreachable": "無法連線",
  "overview.server_endpoint": "端點",
  "overview.server_pid": "程序編號",
  "overview.enclave_title": "Enclave 註冊",
  "overview.host_title": "主機二進位檔",
  "overview.browsers_title": "瀏覽器註冊",
  "overview.browsers_summary": "偵測到的瀏覽器中 $2 個裡有 $1 個已註冊",
  "overview.extension_note":
    "以上檢查涵蓋應用程式、主機與 MCP 伺服器，但無法確認擴充功能已載入並連線 - 請透過擴充功能的工具列圖示確認。",
  "overview.first_run_title": "首次啟動",
  "overview.first_run_registered": "已為偵測到的瀏覽器寫入原生訊息資訊清單。",
  "overview.first_run_none": "未偵測到 Chromium 系瀏覽器。請在「瀏覽器」頁面手動新增。",
  "overview.first_run_errors": "部分註冊被拒絕：",

  "browsers.title": "瀏覽器",
  "browsers.intro":
    "每個 Chromium 瀏覽器都會讀取一個指向內建主機二進位檔的原生訊息資訊清單。註冊只寫入該清單（外加一個小型包裝指令稿）；瀏覽器本身不會被修改，且不是我們寫入的清單會被拒絕，絕不覆寫。",
  "browsers.detected": "已偵測到",
  "browsers.not_detected": "未偵測到",
  "browsers.state": "註冊狀態",
  "browsers.location": "位置",
  "browsers.register": "註冊",
  "browsers.repair": "修復",
  "browsers.unregister": "移除",
  "browsers.restart_note":
    "註冊後請重新啟動瀏覽器，讓它重新讀取註冊資訊，然後載入擴充功能（見「設定」頁面）。",
  "browsers.custom_title": "自訂瀏覽器（資訊清單目錄）",
  "browsers.custom_hint":
    "針對我們無法依名稱識別的 Chromium 建置：請提供其 NativeMessagingHosts 目錄的絕對路徑。",
  "browsers.custom_register": "註冊目錄",
  "browsers.custom_unregister": "移除目錄註冊",

  "pairing.title": "配對",
  "pairing.intro":
    "配對會在這台 Mac 的 Secure Enclave 中產生簽章金鑰。擴充功能會固定其公鑰，因此只有這台機器 - 且經你親自核准 - 才能完成註冊。",
  "pairing.key_present": "註冊金鑰已存在",
  "pairing.key_none": "未註冊",
  "pairing.key_invalid": "金鑰被拒絕 - 請視為不可信，並在下方替換",
  "pairing.key_unsupported": "此平台不支援 Secure Enclave",
  "pairing.key_error": "註冊狀態無法讀取",
  "pairing.fingerprint": "金鑰指紋（SHA-256）",
  "pairing.compare": "擴充功能的註冊畫面必須顯示與此完全一致的指紋。只有逐字元相符時才在那裡核准。",
  "pairing.pair": "配對（Touch ID）",
  "pairing.repair": "替換金鑰並重新配對",
  "pairing.revoke": "撤銷註冊",
  "pairing.touch_hint": "你的 Mac 會要求 Touch ID（或密碼）。拒絕則這台機器維持未註冊狀態。",
  "pairing.revoke_hint": "撤銷會刪除金鑰：已固定公鑰的擴充功能將以失敗關閉處理，直到你重新配對。",
  "pairing.transcript": "最近一次操作",

  "clients.title": "受信任的用戶端",
  "clients.intro":
    "一旦開始強制執行註冊，只有此清單中經過證明的 MCP 用戶端才能驅動橋接。名稱只是標籤；准入實際檢查的是錨點（二進位雜湊或簽章 Team ID）。",
  "clients.posture_unenrolled":
    "尚無允許清單：用戶端准入未被強制。配對你的第一個用戶端即可將橋接鎖定到它。",
  "clients.posture_enforced": "准入已強制：不在此清單中的一律拒絕。",
  "clients.name": "名稱",
  "clients.anchor": "錨點",
  "clients.added": "加入時間",
  "clients.revoke": "撤銷",
  "clients.empty": "尚無受信任的用戶端。",
  "clients.add_title": "新增用戶端",
  "clients.add_hint":
    "新增用戶端等於把你的瀏覽器交給它，因此需要使用者在場證明 - 你執行的程式永遠無法悄悄註冊自己。",
  "clients.anchor_hash": "二進位雜湊",
  "clients.anchor_team": "macOS 簽章 Team ID",
  "clients.name_placeholder": "例如 claude-code",
  "clients.value_placeholder_hash": "小寫十六進位雜湊",
  "clients.value_placeholder_team": "例如 3ZMH96L4V9",
  "clients.add": "新增用戶端（使用者在場）",
  "clients.add_dialog_title": "信任這個 MCP 用戶端？",
  "clients.add_dialog_body":
    "信任「$1」代表它可以驅動你的瀏覽器 - 你的分頁與登入狀態。在支援 Touch ID 的 Mac 上會要求你驗證指紋。",
  "clients.add_confirm": "信任用戶端",
  "clients.add_done": "用戶端已新增（由$1授權）。",
  "clients.hint_cli":
    "提示：在用戶端自己的終端機執行 `chromium-bridge pair-client --name <label> --this-parent`，可一步完成量測並固定。",

  "audit.title": "稽核紀錄",
  "audit.intro":
    "每一個安全相關的決定，由最早開始：工具呼叫、准入、拒絕、配對、撤銷、緊急停止開關的切換，以及擴充功能中的確認。",
  "audit.empty": "尚無稽核紀錄。",
  "audit.unrecognized": "有 $1 筆紀錄無法解析；請將該紀錄鏈視為可疑。",
  "audit.unrecognized_row": "無法辨識的紀錄（損毀、遭竄改或較新的格式）",
  "audit.time": "時間",
  "audit.kind": "事件",
  "audit.details": "詳情",
  "audit.reveal": "顯示檔案",

  "setup.title": "設定",
  "setup.mcp_title": "連接你的 MCP 用戶端",
  "setup.mcp_hint":
    "在終端機執行以下命令，將橋接註冊到 Claude Code。任何 MCP 用戶端都可以不帶參數啟動同一個二進位檔。",
  "setup.cli_title": "命令列工具",
  "setup.cli_hint":
    "在 $1 放置一個 chromium-bridge 符號連結，讓終端機可以執行 doctor、kill、pair-client 等命令。明確且可逆 - 隨時可在此移除。",
  "setup.cli_installed": "已安裝",
  "setup.cli_installed_stale": "已安裝，但指向另一個建置",
  "setup.cli_missing": "未安裝",
  "setup.cli_foreign": "已封鎖：該路徑被非 chromium-bridge 符號連結佔用；不會去動它。",
  "setup.cli_install": "安裝",
  "setup.cli_update": "指向此應用程式",
  "setup.cli_uninstall": "移除",
  "setup.cli_path_note": "請確認 $1 在你的 PATH 中。",
  "setup.ext_title": "載入擴充功能",
  "setup.ext_hint": "橋接透過擴充功能驅動瀏覽器。每個瀏覽器載入一次：",
  "setup.ext_step1": "開啟 chrome://extensions 並啟用開發人員模式。",
  "setup.ext_step2": "點選「載入未封裝項目」，選擇下方的資料夾。",
  "setup.ext_step3": "釘選 Chromium Bridge 圖示，並核准它可以存取的網站。",
  "setup.ext_reveal": "顯示資料夾",
  "setup.ext_missing": "此建置中找不到已解壓縮的擴充功能資料夾。",
  "setup.language_title": "語言",
};
