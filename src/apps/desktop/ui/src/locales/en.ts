// English (canonical) message corpus for the desktop control panel. Flat
// keys, positional $1 substitutions, no plurals - the same shape as the
// extension's bundles. `MessageKey` is derived from this object, so the zh
// bundles are exhaustively checked by the compiler: a missing or extra key
// is a type error, not a runtime fallback.
export const en = {
  "app.title": "Chromium Bridge",

  "nav.overview": "Overview",
  "nav.browsers": "Browsers",
  "nav.pairing": "Pairing",
  "nav.clients": "Clients",
  "nav.audit": "Audit",
  "nav.setup": "Setup",

  "common.refresh": "Refresh",
  "common.copy": "Copy",
  "common.copied": "Copied",
  "common.cancel": "Cancel",
  "common.error": "Error",
  "common.working": "Working...",
  "common.loading": "Loading...",

  "auth.touch_id": "Touch ID",
  "auth.app_confirm": "in-app confirmation",
  "auth.cli_confirm": "terminal confirmation",
  "auth.extension_confirm": "extension confirmation",

  "lang.label": "Display language",
  "lang.auto": "Match system",

  "overview.version": "Version",
  "overview.platform": "Platform",
  "overview.kill_title": "Kill switch",
  "overview.kill_off": "Off - bridge activity permitted",
  "overview.kill_engaged": "ENGAGED - all bridge activity is refused",
  "overview.kill_unreadable": "State unreadable - every enforcement point is failing closed",
  "overview.kill_engage": "Engage kill switch",
  "overview.kill_release": "Release kill switch",
  "overview.kill_release_dialog_title": "Release the kill switch?",
  "overview.kill_release_dialog_body":
    "Releasing lets MCP clients drive your browser again. On a Touch ID Mac you will be asked for your fingerprint.",
  "overview.kill_release_confirm": "Release",
  "overview.kill_released": "Kill switch released (authorized by $1).",
  "overview.kill_engage_hint":
    "One click, no confirmation: engaging only ever reduces what the bridge can do. Live browser connections drop within a second and the state survives restarts.",
  "overview.kill_release_hint":
    "Releasing restores capability, so it requires proof of user presence.",
  "overview.server_title": "MCP server",
  "overview.server_running": "Lock file present",
  "overview.server_not_running": "Not running (no lock file). Start your MCP client.",
  "overview.server_lock_unreadable": "Lock file present but unreadable: $1",
  "overview.server_reachable": "Reachable (socket connect OK)",
  "overview.server_unreachable": "Not reachable",
  "overview.server_endpoint": "Endpoint",
  "overview.server_pid": "PID",
  "overview.enclave_title": "Enclave enrollment",
  "overview.host_title": "Host binary",
  "overview.browsers_title": "Browser registrations",
  "overview.browsers_summary": "$1 of $2 detected browsers registered",
  "overview.extension_note":
    "These checks cover the app, host, and MCP server. They cannot confirm the extension is loaded and connected - verify that from the extension's toolbar icon.",
  "overview.first_run_title": "First launch",
  "overview.first_run_registered":
    "Registered the native-messaging manifests for your detected browsers.",
  "overview.first_run_none":
    "No Chromium-family browser was detected. Add one on the Browsers page.",
  "overview.first_run_errors": "Some registrations were refused:",

  "browsers.title": "Browsers",
  "browsers.intro":
    "Each Chromium browser reads a native-messaging manifest that points at the bundled host binary. Registering writes only that manifest (plus a small wrapper script); the browser itself is never modified, and a manifest we did not write is refused, never overwritten.",
  "browsers.detected": "Detected",
  "browsers.not_detected": "Not detected",
  "browsers.state": "Registration",
  "browsers.location": "Location",
  "browsers.register": "Register",
  "browsers.repair": "Repair",
  "browsers.unregister": "Remove",
  "browsers.restart_note":
    "After registering, restart the browser so it re-reads its registrations, then load the extension (Setup page).",
  "browsers.custom_title": "Custom browser (manifest directory)",
  "browsers.custom_hint":
    "For a Chromium build we do not know by name: give the absolute path of its NativeMessagingHosts directory.",
  "browsers.custom_register": "Register directory",
  "browsers.custom_unregister": "Remove directory registration",

  "pairing.title": "Pairing",
  "pairing.intro":
    "Pairing mints a signing key inside this Mac's Secure Enclave. The extension pins the public key, so only this machine - with you physically approving - can complete an enrollment.",
  "pairing.key_present": "Enrollment key present",
  "pairing.key_none": "Not enrolled",
  "pairing.key_invalid": "Key REJECTED - treat it as untrusted and replace it below",
  "pairing.key_unsupported": "Secure Enclave is not supported on this platform",
  "pairing.key_error": "Enrollment state unreadable",
  "pairing.fingerprint": "Key fingerprint (SHA-256)",
  "pairing.compare":
    "The extension's enrollment screen must show EXACTLY this fingerprint. Approve it there only if it matches character for character.",
  "pairing.pair": "Pair (Touch ID)",
  "pairing.repair": "Replace key and re-pair",
  "pairing.revoke": "Revoke enrollment",
  "pairing.touch_hint":
    "Your Mac will ask for Touch ID (or your password). Declining leaves the machine unenrolled.",
  "pairing.revoke_hint":
    "Revoking deletes the key: a pinned extension fails closed until you pair again.",
  "pairing.transcript": "Last operation",

  "clients.title": "Trusted clients",
  "clients.intro":
    "Once enrollment is enforced, only attested MCP clients on this list may drive the bridge. The name is a label; the anchor (binary hash or signing Team ID) is what admission actually checks.",
  "clients.posture_unenrolled":
    "No allowlist yet: client admission is not enforced. Pair your first client to lock the bridge to it.",
  "clients.posture_enforced": "Admission enforced: anything not on this list is refused.",
  "clients.name": "Name",
  "clients.anchor": "Anchor",
  "clients.added": "Added",
  "clients.revoke": "Revoke",
  "clients.empty": "No trusted clients.",
  "clients.add_title": "Add a client",
  "clients.add_hint":
    "Adding a client grants it your browser, so it requires proof of user presence - a program you run can never enroll itself silently.",
  "clients.anchor_hash": "Binary hash",
  "clients.anchor_team": "macOS signing Team ID",
  "clients.name_placeholder": "e.g. claude-code",
  "clients.value_placeholder_hash": "lowercase hex hash",
  "clients.value_placeholder_team": "e.g. 3ZMH96L4V9",
  "clients.add": "Add client (user presence)",
  "clients.add_dialog_title": "Trust this MCP client?",
  "clients.add_dialog_body":
    "Trusting '$1' lets it drive your browser - your tabs and logins. On a Touch ID Mac you will be asked for your fingerprint.",
  "clients.add_confirm": "Trust client",
  "clients.add_done": "Client added (authorized by $1).",
  "clients.hint_cli":
    "Tip: from the client's own terminal, `chromium-bridge pair-client --name <label> --this-parent` measures and pins it in one step.",

  "audit.title": "Audit trail",
  "audit.intro":
    "Every security-relevant decision, oldest first: tool calls, admissions, refusals, pairings, revocations, kill-switch transitions, and the extension's confirmations.",
  "audit.empty": "No audit records yet.",
  "audit.unrecognized": "$1 record(s) could not be parsed; treat the trail as suspect.",
  "audit.unrecognized_row": "UNRECOGNIZED RECORD (corrupt, tampered, or newer schema)",
  "audit.time": "Time",
  "audit.kind": "Event",
  "audit.details": "Details",
  "audit.reveal": "Show file",

  "setup.title": "Setup",
  "setup.mcp_title": "Connect your MCP client",
  "setup.mcp_hint":
    "Run this in a terminal to register the bridge with Claude Code. Any MCP client can launch the same binary with no arguments.",
  "setup.cli_title": "Command-line tool",
  "setup.cli_hint":
    "Puts a chromium-bridge symlink at $1 so a terminal can run doctor, kill, pair-client, and the rest. Explicit and reversible - remove it here any time.",
  "setup.cli_installed": "Installed",
  "setup.cli_installed_stale": "Installed, but pointing at another build",
  "setup.cli_missing": "Not installed",
  "setup.cli_foreign":
    "Blocked: something that is not a chromium-bridge symlink occupies the path; it will not be touched.",
  "setup.cli_install": "Install",
  "setup.cli_update": "Point at this app",
  "setup.cli_uninstall": "Remove",
  "setup.cli_path_note": "Make sure $1 is on your PATH.",
  "setup.ext_title": "Load the extension",
  "setup.ext_hint":
    "The bridge drives the browser through its extension. Load it once per browser:",
  "setup.ext_step1": "Open chrome://extensions and enable Developer mode.",
  "setup.ext_step2": 'Click "Load unpacked" and choose the folder below.',
  "setup.ext_step3": "Pin the Chromium Bridge icon and approve the sites it may reach.",
  "setup.ext_reveal": "Reveal folder",
  "setup.ext_missing": "The unpacked extension folder was not found in this build.",
  "setup.language_title": "Language",
} as const;

export type MessageKey = keyof typeof en;
