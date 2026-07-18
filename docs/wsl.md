# WSL usage guide

WSL can run chromium-bridge in two ways. Which one to pick depends on **which
operating system Chrome runs in**. The MCP server, the native host Chrome
launches, and Chrome itself must all belong to the same operating system
environment.

## Mode 1: WSL client + Windows Chrome (recommended)

This is the most common WSL setup: the MCP client (Codex, Claude Code, and so
on) runs in WSL, while the daily browser is still Windows Chrome.

1. On Windows, extract the Windows release archive (or build from source),
   run `chromium-bridge.exe doctor --fix` there, and load the archive's
   `extension/dist` into Windows Chrome.
2. In the WSL MCP configuration, run the Windows-installed `.exe` directly.
   WSL interop launches it as a Windows process, so it shares the same
   registry, `%LOCALAPPDATA%` lock file, and Native Messaging host as Windows
   Chrome.

Example `~/.codex/config.toml` for Codex:

```toml
[mcp_servers.chromium-bridge]
command = "/mnt/c/Users/YOUR_WINDOWS_USER/AppData/Local/chromium-bridge/chromium-bridge.exe"
args = []
```

Replace `YOUR_WINDOWS_USER` with your Windows username and confirm the path
exists (the example assumes the binary lives in
`%LOCALAPPDATA%\chromium-bridge`; use wherever you extracted it). This mode
requires neither a Linux install in WSL nor Chrome in WSL.

## Mode 2: WSLg + Linux Chrome/Chromium

If the browser itself runs inside WSLg, use a native Linux install. Install
Google Chrome or Chromium in WSL, put the Linux `chromium-bridge` binary at a
stable path in the WSL filesystem, then register it:

```sh
./chromium-bridge doctor --fix                    # every detected browser
./chromium-bridge doctor --fix --browser chrome   # Google Chrome only
./chromium-bridge doctor --fix --browser chromium # Chromium only
```

Default locations:

- Manifests:
  `~/.config/google-chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json`
  and `~/.config/chromium/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json`
- Runtime lock file: `$XDG_RUNTIME_DIR/chromium-bridge/run.lock`; without
  `XDG_RUNTIME_DIR` it falls back to `$XDG_CACHE_HOME/chromium-bridge/run.lock`
  or `~/.cache/chromium-bridge/run.lock`

Load the release archive's `extension/dist` (or a built
`src/apps/extension/dist/chrome-mv3`) in Linux Chrome/Chromium at
`chrome://extensions`, then configure the MCP client to run the
Linux binary:

```toml
[mcp_servers.chromium-bridge]
command = "/home/YOUR_WSL_USER/.local/lib/chromium-bridge/chromium-bridge"
args = []
```

## Do not mix across systems

- Windows Chrome cannot read the Linux Native Messaging manifest inside WSL,
  and cannot launch a Linux ELF binary.
- Linux Chrome in WSLg does not read the Windows registry, and cannot use
  Windows Chrome's Native Messaging registration.
- Merely launching a Windows `.exe` from WSL is not mixing; that process is
  still a Windows process, which is exactly why mode 1 works.

When connection problems appear, first confirm Chrome, the native host, and
the MCP server all land on the same side, then check Windows'
`%LOCALAPPDATA%\chromium-bridge\run.lock` or the Linux XDG lock file
respectively.
