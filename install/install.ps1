# install.ps1 - build browser-bridge and register the native messaging host for
# any Chromium-based browser (current Windows user, HKCU).

[CmdletBinding()]
param(
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId = 'mkjjlmjbcljpcfkfadfmhblmmddkdihf',
    # Which browsers to register the native host for: "auto" (every known
    # browser present in the registry; the default), "all" (every known
    # browser), "both" (chrome,chromium), or a comma-separated list of keys:
    # chrome,chromium,brave,edge,vivaldi,opera.
    [string]$Browser = 'auto',
    # Escape hatch: register under these exact NativeMessagingHosts registry
    # keys. Targets any Chromium browser not in the table and overrides
    # -Browser. Pass an array for more than one, e.g. -NmRegistry 'keyA','keyB'
    # (a single "keyA,keyB" string is one literal key, not split). Re-pass the
    # same keys to -Uninstall to remove these registrations.
    [string[]]$NmRegistry,
    # Remove exactly what this installer places (binary, native-host manifest,
    # HKCU registry keys for every known browser, run.lock) and leave the browser
    # and extension untouched. Re-pass any -NmRegistry key to clear it too.
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
# Project root. In a release zip the installer sits at the archive root next to
# extension\ (Root == Here); in the source tree it lives in install\ with the
# project one level up (Root == Here\..). Detect by which layout is beside us.
if ((Test-Path -LiteralPath (Join-Path $Here 'extension')) -or
    (Test-Path -LiteralPath (Join-Path $Here 'Cargo.toml'))) {
    $Root = $Here
} else {
    $Root = Split-Path -Parent $Here
}
$HostName = 'com.browser_bridge.host'
$InstallDir = Join-Path $env:LOCALAPPDATA 'browser-bridge'
$BinaryName = 'browser-bridge.exe'

# Registry root each Chromium browser creates for the current user. Every build
# reads an identical manifest; only this vendor key differs. Single source of
# truth for the browsers we know by name; -NmRegistry targets any other.
$BrowserRoots = [ordered]@{
    chrome   = 'HKCU:\Software\Google\Chrome'
    chromium = 'HKCU:\Software\Chromium'
    brave    = 'HKCU:\Software\BraveSoftware\Brave-Browser'
    edge     = 'HKCU:\Software\Microsoft\Edge'
    vivaldi  = 'HKCU:\Software\Vivaldi'
    opera    = 'HKCU:\Software\Opera Software'
}

function Get-NativeHostKey {
    param([string]$Browser)
    "$($BrowserRoots[$Browser])\NativeMessagingHosts\$HostName"
}

function Resolve-BrowserSelection {
    param([string]$Selector)
    switch ($Selector) {
        'all'  { return @($BrowserRoots.Keys) }
        'both' { return @('chrome', 'chromium') }
        'auto' {
            $found = @($BrowserRoots.Keys | Where-Object { Test-Path -LiteralPath $BrowserRoots[$_] })
            if ($found.Count -gt 0) { return $found }
            Write-Host '[install] no Chromium browser detected in registry; defaulting to Google Chrome'
            return @('chrome')
        }
        default {
            $keys = @($Selector -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            if ($keys.Count -eq 0) { throw "-Browser selected no known browser: '$Selector'" }
            foreach ($key in $keys) {
                if (-not $BrowserRoots.Contains($key)) { throw "unknown -Browser key: '$key'" }
            }
            return $keys
        }
    }
}

if ($Uninstall) {
    Write-Host '[uninstall] removing browser-bridge artifacts'

    # Uninstall tears down the shared binary + manifest that every registration
    # points at, so remove every known browser's key regardless of -Browser,
    # plus any explicit -NmRegistry keys.
    $uninstallKeys = @($BrowserRoots.Keys | ForEach-Object { Get-NativeHostKey $_ })
    if ($NmRegistry) { $uninstallKeys += $NmRegistry }
    foreach ($registryPath in $uninstallKeys) {
        if (Test-Path -LiteralPath $registryPath) {
            Remove-Item -LiteralPath $registryPath -Force
            Write-Host "[uninstall] removed registry key: $registryPath"
        } else {
            Write-Host "[uninstall] not present: $registryPath"
        }
    }

    # Files placed under $InstallDir: the manifest, the binary, and the run.lock
    # the server writes there (LockFile::path() uses LOCALAPPDATA on Windows).
    # Exact paths only — no wildcards, no recursive delete.
    $targets = @(
        (Join-Path $InstallDir "$HostName.json"),
        (Join-Path $InstallDir $BinaryName),
        (Join-Path $InstallDir 'run.lock')
    )
    foreach ($target in $targets) {
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Force
            Write-Host "[uninstall] removed: $target"
        } else {
            Write-Host "[uninstall] not present: $target"
        }
    }

    # Drop $InstallDir only when it is now empty (never recursive).
    if ((Test-Path -LiteralPath $InstallDir) -and
        -not (Get-ChildItem -LiteralPath $InstallDir -Force)) {
        Remove-Item -LiteralPath $InstallDir -Force
        Write-Host "[uninstall] removed empty dir: $InstallDir"
    }

    Write-Host '[uninstall] done. Your browser and the loaded extension were left untouched;'
    Write-Host '[uninstall] remove the unpacked extension yourself via chrome://extensions if desired.'
    return
}

# Resolve install targets before any build or filesystem change, so an invalid
# -Browser fails fast instead of leaving a half-installed binary and manifest.
$targetKeys = if ($NmRegistry) {
    @($NmRegistry)
} else {
    @(Resolve-BrowserSelection $Browser | ForEach-Object { Get-NativeHostKey $_ })
}

function Find-Cargo {
    $command = Get-Command cargo.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $userCargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path -LiteralPath $userCargo) { return $userCargo }
    throw 'cargo.exe not found. Install Rust from https://rustup.rs and run this installer again.'
}

if (Test-Path -LiteralPath (Join-Path $Root 'Cargo.toml')) {
    $cargo = Find-Cargo
    Write-Host "[install] source mode - building with $cargo"
    & $cargo build --release --manifest-path (Join-Path $Root 'Cargo.toml')
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    $binarySource = Join-Path $Root "target\release\$BinaryName"

    $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not $npm) {
        throw 'npm.cmd not found. Install Node.js from https://nodejs.org and run this installer again.'
    }
    Write-Host '[install] building extension bundle (esbuild)...'
    $extensionDir = Join-Path $Root 'extension'
    if (-not (Test-Path -LiteralPath (Join-Path $extensionDir 'node_modules'))) {
        & $npm.Source --prefix $extensionDir install
        if ($LASTEXITCODE -ne 0) { throw "npm install failed with exit code $LASTEXITCODE" }
    }
    & $npm.Source --prefix $extensionDir run build
    if ($LASTEXITCODE -ne 0) { throw "extension build failed with exit code $LASTEXITCODE" }
    $distDir = Join-Path $extensionDir 'dist'
} else {
    Write-Host '[install] prebuilt mode - using shipped binary and extension'
    $binarySource = Join-Path $Root $BinaryName
    $distDir = Join-Path $Root 'extension\dist'
    if (-not (Test-Path -LiteralPath $binarySource)) { throw "prebuilt binary not found at $binarySource" }
    if (-not (Test-Path -LiteralPath $distDir)) { throw "extension bundle not found at $distDir" }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$installedBinary = Join-Path $InstallDir $BinaryName
$temporaryBinary = "$installedBinary.tmp.$PID"
Copy-Item -LiteralPath $binarySource -Destination $temporaryBinary -Force
Move-Item -LiteralPath $temporaryBinary -Destination $installedBinary -Force
Write-Host "[install] binary installed at $installedBinary"

# Chrome appends the calling extension origin on Windows. The executable uses
# that argument to select native-host mode, so no wrapper script is required.
$manifestPath = Join-Path $InstallDir "$HostName.json"
$manifest = [ordered]@{
    name = $HostName
    description = 'Browser Bridge native messaging host'
    path = $installedBinary
    type = 'stdio'
    allowed_origins = @("chrome-extension://$ExtensionId/")
}
$manifestJson = $manifest | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText(
    $manifestPath,
    $manifestJson,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "[install] manifest written to $manifestPath"
foreach ($registryPath in $targetKeys) {
    New-Item -Path $registryPath -Force | Out-Null
    Set-Item -Path $registryPath -Value $manifestPath
    Write-Host "[install] native host registered at $registryPath"
}

# Backslashes must be doubled inside JSON/TOML double-quoted strings.
$escapedBinary = $installedBinary -replace '\\', '\\'

Write-Host ''
Write-Host 'NEXT STEPS'
Write-Host "1. Open chrome://extensions, enable Developer mode, and load unpacked: $distDir"
Write-Host '2. Register the MCP server with your client. Config below already has the'
Write-Host "   absolute path filled in ($installedBinary) - just paste:"
Write-Host ''
Write-Host '   - Claude Code (CLI):'
Write-Host "       claude mcp add browser-bridge -- `"$installedBinary`""
Write-Host ''
Write-Host '   - Claude Desktop / generic MCP client (mcpServers JSON):'
Write-Host "       `"browser-bridge`": { `"command`": `"$escapedBinary`", `"args`": [] }"
Write-Host ''
Write-Host '   - Codex (%USERPROFILE%\.codex\config.toml):'
Write-Host '       [mcp_servers.browser-bridge]'
Write-Host "       command = `"$escapedBinary`""
Write-Host '       args = []'
Write-Host '3. Restart your browser, then ask your MCP client to list browser tabs.'
