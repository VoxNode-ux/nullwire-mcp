<#
.SYNOPSIS
    Installs NullWire-MCP on Windows. No Node.js needed.

.DESCRIPTION
    Downloads nullwire-windows-amd64.exe from the project's GitHub release, checks it
    against the release's SHA256SUMS.txt (and installs nothing if the check fails),
    puts it in a per-user folder and adds that folder to your user PATH.

.PARAMETER Version
    Release tag to install. Default: latest.

.PARAMETER InstallDir
    Where to put nullwire-mcp.exe. Default: %LOCALAPPDATA%\Programs\nullwire-mcp.

.PARAMETER Setup
    Also register NullWire with the MCP clients found on this machine.

.PARAMETER Uninstall
    Remove NullWire, its MCP client entries and its PATH entry.

.PARAMETER NoPath
    Do not change your PATH.

.EXAMPLE
    irm https://raw.githubusercontent.com/VoxNode-ux/nullwire-mcp/main/scripts/install.ps1 | iex

.EXAMPLE
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/VoxNode-ux/nullwire-mcp/main/scripts/install.ps1))) -Setup

.NOTES
    Environment: NULLWIRE_VERSION, NULLWIRE_INSTALL_DIR, NULLWIRE_BASE_URL (mirrors and tests).
    Windows on ARM runs the x64 build.
#>
[CmdletBinding()]
param(
    [string]$Version = $(if ($env:NULLWIRE_VERSION) { $env:NULLWIRE_VERSION } else { 'latest' }),
    [string]$InstallDir = $(if ($env:NULLWIRE_INSTALL_DIR) { $env:NULLWIRE_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\nullwire-mcp' }),
    [switch]$Setup,
    [switch]$Uninstall,
    [switch]$NoPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = 'VoxNode-ux/nullwire-mcp'
$asset = 'nullwire-windows-amd64.exe'
$baseUrl = if ($env:NULLWIRE_BASE_URL) { $env:NULLWIRE_BASE_URL.TrimEnd('/') } else { "https://github.com/$repo/releases/download/$Version" }
$exe = Join-Path $InstallDir 'nullwire-mcp.exe'

function Remove-FromUserPath([string]$dir) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { return }
    $kept = @($userPath -split ';' | Where-Object { $_ -and ($_ -ne $dir) })
    [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User')
}

if ($Uninstall) {
    if (Test-Path $exe) {
        try { & $exe install --uninstall --client all } catch { Write-Warning "Could not clean MCP client configs: $_" }
        Remove-Item -Force $exe
        Write-Host "Removed $exe"
    } else {
        Write-Host "Nothing to remove: $exe does not exist."
    }
    if ((Test-Path $InstallDir) -and -not (Get-ChildItem -Force $InstallDir)) { Remove-Item -Force $InstallDir }
    if (-not $NoPath) { Remove-FromUserPath $InstallDir }
    return
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("nullwire-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Write-Host "Installing NullWire-MCP ($asset, release: $Version)"
    $download = Join-Path $work $asset
    $sumsFile = Join-Path $work 'SHA256SUMS.txt'
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$asset" -OutFile $download
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/SHA256SUMS.txt" -OutFile $sumsFile

    $expected = $null
    foreach ($line in Get-Content $sumsFile) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $asset) {
            $expected = $Matches[1].ToLower()
            break
        }
    }
    if (-not $expected) { throw "SHA256SUMS.txt has no entry for $asset" }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $download).Hash.ToLower()
    if ($actual -ne $expected) {
        throw "checksum mismatch for $asset (expected $expected, got $actual); nothing was installed"
    }
    Write-Host 'Checksum OK.'

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    try {
        Copy-Item -Force -Path $download -Destination $exe
    } catch {
        throw "could not write $exe. Is NullWire running? Close it (or your MCP client) and try again. $_"
    }
    Write-Host "Installed $exe"
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @()
    if ($userPath) { $parts = @($userPath -split ';' | Where-Object { $_ }) }
    if ($parts -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $InstallDir) -join ';'), 'User')
        Write-Host "Added $InstallDir to your user PATH. Open a new terminal to use 'nullwire-mcp'."
    }
}

if ($Setup) {
    Write-Host 'Registering with MCP clients...'
    & $exe install --client all
} else {
    Write-Host 'Next: register it with your MCP clients:'
    Write-Host "  `"$exe`" install --client all"
}
