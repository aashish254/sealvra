# Keyholder v0.2 installer (Windows) -- W20.
#
# Installs the zipapp distribution plus a launcher, and creates the
# vault directory with restrictive permissions. Program and data are
# separate on purpose:
#   program:  $InstallRoot\keyholder.pyz
#             $InstallRoot\bin\keyholder.cmd   (launcher)
#   data:     $VaultDir (default $env:LOCALAPPDATA\Keyholder\vault)
# Reinstalling NEVER touches existing vault data: if the vault
# directory already exists its contents are left exactly as they are,
# and this script says so out loud. Data carries over across reinstalls.
#
# Requirements: Python 3.12 on the target machine, plus the two pinned
# dependencies from requirements.txt (cryptography, argon2-cffi).
# Those dependencies are NOT bundled in the zipapp; if they are
# missing this script warns (it does not silently substitute anything)
# and still installs, so the user can install them and then run.
#
# No key, token, or credential is read, written, or printed here.
# No network access, nothing leaves this machine.
# Tier note (CONTRACT.md section 10): on Windows, vault storage is
# USER-SCOPED (DPAPI); directory ACLs below do NOT survive a
# shell-capable same-user attacker (Tier B) and must not be cited as
# Tier B evidence.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 `
#     [-PyzPath .\dist\keyholder.pyz] [-InstallRoot DIR] [-VaultDir DIR]
# Defaults: PyzPath = <repo-root>\dist\keyholder.pyz,
# InstallRoot = $env:LOCALAPPDATA\Keyholder,
# VaultDir = $env:LOCALAPPDATA\Keyholder\vault (or $env:KEYHOLDER_HOME
# when that variable is set).

[CmdletBinding()]
param(
    [string]$PyzPath = "",
    [string]$InstallRoot = "",
    [string]$VaultDir = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrEmpty($InstallRoot)) {
    $InstallRoot = Join-Path $env:LOCALAPPDATA "Keyholder"
}
if ([string]::IsNullOrEmpty($VaultDir)) {
    if (-not [string]::IsNullOrEmpty($env:KEYHOLDER_HOME)) {
        $VaultDir = $env:KEYHOLDER_HOME
    } else {
        $VaultDir = Join-Path $InstallRoot "vault"
    }
}
if ([string]::IsNullOrEmpty($PyzPath)) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
    $PyzPath = Join-Path $RepoRoot "dist\keyholder.pyz"
    if (-not (Test-Path $PyzPath)) {
        $Candidate = Join-Path (Get-Location) "dist\keyholder.pyz"
        if (Test-Path $Candidate) { $PyzPath = $Candidate }
    }
}
if (-not (Test-Path $PyzPath)) {
    Write-Error "install.ps1: keyholder.pyz not found: $PyzPath (pass -PyzPath explicitly)."
    exit 1
}

# Python 3.12 or newer is required by the v0.2 distribution.
# Capture both streams: some Python builds report --version on stderr,
# and a missing python must give a friendly error, not a bare
# CommandNotFoundException under ErrorActionPreference Stop.
try {
    $PyVersion = ((& python --version 2>&1) | Out-String).Trim()
} catch {
    Write-Error "install.ps1: 'python' was not found on PATH. Install Python 3.12 or newer, then re-run this script."
    exit 1
}
if ([string]::IsNullOrEmpty($PyVersion)) {
    Write-Error "install.ps1: could not determine the Python version ('python --version' printed nothing). Install Python 3.12 or newer, then re-run this script."
    exit 1
}
if ($PyVersion -notmatch "Python 3\.(1[2-9]|[2-9][0-9])") {
    if ($PyVersion -notmatch "Python [4-9]\.") {
        Write-Error "install.ps1: Python 3.12 or newer is required (found: $PyVersion)."
        exit 1
    }
}

$BinDir = Join-Path $InstallRoot "bin"
New-Item -ItemType Directory -Force -Path $InstallRoot, $BinDir | Out-Null
Copy-Item -Path $PyzPath -Destination (Join-Path $InstallRoot "keyholder.pyz") -Force

# Launcher: resolves the zipapp relative to its own location, so the
# install root is not baked in and a move/reinstall stays consistent.
$Launcher = Join-Path $BinDir "keyholder.cmd"
$LauncherText = "@echo off`r`npython `"%~dp0..\keyholder.pyz`" %*`r`n"
[System.IO.File]::WriteAllText($Launcher, $LauncherText)

# Vault directory: create if missing; NEVER touch contents on
# reinstall. Existing data carries over untouched.
if (Test-Path $VaultDir) {
    Write-Output "vault directory already exists; existing data preserved untouched: $VaultDir"
} else {
    New-Item -ItemType Directory -Force -Path $VaultDir | Out-Null
    Write-Output "created vault directory: $VaultDir"
}

# Restrict the vault directory ACL to the current user (best effort:
# a failure here warns loudly instead of failing silently, and the
# install still completes so the user can fix permissions by hand).
try {
    $Acl = Get-Acl -Path $VaultDir
    $Acl.SetAccessRuleProtection($true, $false)
    $User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $User, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $Acl.SetAccessRule($Rule)
    Set-Acl -Path $VaultDir -AclObject $Acl
} catch {
    Write-Warning "install.ps1: could not restrict vault ACL on $VaultDir ($($_.Exception.Message)). Fix permissions by hand."
}

# Dependency note (warning only, never a silent substitute).
$DepsOk = $false
try {
    & python -c "import cryptography, argon2" 2>$null
    if ($LASTEXITCODE -eq 0) { $DepsOk = $true }
} catch {
    $DepsOk = $false
}
if (-not $DepsOk) {
    Write-Warning "Python packages 'cryptography' and/or 'argon2-cffi' are not installed. Install them from requirements.txt before running keyholder."
}

Write-Output "installed keyholder program to: $(Join-Path $InstallRoot 'keyholder.pyz')"
Write-Output "installed launcher to:          $Launcher"
Write-Output "vault directory (data, preserved on reinstall): $VaultDir"
Write-Output "add $BinDir to your PATH, then run: keyholder --help"
