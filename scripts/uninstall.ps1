# Keyholder v0.2 uninstaller (Windows) -- W20.
#
# DEFAULT BEHAVIOUR: remove the PROGRAM only (zipapp + launcher).
# Vault data, platform-keychain items, and audit data are PRESERVED
# by default and are never deleted silently. Reinstalling afterwards
# picks the preserved data back up.
#
# -WipeData is a separate, explicitly confirmed option:
#   * it is refused unless -ConfirmWipe is ALSO passed, and
#   * it then asks the user to type WIPE before anything is deleted.
# Before any deletion, a pre-wipe audit record is written twice: once
# appended to the vault audit log (if one exists) and once to a
# wipe-receipt file OUTSIDE the vault directory, so evidence of the
# wipe survives the wipe itself.
#
# Wipe ordering (v3 section 1S, N-S6): live sessions are killed first
# where a launcher is still available; only then is data removed.
#
# WARNING, stated in the script and at wipe time: wiping the local
# vault does NOT revoke provider-side keys. A wiped key can still be
# used by anyone who already holds it. Revoking/rotating keys at the
# provider (GitHub / Gemini) is a separate user step and is NOT done
# by this script.
#
# Keychain honesty: platform-keychain items (DPAPI-protected storage)
# are owned by the vault module (W02 naming); this script does not
# guess their names and does not claim to delete them. On wipe it
# prints that keychain cleanup, if any items exist, is a manual step.
# Do not read this script as claiming a keychain wipe.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\uninstall.ps1 `
#     [-InstallRoot DIR] [-VaultDir DIR]
#   powershell -ExecutionPolicy Bypass -File scripts\uninstall.ps1 `
#     -WipeData -ConfirmWipe [-InstallRoot DIR] [-VaultDir DIR]
# Defaults: InstallRoot = $env:LOCALAPPDATA\Keyholder,
# VaultDir = $env:LOCALAPPDATA\Keyholder\vault (or $env:KEYHOLDER_HOME
# when that variable is set).

[CmdletBinding()]
param(
    [string]$InstallRoot = "",
    [string]$VaultDir = "",
    [switch]$WipeData,
    [switch]$ConfirmWipe
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

if ($WipeData -and -not $ConfirmWipe) {
    Write-Error "uninstall.ps1: -WipeData was given without -ConfirmWipe. Refusing to delete any data. Nothing was removed."
    exit 1
}

$Launcher = Join-Path $InstallRoot "bin\keyholder.cmd"
$Program = Join-Path $InstallRoot "keyholder.pyz"

# Kill live sessions first (best effort; a missing launcher or a
# stopped daemon is not an error here -- the program is being removed).
if (Test-Path $Launcher) {
    try { & $Launcher sessions kill-all 2>$null | Out-Null } catch { }
}

# Remove the program (always; this is the default action too).
if (Test-Path $Launcher) { Remove-Item -Force $Launcher }
if (Test-Path $Program) { Remove-Item -Force $Program }
$BinDir = Join-Path $InstallRoot "bin"
if ((Test-Path $BinDir) -and ((Get-ChildItem $BinDir -Force | Measure-Object).Count -eq 0)) {
    Remove-Item -Force $BinDir
}
Write-Output "removed keyholder program and launcher."

if (-not $WipeData) {
    Write-Output "preserved (NOT deleted): vault data, platform-keychain items, and audit data."
    Write-Output "vault directory left untouched: $VaultDir"
    Write-Output "to delete data as well, re-run with: -WipeData -ConfirmWipe"
    exit 0
}

# --- Wipe path: separately confirmed, pre-wipe audit record first. ---
Write-Output "This will DELETE the local vault and audit data at $VaultDir."
Write-Output "WARNING: wiping the local vault does NOT revoke provider-side keys."
Write-Output "Revoking/rotating keys at GitHub / Gemini is a separate user step."
$Typed = Read-Host "Type WIPE to confirm, anything else to abort"
if ($Typed -ne "WIPE") {
    Write-Error "uninstall.ps1: confirmation did not match WIPE; aborting. Nothing was deleted."
    exit 1
}

# Timestamp format is colon-free on purpose: ':' is illegal in
# Windows filenames, and the old "HH:mm:ss" format made Set-Content
# fail (aborting the wipe under ErrorActionPreference Stop before
# any deletion, with no receipt written).
$Ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHHmmssZ")
$Record = "{`"event_type`": `"vault_wipe`", `"ts`": `"$Ts`", `"vault_dir_removed`": true, `"note`": `"local wipe only; provider-side keys NOT revoked`"}"
$HomeDir = $env:USERPROFILE
if ([string]::IsNullOrEmpty($HomeDir)) { $HomeDir = $env:HOMEDRIVE + $env:HOMEPATH }
$Receipt = Join-Path $HomeDir "keyholder-wipe-receipt-$Ts.json"
# Pre-wipe record: append to the vault audit log first (if a vault
# exists), then to a receipt OUTSIDE the vault so it survives deletion.
if (Test-Path $VaultDir) {
    Add-Content -Path (Join-Path $VaultDir "audit.log") -Value $Record -ErrorAction SilentlyContinue
}
Set-Content -Path $Receipt -Value $Record
Write-Output "pre-wipe audit record written to: $Receipt"

Remove-Item -Recurse -Force $VaultDir -ErrorAction SilentlyContinue
# Do not claim deletion that did not happen: verify before reporting.
if (Test-Path $VaultDir) {
    Write-Warning "uninstall.ps1: vault directory still present after wipe attempt: $VaultDir. Remove it by hand and check for locked files or open handles."
} else {
    Write-Output "deleted vault directory: $VaultDir"
}
Write-Output "wipe receipt kept at: $Receipt"
Write-Output "manual step (not done by this script): remove any platform-keychain"
Write-Output "items for Keyholder, and rotate/revoke the keys at GitHub / Gemini,"
Write-Output "because wiping local data does NOT revoke provider-side keys."
