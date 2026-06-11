# PowerShell uninstaller for the `burn` CLI — the exact inverse of
# install.ps1:
#
#   irm https://afterburner.sh/uninstall | iex
#
# Undoes everything install.ps1 did, and nothing else:
#   1. Removes burn.exe from the install dir, and the dir itself if
#      that leaves it empty.
#   2. Removes the install dir from the User-scope PATH environment
#      variable (the same scope install.ps1 prepended to), and from
#      the current session's $env:Path.
#
# State created by *running* burn (registry logins, caches) is not
# install.ps1's doing and is deliberately untouched.
#
# Honors:
#   $env:BURN_INSTALL   install dir. Defaults to
#                       $env:USERPROFILE\.local\bin — must match what
#                       was used at install time.

$ErrorActionPreference = 'Stop'

$installDir = if ($env:BURN_INSTALL) { $env:BURN_INSTALL } else { Join-Path $env:USERPROFILE '.local\bin' }

# ----- 1. binary ---------------------------------------------------------

$binDst = Join-Path $installDir 'burn.exe'
if (Test-Path $binDst) {
    Remove-Item -Force $binDst
    Write-Host "burn uninstall: removed $binDst"
} else {
    Write-Host "burn uninstall: no binary at $installDir (already removed?)"
}

# install.ps1 created the dir; remove it again if (and only if) it
# is now empty.
if ((Test-Path $installDir) -and -not (Get-ChildItem -Force $installDir)) {
    Remove-Item -Force $installDir
    Write-Host "burn uninstall: removed empty $installDir"
}

# ----- 2. User PATH ------------------------------------------------------
#
# Strip the install dir from the User-scope PATH — the exact entry
# install.ps1 prepended. Other entries are preserved byte-for-byte.

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($null -ne $userPath -and $userPath -ne '') {
    $needle = $installDir.TrimEnd('\')
    $kept = $userPath.Split(';') | Where-Object { $_ -ne '' -and $_.TrimEnd('\') -ne $needle }
    $newPath = $kept -join ';'
    if ($newPath -ne $userPath) {
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host "burn uninstall: removed `"$installDir`" from your User PATH"
    }
}

# Current session too, so `burn` stops resolving immediately.
$sessionKept = $env:Path.Split(';') | Where-Object { $_ -ne '' -and $_.TrimEnd('\') -ne $installDir.TrimEnd('\') }
$env:Path = $sessionKept -join ';'

# ----- summary -----------------------------------------------------------

Write-Host ""
Write-Host "burn was uninstalled."
Write-Host "Open a new terminal for PATH changes to fully propagate."
