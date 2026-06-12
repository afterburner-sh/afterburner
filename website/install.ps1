# PowerShell installer for the `burn` CLI.
#
#   iwr -useb https://afterburner.sh | iex
#
# (Served by the afterburner.sh Cloudflare Worker, which dispatches
# by user agent — PowerShell gets this; curl/wget get install.sh.)
#
# Honors:
#   $env:BURN_VERSION   pinned tag (e.g. v0.1.3). Defaults to "latest".
#   $env:BURN_INSTALL   install dir. Defaults to $env:USERPROFILE\.local\bin.

$ErrorActionPreference = 'Stop'

$repo = 'afterburner-sh/afterburner'
$installDir = if ($env:BURN_INSTALL) { $env:BURN_INSTALL } else { Join-Path $env:USERPROFILE '.local\bin' }
$version = if ($env:BURN_VERSION) { $env:BURN_VERSION } else { 'latest' }

# ----- arch detection ---------------------------------------------------
# Use PROCESSOR_ARCHITECTURE for 64-bit Windows. ARM64 boxes report
# "ARM64"; everything else (Surface, dev workstations, CI runners) is
# AMD64.
$archEnv = $env:PROCESSOR_ARCHITECTURE
if (-not $archEnv -and $env:PROCESSOR_ARCHITEW6432) {
    $archEnv = $env:PROCESSOR_ARCHITEW6432
}
$arch = switch -Regex ($archEnv) {
    'AMD64|x86_64'  { 'x86_64' }
    'ARM64|aarch64' { 'aarch64' }
    default { throw "burn install: unsupported architecture '$archEnv'" }
}

# `aarch64-pc-windows-msvc` is not in the release matrix — the
# rustls Ring crypto backend lacks aarch64-windows assembly.
# Windows 11 on ARM64 ships with transparent x64 emulation, so the
# x86_64 binary runs unmodified. Fall back to x86_64 with a note.
$fallbackNote = $null
if ($arch -eq 'aarch64') {
    $arch = 'x86_64'
    $fallbackNote = 'ARM Windows: installing the x86_64 build (runs under Windows 11 x64 emulation).'
}
$target = "$arch-pc-windows-msvc"

# ----- resolve tag -------------------------------------------------------
if ($version -eq 'latest') {
    $api = "https://api.github.com/repos/$repo/releases/latest"
    $tag = (Invoke-RestMethod -UseBasicParsing -Headers @{ 'User-Agent' = 'burn-installer' } -Uri $api).tag_name
    if (-not $tag) { throw 'burn install: could not resolve latest release tag' }
} else {
    $tag = $version
}
$ver = $tag.TrimStart('v')
$stem = "burn-$ver-$target"
$asset = "$stem.zip"
$url = "https://github.com/$repo/releases/download/$tag/$asset"

Write-Host "burn install: $tag -> $target"
if ($fallbackNote) { Write-Host "  note: $fallbackNote" }
Write-Host "  fetching $url"

# ----- download + verify -------------------------------------------------
$tmp = Join-Path $env:TEMP "burn-install-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    $zipPath = Join-Path $tmp $asset

    # Show a progress bar during the multi-MB archive download. By
    # default `Invoke-WebRequest -UseBasicParsing` shows percent-
    # complete in the host; older PowerShell versions can stall the
    # transfer if `$ProgressPreference` is left at default ('Continue')
    # because of console-redraw cost — that's why some installers
    # *disable* it. Trade-off: the bar slows IWR ~5× on PS 5.1 but
    # gives the user visual feedback the download is alive.
    # PS 7+ doesn't have this slowdown.
    $oldProgress = $ProgressPreference
    try {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            # PS 5.1: keep progress visible (worth the slowdown for UX).
            $ProgressPreference = 'Continue'
        }
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zipPath
    } finally {
        $ProgressPreference = $oldProgress
    }

    $shaPath = "$zipPath.sha256"
    try {
        # Silent for the tiny .sha256 file — the bar would just flash.
        $oldProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$url.sha256" -OutFile $shaPath
        } finally {
            $ProgressPreference = $oldProgress
        }
        $expected = (Get-Content $shaPath | Select-Object -First 1).Split()[0].ToLower()
        $actual = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()
        if ($expected -ne $actual) {
            throw "burn install: SHA-256 mismatch (expected $expected, got $actual)"
        }
        Write-Host '  sha256 ok'
    } catch [System.Net.WebException] {
        Write-Host '  (no checksum available, skipping)'
    }

    # ----- extract --------------------------------------------------------
    # The Windows zip is flat (burn.exe at root + README + LICENSE + docs/).
    # release.yml builds it via `Compress-Archive -Path "$stem/*"`.
    Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    $binSrc = Join-Path $tmp 'burn.exe'
    if (-not (Test-Path $binSrc)) {
        throw "burn install: expected $binSrc inside $asset"
    }

    # ----- install --------------------------------------------------------
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    $binDst = Join-Path $installDir 'burn.exe'
    Copy-Item -Force $binSrc $binDst

    # ----- PATH update ----------------------------------------------------
    #
    # If $installDir isn't on the user's persistent PATH (the
    # `User`-scope environment variable, NOT just the current
    # session's $env:Path), prepend it. Mirrors what bun, rustup,
    # scoop, and uv do on Windows.
    #
    # We update User scope (not Machine) so the install never needs
    # admin elevation. New shells will pick it up; the current
    # session also gets $env:Path updated for immediate use.
    #
    # Set $env:BURN_INSTALL_NO_PATH=1 to skip — for users who manage
    # PATH via dotfiles or a shell profile of their own.
    $pathUpdated = $false
    if (-not $env:BURN_INSTALL_NO_PATH) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if ($null -eq $userPath) { $userPath = '' }
        $userDirs = $userPath.Split(';') | Where-Object { $_ -ne '' } | ForEach-Object { $_.TrimEnd('\') }
        $needle = $installDir.TrimEnd('\')
        if ($userDirs -notcontains $needle) {
            $newPath = if ($userPath) { "$installDir;$userPath" } else { $installDir }
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            $env:Path = "$installDir;$env:Path"
            $pathUpdated = $true
        }
    }

    # ----- summary --------------------------------------------------------
    #
    # Mirrors bun's tone: success line, blank, what we did to PATH,
    # blank, "to get started, run". The "restart your shell" note
    # is the Windows analogue of `source ~/.bashrc` — env vars set
    # via SetEnvironmentVariable propagate via WM_SETTINGCHANGE,
    # which existing terminal sessions don't always re-read.

    Write-Host ""
    Write-Host "burn was installed successfully to $binDst"
    if ($pathUpdated) {
        Write-Host ""
        Write-Host "Added `"$installDir`" to your User PATH"
        Write-Host ""
        Write-Host "To get started, open a new terminal and run:"
        Write-Host ""
        Write-Host "  burn --version"
    } else {
        $sessionDirs = $env:Path.Split(';') | Where-Object { $_ -ne '' } | ForEach-Object { $_.TrimEnd('\') }
        if ($sessionDirs -contains $installDir.TrimEnd('\')) {
            Write-Host ""
            Write-Host "To get started, run:"
            Write-Host ""
            Write-Host "  burn --version"
        } else {
            Write-Host ""
            Write-Host "Note: $installDir is not on `$env:Path. Either add it via"
            Write-Host "      System Properties > Environment Variables, or run"
            Write-Host "      $binDst --version directly."
        }
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
