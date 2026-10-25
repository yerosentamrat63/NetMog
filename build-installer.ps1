# NetMog packaging script
#
#   powershell -ExecutionPolicy Bypass -File build-installer.ps1
#
# Produces, in dist\:
#   NetMog_v<version>_portable.zip   - extract and run; this is what people download
#   NetMog_Setup_v<version>.exe      - optional installer (needs Inno Setup 6)
#
# The Npcap driver is deliberately NOT bundled: its free licence forbids
# redistributing the installer, so the setup links the user to npcap.com.

[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# ---- version: read once from the csproj, pass it everywhere ------------------
$csproj = Join-Path $PSScriptRoot "NetMog/NetMog.csproj"
$match = Select-String -Path $csproj -Pattern '<Version>([^<]+)</Version>' | Select-Object -First 1
if (-not $match) { throw "No <Version> element found in $csproj" }
$version = $match.Matches[0].Groups[1].Value.Trim()

$parts = $version.Split('.')
while ($parts.Count -lt 4) { $parts += "0" }
$quadVersion = ($parts[0..3] -join '.')

$dist = Join-Path $PSScriptRoot "dist"
$publish = Join-Path $PSScriptRoot "bin/publish"
$stage = Join-Path $dist "NetMog_v$version"
$zip = Join-Path $dist "NetMog_v${version}_portable.zip"

New-Item -ItemType Directory -Path $dist -Force | Out-Null

# ---- 1. publish ------------------------------------------------------------
Write-Host "[1/4] Publishing NetMog $version (win-x64, self-contained)..." -ForegroundColor Cyan
if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }

dotnet publish $csproj -c $Configuration -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=None -p:DebugSymbols=false -o $publish
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed (exit code $LASTEXITCODE)" }

$exe = Join-Path $publish "NetMog.exe"
if (-not (Test-Path $exe)) { throw "Publish did not produce $exe" }
Write-Host "      $( '{0:N1} MB' -f ((Get-Item $exe).Length / 1MB) ) -> bin\publish\NetMog.exe" -ForegroundColor DarkGray

# ---- 2. portable zip -------------------------------------------------------
Write-Host "[2/4] Building the portable zip..." -ForegroundColor Cyan
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

Copy-Item $exe $stage
Copy-Item (Join-Path $PSScriptRoot "LICENSE") (Join-Path $stage "LICENSE.txt")

$readme = @"
NetMog $version - quick start
=============================

1. Extract this folder somewhere permanent (for example C:\Tools\NetMog).
   Do not run it from inside the .zip.

2. Install the packet driver, once per PC:
   https://npcap.com/#download
   During setup tick "Install Npcap in WinPcap API-compatible Mode".
   NetMog cannot cut or meter anything without it.

3. Run NetMog.exe and accept the administrator prompt. It needs admin to send
   raw network packets. Your browser opens on http://127.0.0.1:8899
   (8899-8918 if that port is taken).

   The first launch may show "Windows protected your PC" because the
   executable is not code-signed: More info -> Run anyway.

4. Right-click a device card to cut, monitor, or name it. Closing the browser
   tab does not stop NetMog - use the power button in the top-right of the UI,
   which restores every device it cut.

Use NetMog only on a network you own or are responsible for administering.
Poisoning ARP on somebody else's network is illegal in most countries.

Saved data (names, limits, netLock list, history) lives in
%LOCALAPPDATA%\NetMog and is safe to delete when NetMog is not running.
"@
Set-Content -Path (Join-Path $stage "QUICKSTART.txt") -Value $readme -Encoding UTF8

if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
Remove-Item $stage -Recurse -Force
Write-Host "      -> dist\$(Split-Path $zip -Leaf)" -ForegroundColor DarkGray

# ---- 3. installer (optional) ----------------------------------------------
Write-Host "[3/4] Building the setup wizard..." -ForegroundColor Cyan
$iscc = @(
    (Join-Path $env:ProgramFiles "Inno Setup 6/ISCC.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6/ISCC.exe")
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if ($SkipInstaller) {
    Write-Host "      skipped (-SkipInstaller)" -ForegroundColor DarkGray
}
elseif (-not $iscc) {
    Write-Host "      Inno Setup 6 not found - skipped. Install it from" -ForegroundColor Yellow
    Write-Host "      https://jrsoftware.org/isdl.php and re-run to get NetMog_Setup_v$version.exe" -ForegroundColor Yellow
}
else {
    & $iscc "/DMyAppVersion=$version" "/DMyAppVersionQuad=$quadVersion" "installer\setup.iss"
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit code $LASTEXITCODE)" }
    Write-Host "      -> dist\NetMog_Setup_v$version.exe" -ForegroundColor DarkGray
}

# ---- 4. summary ------------------------------------------------------------
Write-Host "`n[4/4] Done. Release artifacts in dist\:" -ForegroundColor Green
Get-ChildItem $dist -File |
    Sort-Object Name |
    ForEach-Object { Write-Host ("      {0}  ({1:N1} MB)" -f $_.Name, ($_.Length / 1MB)) }

Write-Host "`nUpload those files to a GitHub Release, and point the README's" -ForegroundColor White
Write-Host "download link at it. Npcap stays a separate install by design." -ForegroundColor White
