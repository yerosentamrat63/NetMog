# NetMog Packaging & Build Script
# Publishes NetMog as a single self-contained executable and reminds you what the
# installer needs. The Npcap driver is deliberately NOT bundled: its free licence
# forbids redistributing the installer, so setup links the user to npcap.com.

Set-Location -Path $PSScriptRoot

Write-Host "[1/2] Publishing NetMog (win-x64 self-contained single-file)..." -ForegroundColor Cyan
dotnet publish NetMog/NetMog.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o bin/publish

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to publish NetMog binary." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Published binary created: bin/publish/NetMog.exe" -ForegroundColor Green

Write-Host "`n[2/2] Build completed!" -ForegroundColor Cyan
Write-Host "Users need Npcap (WinPcap API-compatible mode) or WinPcap 4.1.3 installed;" -ForegroundColor White
Write-Host "the setup wizard checks for it and links to https://npcap.com" -ForegroundColor White
Write-Host "To compile the setup wizard into NetMog_Setup_v1.0.0.exe:" -ForegroundColor White
Write-Host "  1. Install Inno Setup (https://jrsoftware.org/isdl.php)" -ForegroundColor White
Write-Host "  2. Run: ISCC.exe installer\setup.iss" -ForegroundColor White
