$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$releaseDir = Join-Path $root "src-tauri\target\release"
$liteDir = Join-Path $root "dist-lite\hashcatGUI"
$resourcesDir = Join-Path $liteDir "resources"
$wordlistSource = Join-Path $root "src-tauri\resources\wordlists"
$wordlistDest = Join-Path $resourcesDir "wordlists"
$readmeSource = Join-Path $PSScriptRoot "README-lite.md"

if (Test-Path $liteDir) {
  Remove-Item -LiteralPath $liteDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $resourcesDir | Out-Null
Copy-Item -Path (Join-Path $releaseDir "hashcat-gui.exe") -Destination (Join-Path $liteDir "hashcatGUI.exe") -Force
Copy-Item -Path $readmeSource -Destination (Join-Path $liteDir "README.md") -Force
Copy-Item -Path $wordlistSource -Destination $wordlistDest -Recurse -Force

@"
HashcatGUI Lite

This package does not include hashcat.
This package includes rockyou.txt at:
resources\wordlists\rockyou.txt

Open Settings -> Hashcat Update inside the app to download hashcat into:
resources\hashcat-current

You can also choose a custom hashcat install folder in Settings.
"@ | Set-Content -LiteralPath (Join-Path $liteDir "README-LITE.txt") -Encoding UTF8

Write-Host "Lite build written to $liteDir"
