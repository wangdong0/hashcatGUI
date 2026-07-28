$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$releaseDir = Join-Path $root "src-tauri\target\release"
#$releaseDir = Join-Path $root "src-tauri\target\i686-pc-windows-msvc\release"
$portableDir = Join-Path $root "dist-portable\hashcatGUI"
$resourceSource = Join-Path $root "src-tauri\resources\hashcat"
$resourceDest = Join-Path $portableDir "resources\hashcat"
$wordlistSource = Join-Path $root "src-tauri\resources\wordlists"
$wordlistDest = Join-Path $portableDir "resources\wordlists"

New-Item -ItemType Directory -Force -Path $portableDir | Out-Null
Copy-Item -Path (Join-Path $releaseDir "hashcat-gui.exe") -Destination (Join-Path $portableDir "hashcatGUI.exe") -Force

#if (Test-Path $resourceDest) {
#  Remove-Item -LiteralPath $resourceDest -Recurse -Force
#}

#if (Test-Path $wordlistDest) {
#  Remove-Item -LiteralPath $wordlistDest -Recurse -Force
#}

#New-Item -ItemType Directory -Force -Path (Split-Path -Parent $resourceDest) | Out-Null
#Copy-Item -Path $resourceSource -Destination $resourceDest -Recurse -Force

#if (Test-Path $wordlistSource) {
#  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $wordlistDest) | Out-Null
#  Copy-Item -Path $wordlistSource -Destination $wordlistDest -Recurse -Force
#}

Write-Host "Portable build written to $portableDir"
