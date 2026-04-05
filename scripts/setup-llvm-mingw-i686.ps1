# 下载 llvm-mingw i686 工具链到仓库 .tools/（用于在本机无 MSYS2 mingw32 时编 windows_x86.exe）
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$tools = Join-Path $root ".tools"
New-Item -ItemType Directory -Force -Path $tools | Out-Null

$zipUrl = "https://github.com/mstorsjo/llvm-mingw/releases/download/20260324/llvm-mingw-20260324-ucrt-i686.zip"
$zipPath = Join-Path $tools "llvm-mingw-ucrt-i686.zip"
$extractDir = Join-Path $tools "llvm-mingw-i686"

if (Test-Path (Join-Path $extractDir "bin\i686-w64-mingw32-g++.exe")) {
    Write-Host "Already present: $extractDir\bin\i686-w64-mingw32-g++.exe"
    exit 0
}

Write-Host "Downloading $zipUrl ..."
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
Remove-Item -Force $zipPath

$gpp = Get-ChildItem -Path $extractDir -Recurse -Filter "i686-w64-mingw32-g++.exe" | Select-Object -First 1
if (-not $gpp) { throw "i686-w64-mingw32-g++.exe not found after extract" }
Write-Host "OK: $($gpp.FullName)"
