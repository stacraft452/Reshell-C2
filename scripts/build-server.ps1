# 在项目根目录生成 C2 服务端二进制（纯 Go SQLite，无需 CGO）
# 用法（在仓库根目录执行）:
#   .\scripts\build-server.ps1 -Target linux    # 交叉编译 Linux amd64 -> c2-server-linux
#   .\scripts\build-server.ps1 -Target windows # 本机 Windows -> c2-server.exe
#   .\scripts\build-server.ps1 -Target all      # 两个都编

param(
    [Parameter(Position = 0)]
    [ValidateSet('linux', 'windows', 'all')]
    [string] $Target = 'linux'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$ldflags = '-s -w'
$trim = '-trimpath'
$pkg = './cmd/server'

function Build-Linux {
    Write-Host '==> GOOS=linux GOARCH=amd64 CGO_ENABLED=0' -ForegroundColor Cyan
    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $out = Join-Path $root 'c2-server-linux'
    go build $trim -ldflags $ldflags -o $out $pkg
    Write-Host "OK: $out" -ForegroundColor Green
}

function Build-Windows {
    Write-Host '==> Windows amd64 (本机)' -ForegroundColor Cyan
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    $out = Join-Path $root 'c2-server.exe'
    go build $trim -ldflags $ldflags -o $out $pkg
    Write-Host "OK: $out" -ForegroundColor Green
}

switch ($Target) {
    'linux'  { Build-Linux }
    'windows' { Build-Windows }
    'all' {
        Build-Linux
        Build-Windows
    }
}
