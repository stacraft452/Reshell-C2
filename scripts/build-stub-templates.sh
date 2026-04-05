#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STUBS="$ROOT/data/stubs"
STUBBIN="$ROOT/internal/payload/stubbin"
mkdir -p "$STUBS" "$STUBBIN"

echo "Building $STUBS/linux_amd64.elf (C++ client_linux) ..."
g++ -std=c++11 -O2 -pthread -o "$STUBS/linux_amd64.elf" \
  -I"$ROOT/client/native" "$ROOT/client/native/client_linux.cpp" -lcrypto -lutil
cp -f "$STUBS/linux_amd64.elf" "$STUBBIN/linux_amd64.elf"

# 可选：另生成 Go linuxagent 版（与 Windows 上 ps1 行为一致），例如:
# ( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$STUBS/linux_amd64_go.elf" ./cmd/linuxagent )

if command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
  echo "Building $STUBS/windows_x64.exe ..."
  x86_64-w64-mingw32-g++ -O2 -s -static -o "$STUBS/windows_x64.exe" \
    -I"$ROOT/client/native" "$ROOT/client/native/client.cpp" \
    -lws2_32 -lgdi32 -lgdiplus -lbcrypt -liphlpapi -lpsapi -lshell32 -lole32 -luuid -lshlwapi
  cp -f "$STUBS/windows_x64.exe" "$STUBBIN/windows_x64.exe"
  echo "Building $STUBS/windows_x86.exe (x86_64-w64-mingw32-g++ -m32) ..."
  if x86_64-w64-mingw32-g++ -m32 -O2 -s -static -o "$STUBS/windows_x86.exe" \
    -I"$ROOT/client/native" "$ROOT/client/native/client.cpp" \
    -lws2_32 -lgdi32 -lgdiplus -lbcrypt -liphlpapi -lpsapi -lshell32 -lole32 -luuid -lshlwapi; then
    cp -f "$STUBS/windows_x86.exe" "$STUBBIN/windows_x86.exe"
  elif command -v i686-w64-mingw32-g++ >/dev/null 2>&1; then
    echo "Building $STUBS/windows_x86.exe (i686-w64-mingw32-g++ fallback) ..."
    i686-w64-mingw32-g++ -O2 -s -static -o "$STUBS/windows_x86.exe" \
      -I"$ROOT/client/native" "$ROOT/client/native/client.cpp" \
      -lws2_32 -lgdi32 -lgdiplus -lbcrypt -liphlpapi -lpsapi -lshell32 -lole32 -luuid -lshlwapi
    cp -f "$STUBS/windows_x86.exe" "$STUBBIN/windows_x86.exe"
  else
    echo "warning: windows_x86.exe not built (-m32 failed, no i686-w64-mingw32-g++)" >&2
  fi
elif command -v i686-w64-mingw32-g++ >/dev/null 2>&1; then
  echo "Building $STUBS/windows_x86.exe ..."
  i686-w64-mingw32-g++ -O2 -s -static -o "$STUBS/windows_x86.exe" \
    -I"$ROOT/client/native" "$ROOT/client/native/client.cpp" \
    -lws2_32 -lgdi32 -lgdiplus -lbcrypt -liphlpapi -lpsapi -lshell32 -lole32 -luuid -lshlwapi
  cp -f "$STUBS/windows_x86.exe" "$STUBBIN/windows_x86.exe"
fi

echo "Done. 打入 Go 二进制: cd $ROOT && go build -tags=stubembed ./..."
