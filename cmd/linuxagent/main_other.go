//go:build !linux

package main

import "os"

func main() {
	// 占位：在 Windows 上直接 go build ./cmd/linuxagent 会生成此桩程序。
	// 生成 Linux ELF 请使用：GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o agent.elf ./cmd/linuxagent
	_, _ = os.Stderr.WriteString("linuxagent: 请使用 GOOS=linux GOARCH=amd64 交叉编译，或通过平台「载荷生成」生成 ELF。\n")
	os.Exit(1)
}
