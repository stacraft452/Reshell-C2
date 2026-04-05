//go:build !linux

package linuxagent

import "fmt"

// Run 在非 Linux 目标下仅占位，便于本机 go build ./... 通过。
func Run(bc BootConfig) error {
	return fmt.Errorf("linuxagent: 此包仅用于 GOOS=linux 构建（ELF 客户端）")
}
