//go:build stubembed

package payload

import (
	"embed"
	"os"
)

// 将编好的模板放进 stubbin/（可有其一或多项；缺的 OS 需在磁盘 data/stubs/ 或 C2_STUB_DIR 补全）。
// 目录内至少需有一个文件以便 go:embed 通过（仓库自带 README.txt）。
//
//	go build -tags=stubembed
//
//go:embed stubbin/*
var embeddedPayloadStubs embed.FS

func tryLoadEmbeddedStub(osKey string) ([]byte, error) {
	name := stubTemplateName(osKey)
	if name == "" {
		return nil, os.ErrNotExist
	}
	b, err := embeddedPayloadStubs.ReadFile("stubbin/" + name)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, os.ErrNotExist
	}
	return b, nil
}
