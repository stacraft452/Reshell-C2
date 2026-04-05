package payload

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// 模板文件名与目标 OS 对应关系（须放在 data/stubs/ 或 C2_STUB_DIR 或内嵌 stubbin）：
//
//	windows_x64  → windows_x64.exe
//	windows_x86  → windows_x86.exe
//	linux_amd64  → linux_amd64.elf
func stubTemplateName(osKey string) string {
	switch osKey {
	case "windows_x64":
		return "windows_x64.exe"
	case "windows_x86":
		return "windows_x86.exe"
	case "linux_amd64":
		return "linux_amd64.elf"
	default:
		return ""
	}
}

// StubTemplatePathForOS 返回应在 stubs 目录中存在的文件名（用于错误提示）。
func StubTemplatePathForOS(osKey string) string {
	n := stubTemplateName(osKey)
	if n == "" {
		return ""
	}
	return filepath.Join(RelPathStubs, n)
}

// loadStubTemplate 加载未修补模板：内嵌（-tags=stubembed）→ C2_STUB_DIR → 可执行文件旁 data/stubs → 当前工作目录 data/stubs。
func loadStubTemplate(osKey string) ([]byte, error) {
	name := stubTemplateName(osKey)
	if name == "" {
		return nil, fmt.Errorf("unsupported OS %q", osKey)
	}
	if b, err := tryLoadEmbeddedStub(osKey); err == nil && len(b) > 0 {
		return b, nil
	}
	var paths []string
	if d := strings.TrimSpace(os.Getenv("C2_STUB_DIR")); d != "" {
		paths = append(paths, filepath.Join(d, name))
	}
	if exe, err := os.Executable(); err == nil {
		ed := filepath.Dir(exe)
		paths = append(paths, filepath.Join(ed, RelPathStubs, name))
	}
	paths = append(paths, filepath.Join(RelPathStubs, name))

	var lastErr error
	for _, p := range paths {
		if p == "" {
			continue
		}
		data, err := ioutil.ReadFile(p)
		if err != nil {
			lastErr = err
			continue
		}
		if len(data) > 0 {
			return data, nil
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("未找到模板 %s（已尝试 C2_STUB_DIR、程序旁与 cwd 下的 %s）: %w", name, RelPathStubs, lastErr)
	}
	return nil, fmt.Errorf("未找到模板 %s，请将文件放入 %s/", name, RelPathStubs)
}
