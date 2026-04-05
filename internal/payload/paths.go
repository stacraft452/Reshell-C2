package payload

// 路径约定（相对进程工作目录，或与可执行文件同目录）：
//
//	data/stubs/windows_x64.exe   ← 目标 OS：windows_x64
//	data/stubs/windows_x86.exe   ← 目标 OS：windows_x86
//	data/stubs/linux_amd64.elf   ← 目标 OS：linux_amd64
//
// 生成结果写入 data/generated/（不再使用 data/payloads）。
// 可选环境变量 C2_STUB_DIR 覆盖模板目录；可选 go build -tags=stubembed 内嵌 stubbin/*。

const (
	RelPathStubs     = "data/stubs"
	RelPathGenerated = "data/generated"
)
