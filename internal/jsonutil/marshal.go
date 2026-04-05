// Package jsonutil 提供与 C++ Agent 扁平 JSON 解析器一致的序列化方式。
// Go encoding/json 默认 SetEscapeHTML(true) 会把 <>& 编成 \u003c 等，客户端需完整实现 \u 转义；
// 此处关闭 HTML 转义，仅保留 JSON 规范要求的 " \ 控制符转义，便于两端对齐。
package jsonutil

import (
	"bytes"
	"encoding/json"
)

// MarshalCompact 输出紧凑 JSON，无末尾换行，与 C++ parse_flat_json 期望的扁平对象兼容。
func MarshalCompact(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode 会追加 \n
	return bytes.TrimSpace(buf.Bytes()), nil
}
