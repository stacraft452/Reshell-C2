// Package encodingutil 处理 Windows 等环境下 GBK/ANSI 与 UTF-8 混用时的展示与入库。
package encodingutil

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// cjkCount 粗略统计中日韩统一表意文字数量（用于判断是否已为合法 UTF-8 中文）。
func cjkCount(s string) int {
	n := 0
	for _, r := range s {
		if (r >= 0x4e00 && r <= 0x9fff) || (r >= 0x3400 && r <= 0x4dbf) {
			n++
		}
	}
	return n
}

// FixLocalString 将可能为 GBK/ANSI 误当 UTF-8、或 UTF-8 字节被误按 GBK 解析的字符串规范为 UTF-8。
// - 非法 UTF-8：按 GBK 解码再转 UTF-8。
// - 合法 UTF-8 且已含 CJK：视为已正确，不再二次解码（避免把正确中文再误转）。
// - 合法 UTF-8 且无 CJK：尝试按 GBK 流解码；若结果含更多 CJK（典型：主机名乱码修复），则采用新串。
func FixLocalString(s string) string {
	if s == "" {
		return s
	}
	if !utf8.ValidString(s) {
		b, _, err := transform.Bytes(simplifiedchinese.GBK.NewDecoder(), []byte(s))
		if err == nil {
			out := string(b)
			if utf8.ValidString(out) {
				return out
			}
		}
		return s
	}
	if cjkCount(s) > 0 {
		return s
	}
	b, _, err := transform.Bytes(simplifiedchinese.GBK.NewDecoder(), []byte(s))
	if err != nil {
		return s
	}
	alt := string(b)
	if !utf8.ValidString(alt) {
		return s
	}
	if alt == s {
		return s
	}
	if cjkCount(alt) > cjkCount(s) {
		return alt
	}
	if strings.ContainsRune(s, '\uFFFD') && cjkCount(alt) >= cjkCount(s) {
		return alt
	}
	return s
}
