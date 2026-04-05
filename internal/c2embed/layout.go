// Package c2embed 定义与 client/c2_embed_config.h 一致的 C2EMBED1 块布局（解析与写入）。
package c2embed

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MagicLen    = 8
	HostLen     = 64
	VkeyLen     = 128
	SaltLen     = 128
	WebHostLen  = 64
	TailLen     = 8
	TotalSize   = MagicLen + HostLen + 4 + VkeyLen + SaltLen + 4 + WebHostLen + 4 + TailLen
	MagicString = "C2EMBED1"
	TailString  = "C2EMBED2"
)

// 相对魔数首字节的字段偏移
const (
	RelOffsetHost      = MagicLen
	RelOffsetPort      = RelOffsetHost + HostLen
	RelOffsetVKey      = RelOffsetPort + 4
	RelOffsetSalt      = RelOffsetVKey + VkeyLen
	RelOffsetHeartbeat = RelOffsetSalt + SaltLen
	RelOffsetWebHost   = RelOffsetHeartbeat + 4
	RelOffsetWebPort   = RelOffsetWebHost + WebHostLen
	RelOffsetTail      = RelOffsetWebPort + 4
)

var magicBytes = []byte(MagicString)
var tailBytes = []byte(TailString)

// FindOffset 在 image 中查找首个 C2EMBED1（仅测试或确知仅有一处时使用）。
func FindOffset(image []byte) int {
	return bytes.Index(image, magicBytes)
}

// isTemplateEmbedBlock 与 client/c2_embed_config.h 中 C2_EMBED_CONFIG_TEMPLATE_INIT 一致：
// 除魔数外应为「空 host、TCP 0、空 vkey/salt、空 web、web_port 0」；心跳占位可为任意合法值。
// 仅用「host+port 为空」会误把随机数据里的巧合当成模板，导致补丁打到错误偏移（常见症状：host 写进假块、真 g_c2_embed 端口仍为 0）。
func isTemplateEmbedBlock(p Parsed) bool {
	return strings.TrimSpace(p.Host) == "" && p.Port == 0 &&
		strings.TrimSpace(p.VKey) == "" && strings.TrimSpace(p.Salt) == "" &&
		strings.TrimSpace(p.WebHost) == "" && p.WebPort == 0
}

// FindPatchOffset 在 PE/ELF 中定位应修补的嵌入块。
// PE：仅在 .rdata* 与其它「已初始化、非可执行」节内搜索，避免误匹配 DOS/空洞等偏移（补丁写进假块会导致运行时 host/vkey 看似对、port 仍为 0）。
// ELF：仅在 PT_LOAD 文件映像内搜索。
// 其它（单测、裸缓冲区）：全文件扫描。
func FindPatchOffset(image []byte) int {
	if isELFMagic(image) {
		off, ok := findPatchOffsetELF(image)
		if ok && off >= 0 {
			return off
		}
		if ok {
			return findPatchOffsetRaw(image)
		}
	}
	if isPEMagic(image) {
		off, ok := findPatchOffsetPE(image)
		if ok && off >= 0 {
			return off
		}
		if ok {
			return findPatchOffsetRaw(image)
		}
	}
	return findPatchOffsetRaw(image)
}

func cstrField(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		i = len(b)
	}
	return string(b[:i])
}

// Parsed 从嵌入块解析出的配置。
type Parsed struct {
	Host      string
	Port      int
	VKey      string
	Salt      string
	Heartbeat int
	WebHost   string
	WebPort   int
}

// ParseAt 从 image[off:] 解析一块（off 须指向魔数起始）。
func ParseAt(image []byte, off int) (Parsed, error) {
	var z Parsed
	if off < 0 || off+TotalSize > len(image) {
		return z, fmt.Errorf("c2embed: offset out of range")
	}
	if string(image[off:off+MagicLen]) != MagicString {
		return z, fmt.Errorf("c2embed: magic mismatch")
	}
	p := image[off+MagicLen:]
	z.Host = cstrField(p[:HostLen])
	p = p[HostLen:]
	z.Port = int(binary.LittleEndian.Uint32(p[:4]))
	p = p[4:]
	z.VKey = cstrField(p[:VkeyLen])
	p = p[VkeyLen:]
	z.Salt = cstrField(p[:SaltLen])
	p = p[SaltLen:]
	z.Heartbeat = int(binary.LittleEndian.Uint32(p[:4]))
	p = p[4:]
	z.WebHost = cstrField(p[:WebHostLen])
	p = p[WebHostLen:]
	z.WebPort = int(binary.LittleEndian.Uint32(p[:4]))
	p = p[4:]
	if len(p) < TailLen || string(p[:TailLen]) != TailString {
		return z, fmt.Errorf("c2embed: tail magic mismatch (need %s)", TailString)
	}
	return z, nil
}

// SplitHostPortField 若 s 为 "host:port" 或 "[ipv6]:port"（与 net.JoinHostPort 一致），返回拆分结果。
func SplitHostPortField(s string) (host string, port int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, false
	}
	h, ps, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, false
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, false
	}
	return h, p, true
}

// NormalizeParsedHostPort 当 port 字段未写入成功但 host 中含 "ip:port" 时，从字符串恢复（与 PatchC2Embed 写入的冗余一致）。
func NormalizeParsedHostPort(p *Parsed) {
	if p == nil {
		return
	}
	if h, port, ok := SplitHostPortField(p.Host); ok {
		p.Host = h
		p.Port = port
	}
	if h, port, ok := SplitHostPortField(p.WebHost); ok {
		p.WebHost = h
		p.WebPort = port
	}
}

// ParseFirst 搜索并解析用于运行时的嵌入块（与修补使用同一套定位逻辑）。
func ParseFirst(image []byte) (Parsed, int, error) {
	off := FindPatchOffset(image)
	if off < 0 {
		return Parsed{}, -1, fmt.Errorf("c2embed: no %s block", MagicString)
	}
	pv, err := ParseAt(image, off)
	if err != nil {
		return pv, off, err
	}
	NormalizeParsedHostPort(&pv)
	return pv, off, nil
}

func writePadded(dst []byte, s string, max int) error {
	if max < 1 {
		return fmt.Errorf("invalid max %d", max)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("invalid utf-8")
	}
	if len(s) >= max {
		return fmt.Errorf("len %d >= max %d", len(s), max)
	}
	copy(dst, s)
	for i := len(s); i < max; i++ {
		dst[i] = 0
	}
	return nil
}

// WriteAt 将配置写入 image[off:] 的嵌入块（off 指向魔数；不修改魔数字节）。
func WriteAt(image []byte, off int, host string, port int, vkey, salt string, hb int, webHost string, webPort int) error {
	if off < 0 || off+TotalSize > len(image) {
		return fmt.Errorf("c2embed: offset out of range")
	}
	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	if webPort < 0 || webPort > 65535 {
		return fmt.Errorf("invalid web_port %d", webPort)
	}
	p := image[off:]
	if string(p[:MagicLen]) != MagicString {
		return fmt.Errorf("c2embed: magic mismatch")
	}
	p = p[MagicLen:]
	if err := writePadded(p[:HostLen], host, HostLen); err != nil {
		return fmt.Errorf("host: %w", err)
	}
	p = p[HostLen:]
	binary.LittleEndian.PutUint32(p[:4], uint32(port))
	binary.LittleEndian.PutUint32(p[:4], uint32(port)) // 重复写入同一 LE 端口，缓解异常环境下的部分写入
	p = p[4:]
	if err := writePadded(p[:VkeyLen], vkey, VkeyLen); err != nil {
		return fmt.Errorf("vkey: %w", err)
	}
	p = p[VkeyLen:]
	if err := writePadded(p[:SaltLen], salt, SaltLen); err != nil {
		return fmt.Errorf("salt: %w", err)
	}
	p = p[SaltLen:]
	binary.LittleEndian.PutUint32(p[:4], uint32(hb))
	p = p[4:]
	if err := writePadded(p[:WebHostLen], webHost, WebHostLen); err != nil {
		return fmt.Errorf("web_host: %w", err)
	}
	p = p[WebHostLen:]
	binary.LittleEndian.PutUint32(p[:4], uint32(webPort))
	binary.LittleEndian.PutUint32(p[:4], uint32(webPort))
	p = p[4:]
	copy(p[:TailLen], tailBytes)
	return nil
}

// ValidForBoot TCP 回连是否已配置（修补后应满足）。
func ValidForBoot(p Parsed) bool {
	return strings.TrimSpace(p.Host) != "" && p.Port > 0 && p.Port <= 65535
}
