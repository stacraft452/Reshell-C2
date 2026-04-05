package payload

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseListenerHostPort 解析监听器对外地址（支持 host:port 或 http(s)://host:port / tcp://host:port）。
func ParseListenerHostPort(addr string) (host string, port int, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0, fmt.Errorf("empty external address")
	}
	low := strings.ToLower(addr)
	for _, prefix := range []string{"http://", "https://", "tcp://"} {
		if strings.HasPrefix(low, prefix) {
			u, e := url.Parse(addr)
			if e != nil {
				return "", 0, fmt.Errorf("parse URL: %w", e)
			}
			h := u.Hostname()
			ps := u.Port()
			if h == "" || ps == "" {
				return "", 0, fmt.Errorf("URL 须含主机与端口，例如 http://192.168.1.1:4444")
			}
			p, e := strconv.Atoi(ps)
			if e != nil || p < 1 || p > 65535 {
				return "", 0, fmt.Errorf("无效端口: %q", ps)
			}
			return h, p, nil
		}
	}
	h, ps, e := net.SplitHostPort(addr)
	if e != nil {
		return "", 0, fmt.Errorf("地址格式无效 %q（请用 host:port 或 http://host:port）: %w", addr, e)
	}
	p, e := strconv.Atoi(ps)
	if e != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("无效端口: %q", ps)
	}
	return h, p, nil
}

// DialHostPortForAgent 解析写入载荷的 TCP 回连地址。
// external 须为 host:port / http(s)://host:port / tcp://host:port；若用户只填裸 IP 或主机名（无端口），则用 listen_addr 的端口补全。
func DialHostPortForAgent(externalAddr, listenAddr string) (host string, port int, err error) {
	externalAddr = strings.TrimSpace(externalAddr)
	listenAddr = strings.TrimSpace(listenAddr)
	if externalAddr == "" {
		return "", 0, fmt.Errorf("empty external address")
	}

	h, p, e := ParseListenerHostPort(externalAddr)
	if e == nil {
		if p < 1 {
			return "", 0, fmt.Errorf("external_addr 端口无效: %d", p)
		}
		return h, p, nil
	}

	if strings.Contains(externalAddr, "://") {
		return "", 0, e
	}

	// 裸 IPv4 或主机名，整段不含 ':'（避免与畸形 host: 混淆）
	if !strings.Contains(externalAddr, ":") {
		if listenAddr == "" {
			return "", 0, fmt.Errorf("external_addr %q 未含端口且 listen_addr 为空: %w", externalAddr, e)
		}
		_, lp, e2 := ParseListenerHostPort(listenAddr)
		if e2 != nil {
			return "", 0, fmt.Errorf("无法从 listen_addr %q 解析端口: %w", listenAddr, e2)
		}
		if lp < 1 {
			return "", 0, fmt.Errorf("listen_addr 端口无效: %d", lp)
		}
		return externalAddr, lp, nil
	}

	return "", 0, fmt.Errorf("external_addr 格式无效: %w", e)
}
