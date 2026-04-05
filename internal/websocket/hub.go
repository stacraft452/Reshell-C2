package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"

	"c2/internal/auth"
	"c2/internal/models"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// Client 表示一个WebSocket连接
type Client struct {
	Hub    *Hub
	Conn   *websocket.Conn
	Send   chan []byte
	UserID string
}

// Hub 管理所有WebSocket连接
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
	db         *gorm.DB
	jwtSecret  string
}

// NewHub 创建一个新的Hub
func NewHub(db *gorm.DB, jwtSecret string) *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		db:         db,
		jwtSecret:  jwtSecret,
	}
}

// Run 启动Hub的消息循环
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("WebSocket client registered: %s", client.UserID)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.Send)
			}
			h.mu.Unlock()
			log.Printf("WebSocket client unregistered: %s", client.UserID)

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.Send <- message:
				default:
					close(client.Send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// BroadcastMessage 向所有连接的客户端广播消息
func (h *Hub) BroadcastMessage(msgType string, data interface{}) {
	message := map[string]interface{}{
		"type":      msgType,
		"data":      data,
		"timestamp": time.Now().UnixMilli(),
	}
	jsonData, err := json.Marshal(message)
	if err != nil {
		log.Printf("Failed to marshal broadcast message: %v", err)
		return
	}
	h.broadcast <- jsonData
}

// HandleWebSocket 处理WebSocket连接升级
func (h *Hub) HandleWebSocket(c *gin.Context) {
	// 从查询参数中获取token
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return
	}

	// 验证token
	claims, err := auth.ParseToken(h.jwtSecret, token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		Hub:    h,
		Conn:   conn,
		Send:   make(chan []byte, 256),
		UserID: claims.Username,
	}

	h.register <- client

	go client.writePump()
	go client.readPump()
}

// readPump 处理来自客户端的消息
func (c *Client) readPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadLimit(512 * 1024) // 512KB
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
	}
}

// writePump 向客户端发送消息
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				_ = c.Conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
			// 每条广播单独一条 WebSocket 文本消息。旧实现把多条 JSON 用 \n 拼进同一帧，
			// 浏览器 event.data 变成 "{...}\n{...}"，JSON.parse 直接失败，终端 onmessage 静默丢包，
			// 重连后广播更密时尤其明显，看起来像「只有第一次能连」。
			batch := [][]byte{message}
		drainSend:
			for {
				select {
				case m := <-c.Send:
					batch = append(batch, m)
				default:
					break drainSend
				}
			}
			for _, m := range batch {
				c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := c.Conn.WriteMessage(websocket.TextMessage, m); err != nil {
					return
				}
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// NotifyClientOnline 通知客户端上线
func (h *Hub) NotifyClientOnline(client *models.Client) {
	h.BroadcastMessage("client_online", map[string]interface{}{
		"id":             client.ID,
		"external_ip":    client.ExternalIP,
		"internal_ip":    client.InternalIP,
		"hostname":       client.Hostname,
		"username":       client.Username,
		"os_type":        client.OSType,
		"process_name":   client.ProcessName,
		"status":         client.Status,
		"connect_method": client.ConnectMethod,
	})
}

// NotifyClientOffline 通知客户端下线
func (h *Hub) NotifyClientOffline(clientID uint) {
	h.BroadcastMessage("client_offline", map[string]interface{}{
		"id": clientID,
	})
}

// NotifyClientHeartbeat 通知客户端心跳更新
func (h *Hub) NotifyClientHeartbeat(client *models.Client) {
	h.BroadcastMessage("client_heartbeat", map[string]interface{}{
		"id":              client.ID,
		"heartbeat_value": client.HeartbeatValue,
		"status":          client.Status,
	})
}

// BroadcastShellOutput 广播shell输出到前端
func (h *Hub) BroadcastShellOutput(clientID uint, sessionID string, data string) {
	dp := data
	if len(dp) > 100 {
		dp = dp[:100] + fmt.Sprintf("...(+%dB)", len(data)-100)
	}
	log.Printf("[trace] 4/5 backend->browser [/ws] shell_output broadcast client_id=%d session_id=%s data_len=%d preview=%q subscribers=hub",
		clientID, sessionID, len(data), dp)
	h.BroadcastMessage("shell_output", map[string]interface{}{
		"client_id":  clientID,
		"session_id": sessionID,
		"data":       data,
	})
}
