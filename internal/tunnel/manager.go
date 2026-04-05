package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"gorm.io/gorm"

	"c2/internal/models"
)

// Manager 隧道代理管理器
type Manager struct {
	db       *gorm.DB
	mu       sync.RWMutex
	tunnels  map[uint]*TunnelConn
	connPool map[uint]net.Conn // 客户端连接池
}

// TunnelConn 隧道连接
type TunnelConn struct {
	Tunnel   *models.Tunnel
	Listener net.Listener
	clients  map[string]net.Conn
	stopCh   chan struct{}
	connPool chan net.Conn
}

// NewManager 创建隧道管理器
func NewManager(db *gorm.DB) *Manager {
	return &Manager{
		db:       db,
		tunnels:  make(map[uint]*TunnelConn),
		connPool: make(map[uint]net.Conn),
	}
}

// RegisterClient 注册客户端连接
func (m *Manager) RegisterClient(clientID uint, conn net.Conn) {
	m.mu.Lock()
	m.connPool[clientID] = conn
	m.mu.Unlock()
	log.Printf("[tunnel] RegisterClient: client_id=%d tcp=%s", clientID, conn.RemoteAddr().String())
}

// UnregisterClient 注销客户端连接
func (m *Manager) UnregisterClient(clientID uint) {
	m.mu.Lock()
	delete(m.connPool, clientID)
	m.mu.Unlock()
	log.Printf("[tunnel] UnregisterClient: client_id=%d", clientID)
}

// GetClientConn 获取客户端连接
func (m *Manager) GetClientConn(clientID uint) net.Conn {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connPool[clientID]
}

// CreateTunnel 创建隧道
func (m *Manager) CreateTunnel(clientID uint, name string, listenPort int, targetHost string, targetPort int, tunnelType string, username string, password string) (*models.Tunnel, error) {
	var existingCount int64
	m.db.Model(&models.Tunnel{}).Where("listen_port = ?", listenPort).Count(&existingCount)
	if existingCount > 0 {
		return nil, fmt.Errorf("port %d is already in use by another tunnel", listenPort)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", listenPort))
	if err != nil {
		return nil, fmt.Errorf("port %d is already in use: %v", listenPort, err)
	}
	listener.Close()

	tunnel := &models.Tunnel{
		ClientID:   clientID,
		Name:       name,
		ListenPort: listenPort,
		TargetHost: targetHost,
		TargetPort: targetPort,
		Type:       tunnelType,
		Username:   username,
		Password:   password,
		Status:     "offline",
	}

	if err := m.db.Create(tunnel).Error; err != nil {
		return nil, err
	}

	return tunnel, nil
}

// StartTunnel 启动隧道
func (m *Manager) StartTunnel(tunnelID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tunnels[tunnelID]; exists {
		log.Printf("[tunnel] StartTunnel: tunnel_id=%d already running", tunnelID)
		return nil
	}

	var tunnel models.Tunnel
	if err := m.db.First(&tunnel, tunnelID).Error; err != nil {
		log.Printf("[tunnel] StartTunnel: load tunnel_id=%d from db failed: %v", tunnelID, err)
		return err
	}

	log.Printf("[tunnel] StartTunnel: tunnel_id=%d client_id=%d type=%s listen=%d target=%s:%d",
		tunnel.ID, tunnel.ClientID, tunnel.Type, tunnel.ListenPort, tunnel.TargetHost, tunnel.TargetPort)

	switch tunnel.Type {
	case "socks5":
		return m.startSocks5Tunnel(&tunnel)
	case "tcp_forward":
		return m.startTCPForwardTunnel(&tunnel)
	default:
		return fmt.Errorf("unsupported tunnel type: %s", tunnel.Type)
	}
}

// startSocks5Tunnel 启动SOCKS5隧道
func (m *Manager) startSocks5Tunnel(tunnel *models.Tunnel) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", tunnel.ListenPort))
	if err != nil {
		log.Printf("[tunnel] startSocks5Tunnel: listen failed tunnel_id=%d port=%d err=%v", tunnel.ID, tunnel.ListenPort, err)
		return err
	}

	tc := &TunnelConn{
		Tunnel:   tunnel,
		Listener: listener,
		clients:  make(map[string]net.Conn),
		stopCh:   make(chan struct{}),
	}

	m.tunnels[tunnel.ID] = tc

	m.db.Model(tunnel).Update("status", "online")

	log.Printf("[tunnel] startSocks5Tunnel: running tunnel_id=%d client_id=%d listen=0.0.0.0:%d username=%q",
		tunnel.ID, tunnel.ClientID, tunnel.ListenPort, tunnel.Username)

	go m.acceptSocks5Loop(tc)

	return nil
}

// acceptSocks5Loop SOCKS5接受连接循环
func (m *Manager) acceptSocks5Loop(tc *TunnelConn) {
	for {
		select {
		case <-tc.stopCh:
			return
		default:
		}

		conn, err := tc.Listener.Accept()
		if err != nil {
			select {
			case <-tc.stopCh:
				return
			default:
				log.Printf("SOCKS5 accept error: %v", err)
				continue
			}
		}

		go m.handleSocks5Connection(tc, conn)
	}
}

// handleSocks5Connection 处理SOCKS5连接
func (m *Manager) handleSocks5Connection(tc *TunnelConn, conn net.Conn) {
	defer conn.Close()

	clientConn := m.GetClientConn(tc.Tunnel.ClientID)
	if clientConn == nil {
		return
	}

	connID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	if buf[0] != 0x05 {
		return
	}

	authMethods := int(buf[1])
	hasNoAuth := false
	hasUserPass := false

	for i := 0; i < authMethods && i+2 < n; i++ {
		switch buf[2+i] {
		case 0x00:
			hasNoAuth = true
		case 0x02:
			hasUserPass = true
		}
	}

	requiresAuth := tc.Tunnel.Username != "" && tc.Tunnel.Password != ""

	if requiresAuth {
		if hasUserPass {
			conn.Write([]byte{0x05, 0x02})

			n, err = conn.Read(buf)
			if err != nil {
				return
			}

			if buf[0] != 0x01 {
				return
			}

			ulen := int(buf[1])
			if ulen+2 > n {
				return
			}
			username := string(buf[2 : 2+ulen])

			plen := int(buf[2+ulen])
			if 2+ulen+1+plen > n {
				return
			}
			password := string(buf[3+ulen : 3+ulen+plen])

			if username != tc.Tunnel.Username || password != tc.Tunnel.Password {
				conn.Write([]byte{0x01, 0x01})
				return
			}

			conn.Write([]byte{0x01, 0x00})
		} else {
			conn.Write([]byte{0x05, 0xFF})
			return
		}
	} else {
		if hasNoAuth {
			conn.Write([]byte{0x05, 0x00})
		} else if hasUserPass {
			conn.Write([]byte{0x05, 0x02})

			n, err = conn.Read(buf)
			if err != nil {
				return
			}

			if buf[0] != 0x01 {
				return
			}

			conn.Write([]byte{0x01, 0x00})
		} else {
			conn.Write([]byte{0x05, 0xFF})
			return
		}
	}

	n, err = conn.Read(buf)
	if err != nil {
		return
	}

	if buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	var targetPort int

	switch buf[3] {
	case 0x01:
		targetHost = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		targetPort = int(buf[8])<<8 | int(buf[9])
	case 0x03:
		hostLen := int(buf[4])
		targetHost = string(buf[5 : 5+hostLen])
		targetPort = int(buf[5+hostLen])<<8 | int(buf[6+hostLen])
	case 0x04:
		return
	default:
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	tunnelReq := map[string]interface{}{
		"type":        "tunnel_connect",
		"tunnel_id":   tc.Tunnel.ID,
		"conn_id":     connID,
		"target_host": targetHost,
		"target_port": targetPort,
	}

	reqData, _ := json.Marshal(tunnelReq)
	fmt.Fprintf(clientConn, "%s\n", reqData)

	tc.clients[connID] = conn

	go m.proxyLoop(tc, conn, connID, clientConn)
}

// proxyLoop 代理数据转发循环
func (m *Manager) proxyLoop(tc *TunnelConn, conn net.Conn, connID string, clientConn net.Conn) {
	defer func() {
		delete(tc.clients, connID)
		conn.Close()
	}()

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-tc.stopCh:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Proxy read error: %v", err)
			}
			return
		}

		m.db.Model(tc.Tunnel).UpdateColumn("bytes_in", gorm.Expr("bytes_in + ?", n))

		tunnelData := map[string]interface{}{
			"type":      "tunnel_data",
			"tunnel_id": tc.Tunnel.ID,
			"conn_id":   connID,
			"direction": "out",
			"data":      base64.StdEncoding.EncodeToString(buf[:n]),
		}

		data, _ := json.Marshal(tunnelData)
		fmt.Fprintf(clientConn, "%s\n", data)
	}
}

// startTCPForwardTunnel 启动TCP转发隧道
func (m *Manager) startTCPForwardTunnel(tunnel *models.Tunnel) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", tunnel.ListenPort))
	if err != nil {
		log.Printf("[tunnel] startTCPForwardTunnel: listen failed tunnel_id=%d port=%d err=%v", tunnel.ID, tunnel.ListenPort, err)
		return err
	}

	tc := &TunnelConn{
		Tunnel:   tunnel,
		Listener: listener,
		clients:  make(map[string]net.Conn),
		stopCh:   make(chan struct{}),
	}

	m.tunnels[tunnel.ID] = tc
	m.db.Model(tunnel).Update("status", "online")

	log.Printf("[tunnel] startTCPForwardTunnel: running tunnel_id=%d client_id=%d listen=0.0.0.0:%d -> %s:%d",
		tunnel.ID, tunnel.ClientID, tunnel.ListenPort, tunnel.TargetHost, tunnel.TargetPort)

	go m.acceptTCPForwardLoop(tc)

	return nil
}

// acceptTCPForwardLoop TCP转发接受连接循环
func (m *Manager) acceptTCPForwardLoop(tc *TunnelConn) {
	for {
		select {
		case <-tc.stopCh:
			return
		default:
		}

		conn, err := tc.Listener.Accept()
		if err != nil {
			select {
			case <-tc.stopCh:
				return
			default:
				continue
			}
		}

		go m.handleTCPForwardConnection(tc, conn)
	}
}

// handleTCPForwardConnection 处理TCP转发连接
func (m *Manager) handleTCPForwardConnection(tc *TunnelConn, conn net.Conn) {
	defer conn.Close()

	clientConn := m.GetClientConn(tc.Tunnel.ClientID)
	if clientConn == nil {
		return
	}

	connID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())

	tunnelReq := map[string]interface{}{
		"type":        "tunnel_connect",
		"tunnel_id":   tc.Tunnel.ID,
		"conn_id":     connID,
		"target_host": tc.Tunnel.TargetHost,
		"target_port": tc.Tunnel.TargetPort,
	}

	reqData, _ := json.Marshal(tunnelReq)
	fmt.Fprintf(clientConn, "%s\n", reqData)

	tc.clients[connID] = conn

	go m.proxyLoop(tc, conn, connID, clientConn)
}

// StopTunnel 停止隧道
func (m *Manager) StopTunnel(tunnelID uint) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tc, exists := m.tunnels[tunnelID]
	if exists {
		close(tc.stopCh)
		tc.Listener.Close()

		for _, conn := range tc.clients {
			conn.Close()
		}

		delete(m.tunnels, tunnelID)
	}
	// 无论内存里是否存在，都将数据库状态置为 offline，避免重启后状态陈旧。
	m.db.Model(&models.Tunnel{}).Where("id = ?", tunnelID).Update("status", "offline")
	log.Printf("[tunnel] StopTunnel: tunnel_id=%d stopped (status=offline)", tunnelID)
}

// DeleteTunnel 删除隧道
func (m *Manager) DeleteTunnel(tunnelID uint) {
	m.StopTunnel(tunnelID)
	m.db.Delete(&models.Tunnel{}, tunnelID)
}

// ListTunnels 列出所有隧道
func (m *Manager) ListTunnels(clientID uint) []models.Tunnel {
	var tunnels []models.Tunnel
	m.db.Where("client_id = ?", clientID).Find(&tunnels)
	// 以实际运行态（内存中的 listener）修正状态，防止 DB 中遗留 online 假象。
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range tunnels {
		if _, ok := m.tunnels[tunnels[i].ID]; ok {
			tunnels[i].Status = "online"
		} else {
			tunnels[i].Status = "offline"
		}
	}
	return tunnels
}

// HandleTunnelData 处理隧道数据（从客户端返回）
func (m *Manager) HandleTunnelData(tunnelID uint, connID string, data []byte, direction string) {
	m.mu.RLock()
	tc, exists := m.tunnels[tunnelID]
	m.mu.RUnlock()

	if !exists {
		return
	}

	conn, exists := tc.clients[connID]
	if !exists {
		return
	}

	if direction == "in" {
		conn.Write(data)
		m.db.Model(tc.Tunnel).UpdateColumn("bytes_out", gorm.Expr("bytes_out + ?", len(data)))
	}
}
