package listener

import (
	"log"
	"net"
	"sync"

	"gorm.io/gorm"

	"c2/internal/models"
)

// Manager 负责根据数据库记录启动和关闭监听端口（目前只实现 TCP）。
type Manager struct {
	db *gorm.DB

	mu        sync.Mutex
	running   map[uint]*tcpListener
	onAccept  func(l *models.Listener, conn net.Conn)
}

type tcpListener struct {
	listener net.Listener
	stopCh   chan struct{}
}

// NewManager 创建监听管理器。
// onAccept 在有新客户端连接时被调用，由上层负责后续协议处理。
func NewManager(db *gorm.DB, onAccept func(l *models.Listener, conn net.Conn)) *Manager {
	return &Manager{
		db:      db,
		running: make(map[uint]*tcpListener),
		onAccept: onAccept,
	}
}

// StartListener 根据监听记录启动 TCP 监听。
func (m *Manager) StartListener(l *models.Listener) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.running[l.ID]; exists {
		return nil
	}

	ln, err := net.Listen("tcp", l.ListenAddr)
	if err != nil {
		return err
	}

	tl := &tcpListener{
		listener: ln,
		stopCh:   make(chan struct{}),
	}
	m.running[l.ID] = tl

	go m.acceptLoop(l, tl)

	// 更新状态
	m.db.Model(l).Update("status", "online")
	return nil
}

// StopListener 停止指定监听。
func (m *Manager) StopListener(id uint) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tl, ok := m.running[id]
	if !ok {
		return
	}
	close(tl.stopCh)
	_ = tl.listener.Close()
	delete(m.running, id)

	m.db.Model(&models.Listener{}).Where("id = ?", id).Update("status", "offline")
}

func (m *Manager) acceptLoop(l *models.Listener, tl *tcpListener) {
	for {
		conn, err := tl.listener.Accept()
		if err != nil {
			select {
			case <-tl.stopCh:
				return
			default:
			}
			log.Printf("accept error on listener %d: %v", l.ID, err)
			return
		}

		// 交给上层进行协议处理
		if m.onAccept != nil {
			go m.onAccept(l, conn)
		} else {
			_ = conn.Close()
		}
	}
}

