package heartbeat

import (
	"log"
	"time"

	"gorm.io/gorm"

	"c2/internal/models"
)

// Monitor 心跳监控器
type Monitor struct {
	db     *gorm.DB
	stopCh chan struct{}
}

// NewMonitor 创建心跳监控器
func NewMonitor(db *gorm.DB) *Monitor {
	return &Monitor{
		db:     db,
		stopCh: make(chan struct{}),
	}
}

// Start 启动监控循环
func (m *Monitor) Start() {
	go m.monitorLoop()
}

// Stop 停止监控
func (m *Monitor) Stop() {
	close(m.stopCh)
}

func (m *Monitor) monitorLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkHeartbeats()
		}
	}
}

// checkHeartbeats 检查所有客户端的心跳状态
func (m *Monitor) checkHeartbeats() {
	var clients []models.Client
	if err := m.db.Where("status = ?", "online").Find(&clients).Error; err != nil {
		log.Printf("Failed to query online clients: %v", err)
		return
	}

	now := time.Now()
	for _, client := range clients {
		// 获取关联的监听器配置
		var listener models.Listener
		if client.AssociatedListenerID != nil {
			if err := m.db.First(&listener, *client.AssociatedListenerID).Error; err != nil {
				continue
			}
		} else {
			// 使用默认配置
			listener.HeartbeatIntervalSec = 30
			listener.HeartbeatTimeoutCount = 3
		}

		// 计算超时时间
		timeout := time.Duration(listener.HeartbeatIntervalSec*listener.HeartbeatTimeoutCount) * time.Second

		// 检查是否超时
		if client.LastHeartbeatAt != nil && now.Sub(*client.LastHeartbeatAt) > timeout {
			log.Printf("Client %d heartbeat timeout, marking as offline", client.ID)
			m.db.Model(&client).Updates(map[string]interface{}{
				"status":         "offline",
				"last_online_at": now,
			})
		}
	}
}

// UpdateClientHeartbeat 更新客户端心跳
func (m *Monitor) UpdateClientHeartbeat(clientID uint, heartbeatValue int) error {
	now := time.Now()
	return m.db.Model(&models.Client{}).Where("id = ?", clientID).Updates(map[string]interface{}{
		"status":            "online",
		"heartbeat_value":   heartbeatValue,
		"last_heartbeat_at": &now,
	}).Error
}
