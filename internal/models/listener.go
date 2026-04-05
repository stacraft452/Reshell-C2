package models

import "time"

// Listener 表示一个监听端口配置。
type Listener struct {
	ID uint `gorm:"primaryKey"`

	Remark string `gorm:"size:255"` // 备注

	// 模式（仅实现 tcp）
	Mode string `gorm:"size:32;default:tcp"`

	// 本机监听地址，例如 0.0.0.0:4444
	ListenAddr string `gorm:"size:255"`

	// 外网连接地址（写入 shellcode 的回连地址）
	ExternalAddr string `gorm:"size:255"`

	// 心跳配置
	HeartbeatTimeoutCount int `gorm:"default:3"`
	HeartbeatIntervalSec  int `gorm:"default:30"`

	// 通信凭证 & 加密盐
	VKey string `gorm:"size:255"`
	Salt string `gorm:"size:255"`

	// 状态：online/offline
	Status string `gorm:"size:32;default:offline"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

