package models

import "time"

// CommandLog 记录执行的命令历史
type CommandLog struct {
	ID        uint `gorm:"primaryKey"`
	ClientID  uint
	CommandID string `gorm:"size:64;index"` // 命令唯一ID
	Command   string `gorm:"size:64"`       // 命令类型
	Payload   string `gorm:"type:text"`     // 命令参数JSON
	Result    string `gorm:"type:text"`     // 执行结果
	Status    string `gorm:"size:32"`       // pending, running, completed, failed
	CreatedAt time.Time
	UpdatedAt time.Time
}

// FileTransfer 记录文件传输
type FileTransfer struct {
	ID         uint `gorm:"primaryKey"`
	ClientID   uint
	Type       string `gorm:"size:32"` // upload/download
	Filename   string `gorm:"size:512"`
	RemotePath string `gorm:"size:512"`
	Size       int64
	Status     string `gorm:"size:32;default:pending"` // pending, completed, failed
	Error      string `gorm:"size:512"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Session 表示一个交互式会话
type Session struct {
	ID        uint `gorm:"primaryKey"`
	ClientID  uint
	Type      string `gorm:"size:32"`                // shell, cmd
	Status    string `gorm:"size:32;default:active"` // active, closed
	CreatedAt time.Time
	UpdatedAt time.Time
}
