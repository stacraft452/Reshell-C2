package models

import (
	"time"

	"gorm.io/gorm"

	"c2/internal/encodingutil"
)

// Client 表示一个上线的客户端。
// json 标签与 Web 前端（client_detail / clients 列表）一致，使用 snake_case。
type Client struct {
	ID uint `gorm:"primaryKey" json:"id"`

	Remark string `gorm:"size:255" json:"remark"`

	ConnectMethod string `gorm:"size:32" json:"connect_method"`

	ExternalIP       string `gorm:"size:64" json:"external_ip"`
	ExternalLocation string `gorm:"size:255" json:"external_location"`
	InternalIP       string `gorm:"size:64" json:"internal_ip"`
	Username         string `gorm:"size:255" json:"username"`
	Hostname         string `gorm:"size:255" json:"hostname"`
	OSType           string `gorm:"size:64" json:"os_type"`
	ProcessName      string `gorm:"size:255" json:"process_name"`
	ProcessID        int    `json:"process_id"`
	WorkingDirectory string `gorm:"size:1024" json:"working_directory"`
	Status           string `gorm:"size:32;default:offline" json:"status"`
	HeartbeatValue   int    `json:"heartbeat_value"`
	LastHeartbeatAt  *time.Time `json:"last_heartbeat_at,omitempty"`
	FirstOnlineAt    *time.Time `json:"first_online_at,omitempty"`
	LastOnlineAt     *time.Time `json:"last_online_at,omitempty"`
	AssociatedListenerID *uint `json:"associated_listener_id,omitempty"`

	OSVersion     string `gorm:"size:255" json:"os_version"`
	Architecture  string `gorm:"size:64" json:"architecture"`
	MemorySize    int64  `json:"memory_size"`
	CPUInfo       string `gorm:"size:255" json:"cpu_info"`
	DiskSize      int64  `json:"disk_size"`
	GpuInfo              string `gorm:"type:text" json:"gpu_info"`
	ScreenResolution     string `gorm:"size:64" json:"screen_resolution"`
	LogicalProcessors    int    `json:"logical_processors"`
	NetworkCard   string `gorm:"type:text" json:"network_card,omitempty"`
	InstalledApps string `gorm:"type:text" json:"installed_apps,omitempty"`

	IsAdmin    bool   `json:"is_admin"`
	IsElevated bool   `json:"is_elevated"`
	Integrity  string `gorm:"size:64" json:"integrity"`

	AutoStart     bool   `gorm:"default:false" json:"auto_start"`
	AutoStartType string `gorm:"size:64" json:"auto_start_type"`

	DeletedAt         *time.Time `json:"deleted_at,omitempty"`
	IsManuallyDeleted bool       `json:"is_manually_deleted"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AfterFind 读库后统一将可能为 GBK/ANSI 的字段规范为 UTF-8，供列表与详情 API 展示。
func (c *Client) AfterFind(tx *gorm.DB) error {
	c.Hostname = encodingutil.FixLocalString(c.Hostname)
	c.Username = encodingutil.FixLocalString(c.Username)
	c.ProcessName = encodingutil.FixLocalString(c.ProcessName)
	c.OSVersion = encodingutil.FixLocalString(c.OSVersion)
	c.CPUInfo = encodingutil.FixLocalString(c.CPUInfo)
	c.GpuInfo = encodingutil.FixLocalString(c.GpuInfo)
	c.WorkingDirectory = encodingutil.FixLocalString(c.WorkingDirectory)
	c.ExternalLocation = encodingutil.FixLocalString(c.ExternalLocation)
	c.NetworkCard = encodingutil.FixLocalString(c.NetworkCard)
	c.InstalledApps = encodingutil.FixLocalString(c.InstalledApps)
	return nil
}

// Screenshot 屏幕截图记录
type Screenshot struct {
	ID        uint `gorm:"primaryKey"`
	ClientID  uint
	Data      []byte `gorm:"type:blob"` // 截图数据
	Width     int
	Height    int
	Format    string `gorm:"size:32"` // png/jpeg
	CreatedAt time.Time
}

// Tunnel 隧道代理
type Tunnel struct {
	ID         uint `gorm:"primaryKey"`
	ClientID   uint
	Name       string `gorm:"size:255"`
	ListenPort int    // 本地监听端口
	TargetHost string `gorm:"size:255"` // 目标主机
	TargetPort int    // 目标端口
	Type       string `gorm:"size:32"`                 // socks5/tcp_forward
	Status     string `gorm:"size:32;default:offline"` // online/offline
	Username   string `gorm:"size:255"`                // SOCKS5用户名（可选）
	Password   string `gorm:"size:255"`                // SOCKS5密码（可选）
	BytesIn    int64  // 入站流量
	BytesOut   int64  // 出站流量
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Script 生成的脚本
type Script struct {
	ID         uint `gorm:"primaryKey"`
	ListenerID uint
	Type       string `gorm:"size:32"` // windows_bat/linux_sh/powershell
	Content    string `gorm:"type:text"`
	OneLiner   string `gorm:"type:text"` // 单行命令
	CreatedAt  time.Time
}
