// Package config 从当前工作目录加载 config.yaml，供服务端启动使用。
// YAML 键名与下方 mapstructure 标签一致；修改后需重启进程生效。
package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// ServerConfig 对应 YAML 中的 server: 段。
type ServerConfig struct {
	// Addr HTTP 管理面板与 WebSocket（如 /ws/agent）的监听地址。
	// 常见写法：
	//   ":8080"           — 监听本机所有网卡的 8080（IPv4/IPv6 由系统决定），适合部署后从局域网或公网访问（需防火墙放行）。
	//   "127.0.0.1:8080"  — 仅本机可访问，适合只在本机调试。
	//   "0.0.0.0:8080"    — 显式监听所有 IPv4 接口，效果与 ":8080" 在多数场景接近。
	Addr string `mapstructure:"addr"`

	// PublicHost 可选。下发给已上线 Agent 的「Web 主机名或 IP」，不含端口；端口始终取自 Addr 中的端口。
	// 用途：Agent 建立 TCP 后，若需连 /ws/agent，平台会告知其应访问的 Web 地址；此处避免管理员用浏览器打开
	// http://127.0.0.1:8080 时，把 127.0.0.1 误发给远端肉鸡（肉鸡会连自己）。
	// 如何填写：
	//   公网场景：填公网 IP 或域名，如 "203.0.113.10" 或 "c2.example.com"。
	//   纯内网：可填内网 IP，如 "192.168.1.17"（仅当所有客户端都能路由到该地址）。
	//   不填：依次尝试用「客户端所属监听器 ExternalAddr 中的主机部分」、当前 HTTP 请求的 Host、再回退到 127.0.0.1+端口。
	// 勿填 "0.0.0.0" 作为目标地址，它不是客户端可拨号的有效主机名。
	PublicHost string `mapstructure:"public_host"`
}

// AuthConfig 对应 YAML 中的 auth: 段。
type AuthConfig struct {
	// LoginPassword 浏览器登录管理面板的固定密码（明文存放在配置文件中，请妥善保管配置文件权限）。
	LoginPassword string `mapstructure:"login_password"`

	// JWTSecret 签发与校验会话 JWT 的密钥，须改为长随机字符串；泄露后攻击者可伪造登录态。
	// 修改后：已登录用户需重新登录。
	JWTSecret string `mapstructure:"jwt_secret"`
}

// DatabaseConfig 对应 YAML 中的 database: 段。
type DatabaseConfig struct {
	// Path SQLite 数据库文件路径（相对当前工作目录或绝对路径）。
	// 首次运行会自动创建目录与库文件；迁移服务器时可拷贝该文件保留历史数据。
	Path string `mapstructure:"path"`
}

// LoggingConfig 对应 YAML 中的 logging: 段。
type LoggingConfig struct {
	// Level 日志级别，常见取值：debug, info, warn, error（具体以项目使用的日志库为准，当前多为 info）。
	Level string `mapstructure:"level"`
}

// Config 根配置，与 config.yaml 顶层键一一对应。
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Database DatabaseConfig `mapstructure:"database"`
	Logging  LoggingConfig  `mapstructure:"logging"`
}

// Load 从当前工作目录（.）读取 config.yaml。
// 启动方式：在包含 config.yaml 的目录下执行可执行文件，或先 cd 到该目录再启动。
func Load() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}
