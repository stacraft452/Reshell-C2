package linuxagent

// BootConfig 与载荷生成器 JSON 一致，经 hex 注入 -ldflags。
type BootConfig struct {
	ServerHost string `json:"h"`
	ServerPort int    `json:"p"`
	VKey       string `json:"v"`
	Salt       string `json:"s"`
	WebHost    string `json:"wh"`
	WebPort    int    `json:"wp"`
	HB         int    `json:"hb"`
}
