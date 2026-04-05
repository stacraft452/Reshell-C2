//go:build linux

package linuxagent

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

func isVirtualLinuxIface(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	prefixes := []string{
		"docker", "br-", "veth", "virbr", "vmnet", "lo", "tun", "wg", "zt",
		"dummy", "ifb", "gre", "erspan", "sit", "ip6tnl",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// classifyLinuxIface：0=有线类 eth/en*，1=无线类 wl*，2=其它物理；虚拟/桥接为 -1。
func classifyLinuxIface(name string) int {
	if isVirtualLinuxIface(name) {
		return -1
	}
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "eth"), strings.HasPrefix(n, "en"):
		return 0
	case strings.HasPrefix(n, "wl"):
		return 1
	default:
		return 2
	}
}

func firstIPv4OnInterface(iface net.Interface) string {
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if v4 := ipnet.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}

// firstNonLoopbackIPv4 优先有线(eth/en*)，其次无线(wl*)，再其它；跳过 docker/桥接等虚拟接口。
func firstNonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	var wired, wireless, other []net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		switch classifyLinuxIface(iface.Name) {
		case 0:
			wired = append(wired, iface)
		case 1:
			wireless = append(wireless, iface)
		case 2:
			other = append(other, iface)
		}
	}
	for _, group := range [][]net.Interface{wired, wireless, other} {
		for _, iface := range group {
			if ip := firstIPv4OnInterface(iface); ip != "" {
				return ip
			}
		}
	}
	return "unknown"
}

// internalIPLinuxViaRoute 用内核选路结果（与「访问公网时走哪块网卡」一致），解析本机 src 地址。
func internalIPLinuxViaRoute() string {
	out, err := exec.Command("ip", "-4", "route", "get", "223.5.5.5").CombinedOutput()
	if err != nil {
		return ""
	}
	s := string(out)
	i := strings.Index(s, " src ")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(s[i+5:])
	fields := strings.Fields(rest)
	if len(fields) < 1 {
		return ""
	}
	ip := net.ParseIP(fields[0])
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ""
}

func diskRootGB() int64 {
	du, err := disk.Usage("/")
	if err != nil {
		return 0
	}
	return int64(du.Total / (1024 * 1024 * 1024))
}

func cpuModel() string {
	infos, err := cpu.Info()
	if err != nil || len(infos) == 0 {
		return "unknown"
	}
	return strings.TrimSpace(infos[0].ModelName)
}

func gpuInfoLinux() string {
	// 可选 lspci，失败则留空
	out, err := exec.Command("sh", "-c", "lspci 2>/dev/null | grep -iE 'vga|3d|display' | head -3").Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func screenResLinux() string {
	out, err := exec.Command("sh", "-c", "xdpyinfo 2>/dev/null | awk '/dimensions:/ {print $2; exit}'").Output()
	if err != nil || len(out) == 0 {
		w := os.Getenv("COLUMNS")
		h := os.Getenv("LINES")
		if w != "" && h != "" {
			return w + "x" + h
		}
		return ""
	}
	return strings.TrimSpace(string(out))
}

func networkCardLinux() string {
	out, err := exec.Command("ip", "-br", "addr").Output()
	if err == nil && len(out) > 0 {
		s := strings.TrimSpace(string(out))
		if len(s) > 1200 {
			return s[:1200] + "…"
		}
		return s
	}
	var b strings.Builder
	ifaces, err := net.Interfaces()
	if err != nil {
		return firstNonLoopbackIPv4()
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if v4 := ipnet.IP.To4(); v4 != nil {
					if b.Len() > 0 {
						b.WriteString(" | ")
					}
					b.WriteString(iface.Name)
					b.WriteString(": ")
					b.WriteString(v4.String())
				}
			}
		}
	}
	if b.Len() == 0 {
		return firstNonLoopbackIPv4()
	}
	return b.String()
}

func installedAppsLinux() string {
	var sb strings.Builder
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		out, err := exec.Command("dpkg-query", "-W", "-f", "${Package}\n").Output()
		if err == nil && len(out) > 0 {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			n := 50
			if len(lines) < n {
				n = len(lines)
			}
			for i := 0; i < n; i++ {
				if i > 0 {
					sb.WriteString("; ")
				}
				sb.WriteString(strings.TrimSpace(lines[i]))
			}
			return sb.String()
		}
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\n").Output()
		if err == nil && len(out) > 0 {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			n := 50
			if len(lines) < n {
				n = len(lines)
			}
			for i := 0; i < n; i++ {
				if i > 0 {
					sb.WriteString("; ")
				}
				sb.WriteString(strings.TrimSpace(lines[i]))
			}
			return sb.String()
		}
	}
	return ""
}

func preferredInternalIPLinux() string {
	if v := internalIPLinuxViaRoute(); v != "" {
		return v
	}
	return firstNonLoopbackIPv4()
}

func autoStartLinux(exe string) (string, string) {
	base := filepath.Base(exe)
	home, err := os.UserHomeDir()
	if err != nil {
		return "false", ""
	}
	dir := filepath.Join(home, ".config", "autostart")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "false", ""
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".desktop") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		s := string(data)
		if strings.Contains(s, base) || strings.Contains(s, exe) {
			return "true", "XDG autostart: " + e.Name()
		}
	}
	return "false", ""
}

func collectRegisterFields(bc BootConfig) map[string]string {
	hi, _ := host.Info()
	u, _ := user.Current()
	hostname, _ := os.Hostname()
	vm, _ := mem.VirtualMemory()
	pid := os.Getpid()
	exe, _ := os.Executable()
	procName := filepath.Base(exe)

	reg := map[string]string{
		"type":                "register",
		"external_ip":         "",
		"external_location":   "",
		"internal_ip":         preferredInternalIPLinux(),
		"username":            "unknown",
		"hostname":            hostname,
		"os_type":             "linux_" + runtime.GOARCH,
		"os_version":          "",
		"architecture":        runtime.GOARCH,
		"process_name":        procName,
		"process_id":          strconv.Itoa(pid),
		"vkey":                bc.VKey,
		"is_admin":            strconv.FormatBool(os.Geteuid() == 0),
		"is_elevated":         strconv.FormatBool(os.Geteuid() == 0),
		"integrity":           "N/A",
		"memory_size":         strconv.FormatUint(vm.Total/(1024*1024), 10),
		"cpu_info":            cpuModel(),
		"disk_size":           strconv.FormatInt(diskRootGB(), 10),
		"screen_resolution":   screenResLinux(),
		"logical_processors": strconv.Itoa(runtime.NumCPU()),
	}
	if u != nil {
		reg["username"] = u.Username
	}
	if hi != nil {
		reg["os_version"] = fmt.Sprintf("%s %s (%s)", hi.Platform, hi.PlatformVersion, hi.KernelVersion)
	}
	if wd, err := os.Getwd(); err == nil {
		reg["working_dir"] = wd
	}
	if g := gpuInfoLinux(); g != "" {
		reg["gpu_info"] = g
	}
	reg["network_card"] = networkCardLinux()
	if apps := installedAppsLinux(); apps != "" {
		reg["installed_apps"] = apps
	}
	as, at := autoStartLinux(exe)
	reg["auto_start"] = as
	reg["auto_start_type"] = at
	return reg
}
