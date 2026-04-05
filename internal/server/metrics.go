package server

import (
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	gnet "github.com/shirou/gopsutil/v3/net"
)

type systemMetrics struct {
	GOOS               string
	SwapLabel          string
	DiskLabel          string
	CPUUsagePercent    float64
	DiskUsagePercent   float64
	MemoryUsagePercent float64
	SwapUsagePercent   float64
	TCPEstablished     int
	UDPCount           int
	NetOutBps          float64
	NetInBps           float64
}

var (
	netIOMu       sync.Mutex
	netLastTime   time.Time
	netLastSent   uint64
	netLastRecv   uint64
	netSampleInit bool
)

func diskUsageRoot() (usedPercent float64, label string) {
	label = "/"
	paths := []string{"/"}
	if runtime.GOOS == "windows" {
		paths = []string{`C:`, `C:\`, `/`}
		label = "C:"
	}
	for _, p := range paths {
		if d, err := disk.Usage(p); err == nil && d.Total > 0 {
			return d.UsedPercent, p
		}
	}
	return 0, label
}

func countTCPEstablished() int {
	conns, err := gnet.Connections("tcp")
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range conns {
		st := strings.ToUpper(c.Status)
		if st == "ESTABLISHED" || st == "ESTAB" {
			n++
		}
	}
	return n
}

func countUDPSockets() int {
	conns, err := gnet.Connections("udp")
	if err != nil {
		return 0
	}
	return len(conns)
}

func updateNetBandwidth() (outBps, inBps float64) {
	counters, err := gnet.IOCounters(false)
	if err != nil || len(counters) == 0 {
		return 0, 0
	}
	var sent, recv uint64
	for i := range counters {
		sent += counters[i].BytesSent
		recv += counters[i].BytesRecv
	}
	now := time.Now()
	netIOMu.Lock()
	defer netIOMu.Unlock()
	if !netSampleInit {
		netSampleInit = true
		netLastTime = now
		netLastSent = sent
		netLastRecv = recv
		return 0, 0
	}
	dt := now.Sub(netLastTime).Seconds()
	if dt <= 0.05 {
		return 0, 0
	}
	outBps = float64(sent-netLastSent) / dt
	inBps = float64(recv-netLastRecv) / dt
	if outBps < 0 {
		outBps = 0
	}
	if inBps < 0 {
		inBps = 0
	}
	netLastTime = now
	netLastSent = sent
	netLastRecv = recv
	return outBps, inBps
}

func collectSystemMetrics() systemMetrics {
	var m systemMetrics
	m.GOOS = runtime.GOOS
	if m.GOOS == "windows" {
		m.SwapLabel = "虚拟内存占用率"
		m.DiskLabel = "磁盘占用率（系统盘）"
	} else {
		m.SwapLabel = "交换分区占用率"
		m.DiskLabel = "磁盘占用率（根分区 /）"
	}

	// 短阻塞换较准的 CPU 占用（仪表盘轮询间隔较长，可接受）
	if percentages, err := cpu.Percent(150*time.Millisecond, false); err == nil && len(percentages) > 0 {
		m.CPUUsagePercent = percentages[0]
	}

	if v, err := mem.VirtualMemory(); err == nil {
		m.MemoryUsagePercent = v.UsedPercent
	}

	if s, err := mem.SwapMemory(); err == nil {
		if s.Total > 0 {
			m.SwapUsagePercent = s.UsedPercent
		} else {
			m.SwapUsagePercent = 0
		}
	}

	pct, path := diskUsageRoot()
	m.DiskUsagePercent = pct
	if runtime.GOOS == "windows" {
		m.DiskLabel = "磁盘占用率（" + path + "）"
	}

	m.TCPEstablished = countTCPEstablished()
	m.UDPCount = countUDPSockets()
	m.NetOutBps, m.NetInBps = updateNetBandwidth()

	return m
}
