//go:build linux

package linuxagent

import (
	"fmt"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

func processListJSON() string {
	procs, err := process.Processes()
	if err != nil {
		return "[]"
	}
	var parts []string
	for _, p := range procs {
		name, _ := p.Name()
		parts = append(parts, fmt.Sprintf(`{"pid":%d,"name":%s}`, p.Pid, jsonEscape(name)))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func killPID(pid int32) bool {
	p, err := process.NewProcess(pid)
	if err != nil {
		return false
	}
	return p.Kill() == nil
}
