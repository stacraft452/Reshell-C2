//go:build linux

package linuxagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const fileChunkSize = 256 * 1024

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func listDirJSON(dir string) string {
	dir = filepath.Clean(dir)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "[]"
	}
	var parts []string
	for _, e := range entries {
		name := e.Name()
		if name == "." || name == ".." {
			continue
		}
		full := filepath.Join(dir, name)
		info, err := e.Info()
		if err != nil {
			continue
		}
		mt := info.ModTime().Format("2006-01-02 15:04:05")
		parts = append(parts, fmt.Sprintf(`{"name":%s,"path":%s,"is_dir":%t,"size":%d,"modified":%s}`,
			jsonEscape(name), jsonEscape(filepath.ToSlash(full)), e.IsDir(), info.Size(), jsonEscape(mt)))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func listDirChildrenJSON(rawPath string) string {
	p := filepath.Clean(strings.TrimSpace(rawPath))
	if p == "." || p == "" || p == "/" {
		var parts []string
		entries, err := os.ReadDir("/")
		if err != nil {
			return "[]"
		}
		for _, e := range entries {
			name := e.Name()
			if name == "." || name == ".." {
				continue
			}
			full := filepath.Join("/", name)
			if !e.IsDir() {
				continue
			}
			parts = append(parts, fmt.Sprintf(`{"name":%s,"path":%s,"type":"directory"}`,
				jsonEscape(name), jsonEscape(filepath.ToSlash(full))))
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return "[]"
	}
	var parts []string
	for _, e := range entries {
		name := e.Name()
		if name == "." || name == ".." {
			continue
		}
		full := filepath.Join(p, name)
		info, err := e.Info()
		if err != nil {
			continue
		}
		mt := info.ModTime().Format("2006-01-02 15:04:05")
		typ := "file"
		if e.IsDir() {
			typ = "directory"
		}
		parts = append(parts, fmt.Sprintf(`{"name":%s,"path":%s,"is_dir":%t,"size":%d,"modified":%s,"type":%s}`,
			jsonEscape(name), jsonEscape(filepath.ToSlash(full)), e.IsDir(), info.Size(), jsonEscape(mt), jsonEscape(typ)))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func mkdirLinux(path string) (string, bool) {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err.Error(), false
	}
	return "mkdir ok", true
}

func readFileB64(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return err.Error(), false
	}
	return base64.StdEncoding.EncodeToString(b), true
}

func readFileRangeB64(path string, offset uint64, maxRead int) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return err.Error(), false
	}
	defer f.Close()
	if _, err := f.Seek(int64(offset), io.SeekStart); err != nil {
		return err.Error(), false
	}
	buf := make([]byte, maxRead)
	n, err := f.Read(buf)
	if n <= 0 {
		if err != nil && err != io.EOF {
			return err.Error(), false
		}
		return "", true
	}
	return base64.StdEncoding.EncodeToString(buf[:n]), true
}

func writeFileFull(path, b64 string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err.Error(), false
	}
	if err := os.WriteFile(path, raw, 0644); err != nil {
		return err.Error(), false
	}
	return "write_file ok", true
}

func writeFileChunk(path, b64 string, chunkIndex uint64) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err.Error(), false
	}
	if chunkIndex == 0 {
		if err := os.WriteFile(path, raw, 0644); err != nil {
			return err.Error(), false
		}
		return "write_file_chunk[0] ok", true
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return err.Error(), false
	}
	defer f.Close()
	off := int64(chunkIndex) * int64(fileChunkSize)
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return err.Error(), false
	}
	if _, err := f.Write(raw); err != nil {
		return err.Error(), false
	}
	return fmt.Sprintf("write_file_chunk[%d] ok", chunkIndex), true
}

func execShell(cmd string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out) + err.Error()
	}
	return string(out)
}
