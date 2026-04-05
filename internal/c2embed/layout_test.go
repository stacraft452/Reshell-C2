package c2embed

import (
	"testing"
)

func TestParseWriteRoundTrip(t *testing.T) {
	buf := make([]byte, 800)
	copy(buf[200:], []byte(MagicString))
	off := 200
	if err := WriteAt(buf, off, "10.0.0.9", 1234, "vk", "sl", 15, "w.h", 8081); err != nil {
		t.Fatal(err)
	}
	p, err := ParseAt(buf, off)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "10.0.0.9" || p.Port != 1234 || p.VKey != "vk" || p.Salt != "sl" || p.Heartbeat != 15 || p.WebHost != "w.h" || p.WebPort != 8081 {
		t.Fatalf("%+v", p)
	}
}

func TestNormalizeParsedHostPortFromComboString(t *testing.T) {
	p := Parsed{Host: "127.0.0.1:4444", Port: 0, WebHost: "[::1]:8080", WebPort: 0}
	NormalizeParsedHostPort(&p)
	if p.Host != "127.0.0.1" || p.Port != 4444 {
		t.Fatalf("tcp %+v", p)
	}
	if p.WebHost != "::1" || p.WebPort != 8080 {
		t.Fatalf("web %+v", p)
	}
}

func TestFindPatchOffsetPrefersFullTemplate(t *testing.T) {
	// 块1：魔数后看似「空 host + port 0」但 vkey 非空 —— 不应再被当成模板
	off1 := 64
	// 块2：真模板（与 C2_EMBED_CONFIG_TEMPLATE_INIT 一致）
	off2 := 64 + TotalSize + 32
	buf := make([]byte, off2+TotalSize+64)
	copy(buf[off1:], []byte(MagicString))
	copy(buf[off2:], []byte(MagicString))
	copy(buf[off2+TotalSize-TailLen:off2+TotalSize], []byte(TailString))
	if err := WriteAt(buf, off1, "", 0, "x", "", 30, "", 0); err != nil {
		t.Fatal(err)
	}
	// off2：首魔数 + 全零字段 + 尾魔数（与未初始化模板一致）
	if FindPatchOffset(buf) != off2 {
		t.Fatalf("want template at %d", off2)
	}
}
