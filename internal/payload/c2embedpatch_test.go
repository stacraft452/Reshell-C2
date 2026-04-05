package payload

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"c2/internal/c2embed"
)

func TestPatchC2Embed(t *testing.T) {
	buf := make([]byte, 2000)
	off := 100
	copy(buf[off:], []byte(c2embed.MagicString))
	if err := c2embed.WriteAt(buf, off, "", 0, "", "", 30, "", 0); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		VKey:              "k",
		Salt:              "s",
		HeartbeatInterval: 10,
		WebHost:           "10.0.0.1",
		WebPort:           9090,
	}
	out, err := PatchC2Embed(buf, cfg, "192.168.1.2", 5555)
	if err != nil {
		t.Fatal(err)
	}
	p := out[off+c2embed.MagicLen:]
	host := string(bytes.SplitN(p[:c2embed.HostLen], []byte{0}, 2)[0])
	if host != "192.168.1.2:5555" {
		t.Fatalf("host field want combined host:port got %q", host)
	}
	port := binary.LittleEndian.Uint32(p[c2embed.HostLen : c2embed.HostLen+4])
	if port != 5555 {
		t.Fatalf("port %d", port)
	}
	if !strings.Contains(string(out), c2embed.MagicString) {
		t.Fatal("magic lost")
	}
}

func TestPatchC2EmbedNoMagic(t *testing.T) {
	_, err := PatchC2Embed([]byte("hello"), &Config{}, "1.2.3.4", 1)
	if err != ErrNoC2Embed {
		t.Fatalf("want ErrNoC2Embed got %v", err)
	}
}
