package payload

import "testing"

func TestParseListenerHostPort(t *testing.T) {
	h, p, err := ParseListenerHostPort("192.168.1.2:4444")
	if err != nil || h != "192.168.1.2" || p != 4444 {
		t.Fatalf("host:port got %q %d %v", h, p, err)
	}
	h, p, err = ParseListenerHostPort("http://192.168.120.128:4444")
	if err != nil || h != "192.168.120.128" || p != 4444 {
		t.Fatalf("http URL got %q %d %v", h, p, err)
	}
}

func TestDialHostPortForAgent(t *testing.T) {
	h, p, err := DialHostPortForAgent("192.168.1.2:4444", "0.0.0.0:1")
	if err != nil || h != "192.168.1.2" || p != 4444 {
		t.Fatalf("full external got %q %d %v", h, p, err)
	}
	h, p, err = DialHostPortForAgent("127.0.0.1", "0.0.0.0:4444")
	if err != nil || h != "127.0.0.1" || p != 4444 {
		t.Fatalf("bare IP + listen got %q %d %v", h, p, err)
	}
	_, _, err = DialHostPortForAgent("127.0.0.1", "")
	if err == nil {
		t.Fatal("want error when bare IP and no listen")
	}
}
