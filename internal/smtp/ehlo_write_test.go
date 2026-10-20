package smtp

import (
	"net"
	"strings"
	"testing"
)

// The whole EHLO reply must arrive in one read: clients that read the socket once after EHLO
// otherwise get a stale "250-..." line as the reply to AUTH ("Expected 334, got 250-...").
func TestEHLOReplySingleWrite(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &session{conn: server, hostname: "mx.example.net", dataLimits: DataLimits{}.withDefaults(), submission: true, secure: true}
	go func() { _ = s.writeEHLO(true) }()

	buf := make([]byte, 4096)
	n, err := client.Read(buf) // net.Pipe: one Read returns at most one Write
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "250-mx.example.net\r\n") || !strings.Contains(got, "250-AUTH PLAIN LOGIN\r\n") || !strings.HasSuffix(got, "250 2.0.0 Ok\r\n") {
		t.Fatalf("first read %q, want the complete multi-line EHLO reply", got)
	}
}
