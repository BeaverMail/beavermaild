package smtp

import (
	"bufio"
	"net"
	"reflect"
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
	if !strings.HasPrefix(got, "250-mx.example.net\r\n") || !strings.HasSuffix(got, "250 AUTH PLAIN LOGIN\r\n") {
		t.Fatalf("first read %q, want the complete multi-line EHLO reply", got)
	}
}

// RFC 5321 4.1.1.1: the last EHLO line is an extension too (Postfix ends with "250 CHUNKING"), and the
// first line is the server domain, not a keyword.
func TestReadEHLOCapsLastLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("250-mx.example.org PIPELINING ready\r\n250-SIZE 1000\r\n250-AUTH plain LOGIN\r\n250-X-STARTTLS-NOT\r\n250 CHUNKING\r\nNOOP\r\n"))
	caps, err := readEHLOCaps(r)
	if err != nil {
		t.Fatal(err)
	}
	want := clientCaps{Size: true, SizeLimit: 1000, Chunking: true, Auth: []string{"PLAIN", "LOGIN"}}
	if !reflect.DeepEqual(caps, want) {
		t.Fatalf("caps %+v, want %+v", caps, want)
	}
	if rest, _ := r.ReadString('\n'); rest != "NOOP\r\n" {
		t.Fatalf("parser read past the last EHLO line, next %q", rest)
	}
}
