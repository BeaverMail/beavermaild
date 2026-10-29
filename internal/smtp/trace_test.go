package smtp

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
)

func TestReceivedField(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	now := time.Date(2026, 10, 20, 12, 0, 2, 0, time.FixedZone("CEST", 2*3600))

	s := &session{conn: server, hostname: "mx.example.net", heloDomain: "web01.example.org", iprevPTR: "web01.example.org.",
		pipelining: true, rcpt: []rcptTarget{{address: "info@example.net"}}, filterTxnID: "abc123"}
	got := s.receivedField(now)
	want := "from web01.example.org (web01.example.org [pipe])\r\n\tby mx.example.net (BeaverMail) with ESMTP id abc123\r\n\tfor <info@example.net>; Tue, 20 Oct 2026 12:00:02 +0200"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}

	// TLS + AUTH -> ESMTPSA (RFC 3848); HELO -> plain SMTP; several recipients -> no "for".
	s.secure, s.principal = true, directory.Principal{AccountID: 7}
	s.rcpt = append(s.rcpt, rcptTarget{address: "b@example.net"})
	if got := s.receivedField(now); !strings.Contains(got, "with ESMTPSA id") || strings.Contains(got, "for <") {
		t.Fatalf("submission hop %q", got)
	}
	s.pipelining = false
	if got := s.receivedField(now); !strings.Contains(got, "with SMTP id") {
		t.Fatalf("HELO hop %q", got)
	}
}

// The HELO argument is chosen by the client: it must not inject header lines or comments.
func TestTraceTokenSanitizes(t *testing.T) {
	for in, want := range map[string]string{
		"evil\r\nX-Injected: 1": "evil",
		"host (fake) [1.2.3.4]": "host",
		"a(b);c":                "abc",
		"":                      "unknown",
		"\x01\x02":              "unknown",
	} {
		if got := traceToken(in); got != want {
			t.Fatalf("traceToken(%q) = %q want %q", in, got, want)
		}
	}
}

func TestCountReceivedHeaderOnly(t *testing.T) {
	raw := []byte("Received: from a\r\n\tby b; date\r\nreceived: from c\r\nSubject: x\r\n\r\nReceived: in body\r\n")
	if n := countReceived(raw); n != 2 {
		t.Fatalf("count %d want 2 (folded lines and body ignored)", n)
	}
}
