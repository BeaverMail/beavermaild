package app

import (
	"reflect"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/config"
	"github.com/BeaverMail/beavermaild/internal/httpapi"
)

// Only public client listeners become SRV records; loopback dev defaults and unset ones do not.
func TestMailServices(t *testing.T) {
	t.Parallel()
	cfg := config.Default(t.TempDir())
	cfg.SMTP.SubmissionTLSListen = ":465"
	cfg.SMTP.SubmissionListen = "192.0.2.10:587"
	cfg.IMAP.TLSListen = "[::1]:993" // loopback
	cfg.IMAP.Listen = ""             // default 127.0.0.1:1143
	got := mailServices(cfg)
	want := []httpapi.MailService{{Name: "_submissions._tcp", Priority: 0, Port: 465}, {Name: "_submission._tcp", Priority: 10, Port: 587}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}
