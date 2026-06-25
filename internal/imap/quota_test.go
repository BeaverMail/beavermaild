package imap

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
)

func TestFormatQuota(t *testing.T) {
	t.Parallel()

	got := formatQuota(mail.QuotaStatus{
		Root:          mail.QuotaRoot,
		StorageUsed:   128,
		StorageLimit:  4096,
		MessagesUsed:  3,
		MessagesLimit: 100,
	})
	if got != `QUOTA "" (STORAGE 128 4096) (MESSAGE 3 100)` {
		t.Fatalf("format %q", got)
	}
}

func TestParseQuotaRootArg(t *testing.T) {
	t.Parallel()

	root, ok := parseQuotaRootArg(`""`)
	if !ok || root != "" {
		t.Fatalf("empty root %q ok=%v", root, ok)
	}
}
