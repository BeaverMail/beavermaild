package imap

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

func TestFormatQuota(t *testing.T) {
	t.Parallel()

	// RFC 9208 4.2.1, 5.1: one list of triplets, STORAGE in KiB (rounded up), unlimited left out.
	for _, c := range []struct {
		st   mail.QuotaStatus
		want string
	}{
		{mail.QuotaStatus{StorageUsed: 3037, StorageLimit: 1 << 20, MessagesUsed: 3, MessagesLimit: 100}, `QUOTA "" (STORAGE 3 1024 MESSAGE 3 100)`},
		{mail.QuotaStatus{StorageUsed: 2048, StorageLimit: 500}, `QUOTA "" (STORAGE 2 1)`},
		{mail.QuotaStatus{StorageUsed: 0, MessagesUsed: 7, MessagesLimit: 10}, `QUOTA "" (MESSAGE 7 10)`},
		{mail.QuotaStatus{StorageUsed: 3037, MessagesUsed: 7}, `QUOTA "" ()`},
	} {
		if got := formatQuota(c.st); got != c.want {
			t.Fatalf("format %+v: %q, want %q", c.st, got, c.want)
		}
	}
}

func TestParseQuotaRootArg(t *testing.T) {
	t.Parallel()

	root, ok := parseQuotaRootArg(`""`)
	if !ok || root != "" {
		t.Fatalf("empty root %q ok=%v", root, ok)
	}
}
