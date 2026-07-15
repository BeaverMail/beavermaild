package smtp_test

import (
	"context"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

func TestGreylistPersistsRetryWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := smtp.GreylistConfig{Enabled: true, MinDelay: 20 * time.Millisecond, MaxAge: time.Hour}
	first := smtp.NewGreylist(store, cfg)
	ok, err := first.Allow(ctx, "192.0.2.10", "sender@example.com", "alice@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("first attempt must be greylisted")
	}

	time.Sleep(30 * time.Millisecond)
	reopened := smtp.NewGreylist(store, cfg)
	ok, err = reopened.Allow(ctx, "192.0.2.10", "sender@example.com", "alice@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("retry after minimum delay must be accepted")
	}
}

func TestGreylistDisabledAllowsImmediately(t *testing.T) {
	var gate *smtp.Greylist
	ok, err := gate.Allow(context.Background(), "192.0.2.10", "a@b", "c@d")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
