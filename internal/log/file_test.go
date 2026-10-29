package log_test

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/log"
)

func TestRotatingFileAndHistory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "beaver.log")
	rf, err := log.OpenFile(path, log.FileOptions{MaxBytes: 4 << 10, Keep: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rf.Close() })

	var discard bytes.Buffer
	base := slog.New(slog.NewTextHandler(&discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger := log.WithFile(base, rf)

	for i := 0; i < 80; i++ {
		logger.Info("line", "i", i)
	}
	_ = rf.Close()

	entries, err := log.ReadHistory(path, 3, log.Query{LevelSet: true, MinLevel: slog.LevelDebug, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 20 {
		t.Fatalf("want history got %d", len(entries))
	}
	before := entries[len(entries)/2].Time
	older, err := log.ReadHistory(path, 3, log.Query{
		LevelSet: true,
		MinLevel: slog.LevelDebug,
		Limit:    20,
		Before:   before,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(older) == 0 {
		t.Fatal("expected older page")
	}
	for _, e := range older {
		if !e.Time.Before(before) {
			t.Fatalf("before filter failed: %v >= %v", e.Time, before)
		}
	}
}

func TestWithFileRedactsSecrets(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "beaver.log")
	rf, err := log.OpenFile(path, log.FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rf.Close() })
	var discard bytes.Buffer
	logger := log.WithFile(slog.New(slog.NewTextHandler(&discard, nil)), rf)
	logger.Info("login", "email", "a@b.test", "password", "secret")
	_ = rf.Close()

	entries, err := log.ReadHistory(path, 1, log.Query{LevelSet: true, MinLevel: slog.LevelDebug, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Attrs["password"] != "[redacted]" {
		t.Fatalf("%+v", entries)
	}
}
