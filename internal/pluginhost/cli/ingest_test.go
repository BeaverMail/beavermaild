package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beaver/plugin"
)

func TestLoadMessageRawPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "mail.eml")
	body := []byte("From: a@b.com\r\n\r\nx\r\n")
	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatal(err)
	}
	raw, cleanup, err := loadMessageRaw(plugin.BatchMessage{RawPath: src})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if string(raw) != string(body) {
		t.Fatalf("got %q", raw)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatal("source file should remain")
	}
}

func TestLoadMessageRawTempRemoved(t *testing.T) {
	t.Parallel()
	path, err := plugin.WriteTempMessage([]byte("raw"))
	if err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := loadMessageRaw(plugin.BatchMessage{RawPath: path})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("temp file should be removed")
	}
}

func TestLoadMessageRawB64(t *testing.T) {
	t.Parallel()
	raw, cleanup, err := loadMessageRaw(plugin.BatchMessage{RawB64: "aGVsbG8="})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if string(raw) != "hello" {
		t.Fatalf("got %q", raw)
	}
}
