package plugin_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beavermaild/plugin"
)

func TestIsPluginTempPath(t *testing.T) {
	t.Parallel()
	f, err := os.CreateTemp("", "beaver-plugin-msg-*.eml")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()
	defer os.Remove(path)
	if !plugin.IsPluginTempPath(path) {
		t.Fatalf("expected plugin temp path %q", path)
	}
	if plugin.IsPluginTempPath(filepath.Join(t.TempDir(), "mail.eml")) {
		t.Fatal("arbitrary temp dir file should not match")
	}
	if plugin.IsPluginTempPath("/etc/passwd") {
		t.Fatal("system path should not match")
	}
}

func TestHashFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "m.eml")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	h1, err := plugin.HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := plugin.HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("hash %q", h1)
	}
}
