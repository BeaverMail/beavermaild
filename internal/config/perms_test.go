//go:build unix

package config_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/BeaverMail/beaver/internal/config"
)

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// init on a pre-created, world-readable data dir (the old install steps) must close it, and,
// under beaver's own 077 umask, still leave the config dir it creates traversable.
func TestInitLayoutDataDirOwnerOnly(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0o077))
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dataDir, 0o755); err != nil { // the test umask may have masked it
		t.Fatal(err)
	}
	cfg, err := config.InitLayout(filepath.Join(root, "etc", "config.json"), dataDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if p := perm(t, cfg.DataDir); p != 0o700 {
		t.Fatalf("data dir %o, want 700", p)
	}
	if p := perm(t, cfg.ConfigPath()); p != 0o600 {
		t.Fatalf("config %o, want 600", p)
	}
	if p := perm(t, filepath.Dir(cfg.ConfigPath())); p != 0o755 {
		t.Fatalf("config dir %o, want 755 (service user must reach config.json)", p)
	}
}

func TestSecureDataDir(t *testing.T) {
	cfg, err := config.InitLayout(filepath.Join(t.TempDir(), "config.json"), filepath.Join(t.TempDir(), "data"), "")
	if err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{cfg.DataDir: 0o755, cfg.StorePath(): 0o644, cfg.StorePath() + "-wal": 0o640} {
		if err := os.WriteFile(path, nil, 0o600); err != nil && path != cfg.DataDir {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	changed, err := cfg.SecureDataDir()
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 3 {
		t.Fatalf("changed %v, want data dir, store and wal", changed)
	}
	want := map[string]os.FileMode{cfg.DataDir: 0o700, cfg.StorePath(): 0o600, cfg.StorePath() + "-wal": 0o600}
	for path, mode := range want {
		if p := perm(t, path); p != mode {
			t.Errorf("%s: %o, want %o", path, p, mode)
		}
	}
	if changed, _ := cfg.SecureDataDir(); len(changed) != 0 {
		t.Fatalf("second run changed %v", changed)
	}
}

// A setgid config dir (as the package creates it) makes init write a group-readable config.
func TestInitLayoutSetgidConfigDir(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0o077))
	etc := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(etc, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(etc, os.ModeSetgid|0o750); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.InitLayout(filepath.Join(etc, "config.json"), filepath.Join(t.TempDir(), "data"), "")
	if err != nil {
		t.Fatal(err)
	}
	if p := perm(t, cfg.ConfigPath()); p != 0o640 {
		t.Fatalf("config %o, want 640 in a setgid dir", p)
	}
	if cfg.ConfigFileShared() {
		t.Fatal("group read must not count as shared")
	}
}
