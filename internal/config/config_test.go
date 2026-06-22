package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beaver/internal/config"
)

func TestInitLayoutCreatesConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg, err := config.InitLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != dir {
		t.Fatalf("data_dir %q", cfg.DataDir)
	}
	if cfg.Secrets.AuthKey == "" {
		t.Fatal("missing auth key")
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "blobs")); err != nil {
		t.Fatal(err)
	}
}

func TestLoadApplyEnv(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.InitLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BEAVER_LOG_LEVEL", "debug")
	cfg.ApplyEnv()
	if cfg.LogLevel != "debug" {
		t.Fatalf("level %q", cfg.LogLevel)
	}

	loaded, err := config.Load(cfg.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.StorePath() != filepath.Join(dir, "store.sqlite") {
		t.Fatalf("store path %q", loaded.StorePath())
	}
}
