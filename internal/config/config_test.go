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

func TestACMECacheDirDefault(t *testing.T) {
	t.Parallel()
	cfg := config.Default(t.TempDir())
	cfg.TLS.ACMEHosts = []string{"mail.example.com"}
	want := filepath.Join(cfg.DataDir, "tls", "acme")
	if got := cfg.ACMECacheDir(); got != want {
		t.Fatalf("cache %q want %q", got, want)
	}
}

func TestSMTPRelayEnv(t *testing.T) {
	cfg := config.Default(t.TempDir())
	t.Setenv("BEAVER_SMTP_RELAY", "relay.test:587")
	t.Setenv("BEAVER_SMTP_RELAY_USER", "u")
	t.Setenv("BEAVER_SMTP_RELAY_PASSWORD", "p")
	t.Setenv("BEAVER_SMTP_RELAY_STARTTLS", "true")
	cfg.ApplyEnv()
	if cfg.SMTPRelay() != "relay.test:587" {
		t.Fatalf("relay %q", cfg.SMTPRelay())
	}
	if cfg.SMTPRelayUser() != "u" || cfg.SMTPRelayPassword() != "p" || !cfg.SMTPRelayStartTLS() {
		t.Fatalf("relay opts user=%q pass=%q starttls=%v", cfg.SMTPRelayUser(), cfg.SMTPRelayPassword(), cfg.SMTPRelayStartTLS())
	}
}
