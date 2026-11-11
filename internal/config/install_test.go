package config_test

import (
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/config"
)

func TestInstallIDStable(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.InitLayout(filepath.Join(dir, "etc", "config.json"), filepath.Join(dir, "data"), "")
	if err != nil {
		t.Fatal(err)
	}
	id, err := cfg.InstallID()
	if err != nil || len(id) != 32 {
		t.Fatalf("InstallID = %q, %v", id, err)
	}
	again, err := cfg.InstallID()
	if err != nil || again != id {
		t.Fatalf("InstallID changed: %q then %q (%v)", id, again, err)
	}
	if got, want := cfg.LicensesDir(), filepath.Join(dir, "etc", "licenses"); got != want {
		t.Fatalf("LicensesDir = %q, want %q", got, want)
	}
}
