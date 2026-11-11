package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LicensesDir holds plugin license files (<plugin>.lic) next to config.json.
func (c *Config) LicensesDir() string {
	return filepath.Join(filepath.Dir(c.ConfigPath()), "licenses")
}

// InstallID returns this installation's id (data_dir/install-id), creating it on first use.
// It lives in the data dir so a restore from backup keeps it; a fresh install gets a new one.
func (c *Config) InstallID() (string, error) {
	path := filepath.Join(c.DataDir, "install-id")
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(b)), nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		// Lost a creation race: the other writer's id wins.
		b, err := os.ReadFile(path)
		return strings.TrimSpace(string(b)), err
	}
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(id + "\n"); err != nil {
		f.Close()
		return "", err
	}
	return id, f.Close()
}
