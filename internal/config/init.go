// Package config loads BeaverMail bootstrap settings from config.json.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// InitLayout creates data_dir, blobs/, and config.json when missing.
func InitLayout(dataDir string) (*Config, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil, errors.New("config: data_dir is required")
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "blobs"), 0o755); err != nil {
		return nil, err
	}

	cfgPath := filepath.Join(dataDir, "config.json")
	if _, err := os.Stat(cfgPath); err == nil {
		return Load(cfgPath)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	cfg := Default(dataDir)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate auth key: %w", err)
	}
	cfg.Secrets.AuthKey = hex.EncodeToString(key)
	if err := cfg.Save(cfgPath); err != nil {
		return nil, err
	}
	return cfg, nil
}
