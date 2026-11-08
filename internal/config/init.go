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

// InitLayout writes a new config at configPath and creates data_dir and blobs/.
// An existing config is loaded as is (dataDir and hostname are then ignored).
// hostname marks a public MX: ACME for it, admin UI on :443 (:80 for challenges and redirects)
// and the standard public mail ports. Without it everything stays on loopback dev ports
// (reach the admin UI via SSH tunnel or a reverse proxy).
func InitLayout(configPath, dataDir, hostname string) (*Config, error) {
	if _, err := os.Stat(configPath); err == nil {
		cfg, err := Load(configPath)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(cfg.BlobDir(), 0o700); err != nil {
			return nil, err
		}
		_, err = cfg.SecureDataDir()
		return cfg, err
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil, errors.New("config: data_dir is required")
	}
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if strings.ContainsAny(hostname, ":/ ") {
		return nil, fmt.Errorf("config: hostname %q must be a bare DNS name", hostname)
	}

	cfg := Default(dataDir)
	cfg.path = configPath
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate auth key: %w", err)
	}
	cfg.Secrets.AuthKey = hex.EncodeToString(key)
	cfg.HTTP.Enabled = true
	cfg.HTTP.Listen = "127.0.0.1:8080"
	if hostname != "" {
		cfg.TLS.ACMEHosts = []string{hostname}
		cfg.SMTP.Hostname = hostname
		cfg.HTTP.Listen = ":443"
		cfg.HTTP.PlainListen = ":80"
		cfg.SMTP.Listen = ":25"
		cfg.SMTP.SubmissionListen = ":587"
		cfg.SMTP.SubmissionTLSListen = ":465"
		cfg.IMAP.Listen = ":143"
		cfg.IMAP.TLSListen = ":993"
	}

	if err := os.MkdirAll(cfg.BlobDir(), 0o700); err != nil {
		return nil, err
	}
	// MkdirAll keeps the mode of a data dir that already exists; tighten it explicitly.
	if _, err := cfg.SecureDataDir(); err != nil {
		return nil, err
	}
	// The config dir must stay traversable for the service user under our 077 umask;
	// config.json itself is 0600, so only the dir is opened up, and only when init creates it.
	configDir := filepath.Dir(configPath)
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			return nil, err
		}
		if err := os.Chmod(configDir, 0o755); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := cfg.Save(configPath); err != nil {
		return nil, err
	}
	// A setgid config dir (the package makes /etc/beavermail root:beavermail 2750) hands its
	// group to new files: let that group, the service, read the config.
	if st, err := os.Stat(configDir); err == nil && st.Mode()&os.ModeSetgid != 0 {
		if err := os.Chmod(configPath, 0o640); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}
