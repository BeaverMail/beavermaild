// Package config loads BeaverMail bootstrap settings from config.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultDataDir is the relative data root when not overridden.
const DefaultDataDir = "data"

// Config is the on-disk bootstrap configuration (JSON).
type Config struct {
	DataDir  string  `json:"data_dir"`
	LogLevel string  `json:"log_level"`
	Secrets  Secrets `json:"secrets"`
}

// Secrets holds generated credentials written by beaver init.
type Secrets struct {
	AuthKey string `json:"auth_key"`
}

// Default returns a new config for dataDir with info logging.
func Default(dataDir string) *Config {
	return &Config{
		DataDir:  dataDir,
		LogLevel: "info",
	}
}

// Load reads path, applies environment overrides, and validates.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.ApplyEnv()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes cfg as JSON to path (mode 0600).
func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o600)
}

// ApplyEnv overrides fields from BEAVER_DATA_DIR and BEAVER_LOG_LEVEL.
func (c *Config) ApplyEnv() {
	if v := os.Getenv("BEAVER_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("BEAVER_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
}

// Validate checks required fields and paths.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.DataDir) == "" {
		return errors.New("config: data_dir is required")
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	return nil
}

// ConfigPath returns data_dir/config.json.
func (c *Config) ConfigPath() string {
	return filepath.Join(c.DataDir, "config.json")
}

// StorePath returns the SQLite database file path.
func (c *Config) StorePath() string {
	return filepath.Join(c.DataDir, "store.sqlite")
}

// BlobDir returns the filesystem blob store root.
func (c *Config) BlobDir() string {
	return filepath.Join(c.DataDir, "blobs")
}
