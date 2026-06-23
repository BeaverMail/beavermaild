// Package config loads BeaverMail bootstrap settings from config.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultDataDir is the relative data root when not overridden.
const DefaultDataDir = "data"

// Config is the on-disk bootstrap configuration (JSON).
type Config struct {
	DataDir  string     `json:"data_dir"`
	LogLevel string     `json:"log_level"`
	Secrets  Secrets    `json:"secrets"`
	SMTP     SMTPConfig  `json:"smtp"`
	IMAP     IMAPConfig  `json:"imap"`
	Queue    QueueConfig `json:"queue"`
}

// SMTPConfig holds inbound SMTP listener settings.
type SMTPConfig struct {
	Listen string `json:"listen"`
	Relay  string `json:"relay"`
}

// IMAPConfig holds IMAP listener settings.
type IMAPConfig struct {
	Listen string `json:"listen"`
}

// QueueConfig holds outbound queue schedule defaults.
type QueueConfig struct {
	RetryIntervals []string `json:"retry_intervals"`
	MaxLifetime    string   `json:"max_lifetime"`
	RunDelay       string   `json:"run_delay"`
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
	if v := os.Getenv("BEAVER_SMTP_LISTEN"); v != "" {
		c.SMTP.Listen = v
	}
	if v := os.Getenv("BEAVER_SMTP_RELAY"); v != "" {
		c.SMTP.Relay = v
	}
	if v := os.Getenv("BEAVER_IMAP_LISTEN"); v != "" {
		c.IMAP.Listen = v
	}
	if v := os.Getenv("BEAVER_QUEUE_RUN_DELAY"); v != "" {
		c.Queue.RunDelay = v
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
	if c.SMTP.Listen == "" {
		c.SMTP.Listen = "127.0.0.1:1025"
	}
	if c.IMAP.Listen == "" {
		c.IMAP.Listen = "127.0.0.1:1143"
	}
	if c.Queue.MaxLifetime == "" {
		c.Queue.MaxLifetime = "3d"
	}
	if c.Queue.RunDelay == "" {
		c.Queue.RunDelay = "1s"
	}
	return nil
}

// SMTPListen returns the inbound SMTP bind address.
func (c *Config) SMTPListen() string {
	if c.SMTP.Listen != "" {
		return c.SMTP.Listen
	}
	return "127.0.0.1:1025"
}

// SMTPRelay returns the outbound SMTP relay (may be empty).
func (c *Config) SMTPRelay() string {
	return strings.TrimSpace(c.SMTP.Relay)
}

// IMAPListen returns the IMAP bind address.
func (c *Config) IMAPListen() string {
	if c.IMAP.Listen != "" {
		return c.IMAP.Listen
	}
	return "127.0.0.1:1143"
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

// QueueTimings holds parsed outbound queue schedule values.
type QueueTimings struct {
	RetryIntervals []time.Duration
	MaxLifetime    time.Duration
	RunDelay       time.Duration
}

// QueueTimings parses queue schedule settings.
func (c *Config) QueueTimings() (QueueTimings, error) {
	intervals := c.Queue.RetryIntervals
	if len(intervals) == 0 {
		intervals = []string{"2m", "5m", "10m", "15m", "30m", "1h", "2h", "24h", "3d"}
	}
	parsed := make([]time.Duration, len(intervals))
	for i, s := range intervals {
		d, err := ParseDuration(s)
		if err != nil {
			return QueueTimings{}, err
		}
		parsed[i] = d
	}
	life, err := ParseDuration(c.Queue.MaxLifetime)
	if err != nil {
		return QueueTimings{}, err
	}
	run, err := ParseDuration(c.Queue.RunDelay)
	if err != nil {
		return QueueTimings{}, err
	}
	return QueueTimings{
		RetryIntervals: parsed,
		MaxLifetime:    life,
		RunDelay:       run,
	}, nil
}
