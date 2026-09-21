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

	"github.com/BeaverMail/beaver/internal/dkimout"
	"github.com/BeaverMail/beaver/internal/mtasts"
	"github.com/BeaverMail/beaver/internal/security"
)

// DefaultDataDir is the relative data root when not overridden.
const DefaultDataDir = "data"

// SystemConfigPath is the default bootstrap config on installed systems (FHS).
const SystemConfigPath = "/etc/beavermail/config.json"

// DefaultConfigPath returns BEAVER_CONFIG when set, otherwise SystemConfigPath.
func DefaultConfigPath() string {
	if v := os.Getenv("BEAVER_CONFIG"); v != "" {
		return v
	}
	return SystemConfigPath
}

// Config is the on-disk bootstrap configuration (JSON).
type Config struct {
	DataDir  string         `json:"data_dir"`
	LogLevel string         `json:"log_level"`
	Store    StoreConfig    `json:"store"`
	Secrets  Secrets        `json:"secrets"`
	TLS      TLSConfig      `json:"tls"`
	HTTP     HTTPConfig     `json:"http"`
	SMTP     SMTPConfig     `json:"smtp"`
	IMAP     IMAPConfig     `json:"imap"`
	Auth     AuthConfig     `json:"auth"`
	Queue    QueueConfig    `json:"queue"`
	Quota    QuotaConfig    `json:"quota"`
	Plugins  PluginsConfig  `json:"plugins"`
	MailAuth MailAuthConfig `json:"mail_auth"`
}

// HTTPConfig enables the in-process admin/API listener (off by default).
type HTTPConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"` // e.g. 127.0.0.1:8080; non-loopback requires TLS certs
}

// StoreDriverSQLite is the default embedded KV backend.
const StoreDriverSQLite = "sqlite"

// StoreDriverMySQL selects MySQL or MariaDB via the MySQL wire protocol.
const StoreDriverMySQL = "mysql"

// StoreConfig selects the KV backend (sqlite default; mysql for MariaDB/MySQL).
type StoreConfig struct {
	// Driver is sqlite (default) or mysql (MariaDB/MySQL).
	Driver string `json:"driver"`
	// DSN is required for mysql (go-sql-driver format). Ignored for sqlite.
	DSN string `json:"dsn"`
}

// MailAuthConfig holds inbound SPF/DKIM/DMARC verification settings.
type MailAuthConfig struct {
	Enabled      bool           `json:"enabled"`
	DNSTimeoutMs int            `json:"dns_timeout_ms"`
	SPF          MailAuthToggle `json:"spf"`
	DKIM         MailAuthToggle `json:"dkim"`
	DMARC        MailAuthToggle `json:"dmarc"`
	ARC          MailAuthToggle `json:"arc"`
}

// MailAuthToggle enables one mail-auth check family.
type MailAuthToggle struct {
	Enabled bool `json:"enabled"`
}

// PluginsConfig holds plugin host settings.
type PluginsConfig struct {
	SMTP PluginsSMTPConfig `json:"smtp"`
}

// PluginsSMTPConfig holds SMTP filter plugin settings for beaver serve.
type PluginsSMTPConfig struct {
	FilterTimeoutMs  int    `json:"filter_timeout_ms"`
	TimeoutPolicy    string `json:"timeout_policy"` // accept (fail-open) or tempfail
	SocketDir        string `json:"socket_dir"`
	RestartBackoffMs int    `json:"restart_backoff_ms"`
}

// TLSConfig holds PEM paths or ACME hostnames for server TLS.
type TLSConfig struct {
	CertFile     string   `json:"cert_file"`
	KeyFile      string   `json:"key_file"`
	MinVersion   string   `json:"min_version"`
	Required     bool     `json:"required"`
	ACMEHosts    []string `json:"acme_hosts"`
	ACMECacheDir string   `json:"acme_cache_dir"`
}

// SMTPConfig holds inbound SMTP listener settings.
type SMTPConfig struct {
	Listen                  string                    `json:"listen"`
	SubmissionListen        string                    `json:"submission_listen"`
	SubmissionTLSListen     string                    `json:"submission_tls_listen"`
	Relay                   string                    `json:"relay"`
	RelayStartTLS           bool                      `json:"relay_starttls"`
	RelayUser               string                    `json:"relay_user"`
	RelayPassword           string                    `json:"relay_password"`
	OutboundTLSInsecureSkip bool                      `json:"outbound_tls_insecure_skip_verify"` // dev/self-signed relay or MX; default verify
	MTASTS                  MTASTSConfig              `json:"mta_sts"`
	DKIMSign                DKIMSignConfig            `json:"dkim_sign"`
	Greylist                GreylistConfig            `json:"greylist"`
	ASNLookup               ASNLookupConfig           `json:"asn_lookup"`
	MaxMessageBytes         int                       `json:"max_message_bytes"`
	VRFYEnabled             bool                      `json:"vrfy_enabled"` // off by default (RFC 5321: user enumeration risk)
	SubmissionRateLimit     SubmissionRateLimitConfig `json:"submission_rate_limit"`
}

// SubmissionRateLimitConfig limits accepted messages per authenticated principal.
type SubmissionRateLimitConfig struct {
	Disable     bool   `json:"disable"`      // default off = rate limit enabled
	MaxMessages int    `json:"max_messages"` // default 200
	Window      string `json:"window"`       // default 1h
}

// GreylistConfig controls persistent inbound SMTP greylisting.
type GreylistConfig struct {
	Enabled     bool `json:"enabled"`
	MinDelaySec int  `json:"min_delay_sec"`
	MaxAgeSec   int  `json:"max_age_sec"`
}

// ASNLookupConfig enables optional Team Cymru-style ASN/country DNS at SMTP connect.
type ASNLookupConfig struct {
	Enabled         bool   `json:"enabled"` // default false
	TimeoutMs       int    `json:"timeout_ms"`
	ZoneIPv4        string `json:"zone_ipv4"`
	ZoneIPv6        string `json:"zone_ipv6"`
	CacheTTLSec     int    `json:"cache_ttl_sec"`
	CacheTTLMissSec int    `json:"cache_ttl_miss_sec"`
	CacheMaxEntries int    `json:"cache_max_entries"`
}

// MTASTSConfig controls outbound MTA-STS policy lookup (RFC 8461).
type MTASTSConfig struct {
	Disable bool `json:"disable"` // default off = MTA-STS enabled for direct MX delivery
}

// DKIMSignConfig enables outbound DKIM signing for remote queue delivery.
type DKIMSignConfig struct {
	Selector       string `json:"selector"`
	Domain         string `json:"domain"`           // optional SDID override
	PrivateKeyPath string `json:"private_key_path"` // PEM under data_dir or absolute
}

// IMAPConfig holds IMAP listener settings.
type IMAPConfig struct {
	Listen    string `json:"listen"`
	TLSListen string `json:"tls_listen"`
}

// AuthConfig holds authentication security settings.
type AuthConfig struct {
	RateLimit AuthRateLimitConfig `json:"rate_limit"`
}

// AuthRateLimitConfig limits failed LOGIN/AUTH attempts per client IP.
type AuthRateLimitConfig struct {
	Disable     bool   `json:"disable"`      // default off = rate limit enabled
	MaxAttempts int    `json:"max_attempts"` // default 10
	Window      string `json:"window"`       // default 15m
}

// QueueConfig holds outbound queue schedule defaults.
type QueueConfig struct {
	RetryIntervals []string `json:"retry_intervals"`
	MaxLifetime    string   `json:"max_lifetime"`
	RunDelay       string   `json:"run_delay"`
}

// QuotaConfig holds default per-account storage limits (0 = unlimited).
type QuotaConfig struct {
	DefaultStorageBytes uint64 `json:"default_storage_bytes"`
	DefaultMessages     uint32 `json:"default_messages"`
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
	if v := os.Getenv("BEAVER_SMTP_RELAY_USER"); v != "" {
		c.SMTP.RelayUser = v
	}
	if v := os.Getenv("BEAVER_SMTP_RELAY_PASSWORD"); v != "" {
		c.SMTP.RelayPassword = v
	}
	if v := os.Getenv("BEAVER_SMTP_RELAY_STARTTLS"); v == "1" || strings.EqualFold(v, "true") {
		c.SMTP.RelayStartTLS = true
	}
	if v := os.Getenv("BEAVER_SMTP_OUTBOUND_TLS_INSECURE"); v == "1" || strings.EqualFold(v, "true") {
		c.SMTP.OutboundTLSInsecureSkip = true
	}
	if v := os.Getenv("BEAVER_SMTP_VRFY_ENABLED"); v == "1" || strings.EqualFold(v, "true") {
		c.SMTP.VRFYEnabled = true
	}
	if v := os.Getenv("BEAVER_IMAP_LISTEN"); v != "" {
		c.IMAP.Listen = v
	}
	if v := os.Getenv("BEAVER_AUTH_RATE_LIMIT_DISABLE"); v == "1" || strings.EqualFold(v, "true") {
		c.Auth.RateLimit.Disable = true
	}
	if v := os.Getenv("BEAVER_SMTP_SUBMISSION_RATE_LIMIT_DISABLE"); v == "1" || strings.EqualFold(v, "true") {
		c.SMTP.SubmissionRateLimit.Disable = true
	}
	if v := os.Getenv("BEAVER_SMTP_MTA_STS_DISABLE"); v == "1" || strings.EqualFold(v, "true") {
		c.SMTP.MTASTS.Disable = true
	}
	if v := os.Getenv("BEAVER_QUEUE_RUN_DELAY"); v != "" {
		c.Queue.RunDelay = v
	}
	if v := os.Getenv("BEAVER_STORE_DRIVER"); v != "" {
		c.Store.Driver = v
	}
	if v := os.Getenv("BEAVER_STORE_DSN"); v != "" {
		c.Store.DSN = v
	}
	if v := os.Getenv("BEAVER_HTTP_ENABLED"); v == "1" || strings.EqualFold(v, "true") {
		c.HTTP.Enabled = true
	}
	if v := os.Getenv("BEAVER_HTTP_LISTEN"); v != "" {
		c.HTTP.Listen = v
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
	if err := c.validateStore(); err != nil {
		return err
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
	if c.Plugins.SMTP.FilterTimeoutMs <= 0 {
		c.Plugins.SMTP.FilterTimeoutMs = 10000
	}
	if c.Plugins.SMTP.TimeoutPolicy == "" {
		c.Plugins.SMTP.TimeoutPolicy = "accept"
	}
	if c.Plugins.SMTP.RestartBackoffMs <= 0 {
		c.Plugins.SMTP.RestartBackoffMs = 1000
	}
	switch c.Plugins.SMTP.TimeoutPolicy {
	case "accept", "tempfail":
	default:
		return fmt.Errorf("config: plugins.smtp.timeout_policy must be accept or tempfail")
	}
	c.normalizeMailAuth()
	if err := c.validateHTTP(); err != nil {
		return err
	}
	return nil
}

// validateHTTP checks listen/auth_key when the HTTP API is enabled.
func (c *Config) validateHTTP() error {
	if !c.HTTP.Enabled {
		return nil
	}
	if strings.TrimSpace(c.HTTP.Listen) == "" {
		c.HTTP.Listen = "127.0.0.1:8080"
	}
	if strings.TrimSpace(c.Secrets.AuthKey) == "" {
		return errors.New("config: secrets.auth_key is required when http.enabled")
	}
	return nil
}

// normalizeMailAuth enables SPF/DKIM/DMARC/ARC when mail_auth.enabled and no sub-toggle is set.
func (c *Config) normalizeMailAuth() {
	if !c.MailAuth.Enabled {
		return
	}
	if !c.MailAuth.SPF.Enabled && !c.MailAuth.DKIM.Enabled && !c.MailAuth.DMARC.Enabled && !c.MailAuth.ARC.Enabled {
		c.MailAuth.SPF.Enabled = true
		c.MailAuth.DKIM.Enabled = true
		c.MailAuth.DMARC.Enabled = true
		c.MailAuth.ARC.Enabled = true
	}
}

// PluginsSMTPSocketDir returns the Unix socket directory for SMTP filter plugins.
func (c *Config) PluginsSMTPSocketDir() string {
	dir := strings.TrimSpace(c.Plugins.SMTP.SocketDir)
	if dir == "" {
		return filepath.Join(c.DataDir, "run", "plugins")
	}
	if !filepath.IsAbs(dir) {
		return filepath.Join(c.DataDir, dir)
	}
	return dir
}

// PluginsSMTPFilterTimeout returns the default filter request timeout.
func (c *Config) PluginsSMTPFilterTimeout() time.Duration {
	ms := c.Plugins.SMTP.FilterTimeoutMs
	if ms <= 0 {
		ms = 10000
	}
	return time.Duration(ms) * time.Millisecond
}

// PluginsSMTPTimeoutFailOpen reports whether plugin timeouts accept mail (fail-open).
func (c *Config) PluginsSMTPTimeoutFailOpen() bool {
	return c.Plugins.SMTP.TimeoutPolicy != "tempfail"
}

// PluginsSMTPRestartBackoff returns the delay between daemon plugin respawn attempts.
func (c *Config) PluginsSMTPRestartBackoff() time.Duration {
	ms := c.Plugins.SMTP.RestartBackoffMs
	if ms <= 0 {
		ms = 1000
	}
	return time.Duration(ms) * time.Millisecond
}

// MailAuthDNSTimeout returns the DNS timeout for SPF/DKIM/DMARC lookups.
func (c *Config) MailAuthDNSTimeout() time.Duration {
	ms := c.MailAuth.DNSTimeoutMs
	if ms <= 0 {
		ms = 5000
	}
	return time.Duration(ms) * time.Millisecond
}
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

// SMTPRelayUser returns relay AUTH username (may be empty).
func (c *Config) SMTPRelayUser() string {
	return strings.TrimSpace(c.SMTP.RelayUser)
}

// SMTPRelayPassword returns relay AUTH password (may be empty).
func (c *Config) SMTPRelayPassword() string {
	return c.SMTP.RelayPassword
}

// SMTPRelayStartTLS reports whether outbound relay uses STARTTLS when offered.
func (c *Config) SMTPRelayStartTLS() bool {
	return c.SMTP.RelayStartTLS
}

// SMTPOutboundTLSInsecureSkip reports whether outbound relay/MX skips TLS cert verify.
func (c *Config) SMTPOutboundTLSInsecureSkip() bool {
	return c.SMTP.OutboundTLSInsecureSkip
}

// SMTPMaxMessageBytes returns the inbound DATA size cap (0 lets smtp use its default).
func (c *Config) SMTPMaxMessageBytes() int {
	return c.SMTP.MaxMessageBytes
}

// SMTPVRFYEnabled reports whether VRFY is advertised and honored on SMTP listeners.
func (c *Config) SMTPVRFYEnabled() bool {
	return c.SMTP.VRFYEnabled
}

// SMTPGreylist returns normalized greylist runtime settings.
func (c *Config) SMTPGreylist() (enabled bool, minDelay, maxAge time.Duration) {
	if !c.SMTP.Greylist.Enabled {
		return false, 0, 0
	}
	minDelay = time.Duration(c.SMTP.Greylist.MinDelaySec) * time.Second
	maxAge = time.Duration(c.SMTP.Greylist.MaxAgeSec) * time.Second
	if minDelay <= 0 {
		minDelay = 5 * time.Minute
	}
	if maxAge <= minDelay {
		maxAge = 36 * time.Hour
	}
	return true, minDelay, maxAge
}

// SMTPASNLookup returns runtime ASN lookup settings (disabled by default).
func (c *Config) SMTPASNLookup() (enabled bool, timeout, cacheTTL, cacheMissTTL time.Duration, zoneV4, zoneV6 string, cacheMax int) {
	if !c.SMTP.ASNLookup.Enabled {
		return false, 0, 0, 0, "", "", 0
	}
	timeout = time.Duration(c.SMTP.ASNLookup.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	cacheTTL = time.Duration(c.SMTP.ASNLookup.CacheTTLSec) * time.Second
	cacheMissTTL = time.Duration(c.SMTP.ASNLookup.CacheTTLMissSec) * time.Second
	zoneV4 = strings.TrimSpace(c.SMTP.ASNLookup.ZoneIPv4)
	zoneV6 = strings.TrimSpace(c.SMTP.ASNLookup.ZoneIPv6)
	cacheMax = c.SMTP.ASNLookup.CacheMaxEntries
	return true, timeout, cacheTTL, cacheMissTTL, zoneV4, zoneV6, cacheMax
}

// IMAPListen returns the plain IMAP bind address.
func (c *Config) IMAPListen() string {
	if c.IMAP.Listen != "" {
		return c.IMAP.Listen
	}
	return "127.0.0.1:1143"
}

// IMAPTLSListen returns the implicit-TLS IMAP bind address (empty if disabled).
func (c *Config) IMAPTLSListen() string {
	return strings.TrimSpace(c.IMAP.TLSListen)
}

// SMTPSubmissionTLSListen returns the implicit-TLS submission bind address (may be empty).
func (c *Config) SMTPSubmissionTLSListen() string {
	return strings.TrimSpace(c.SMTP.SubmissionTLSListen)
}

// HTTPEnabled reports whether the admin/API HTTP listener should start.
func (c *Config) HTTPEnabled() bool {
	return c != nil && c.HTTP.Enabled
}

// HTTPListen returns the HTTP API bind address (default loopback when enabled).
func (c *Config) HTTPListen() string {
	if c == nil {
		return ""
	}
	if listen := strings.TrimSpace(c.HTTP.Listen); listen != "" {
		return listen
	}
	if c.HTTP.Enabled {
		return "127.0.0.1:8080"
	}
	return ""
}

// ACMEHosts returns trimmed ACME hostnames (empty if ACME disabled).
func (c *Config) ACMEHosts() []string {
	var out []string
	for _, h := range c.TLS.ACMEHosts {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

// ACMECacheDir returns the directory for autocert certificate cache.
func (c *Config) ACMECacheDir() string {
	dir := strings.TrimSpace(c.TLS.ACMECacheDir)
	if dir == "" {
		return filepath.Join(c.DataDir, "tls", "acme")
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(c.DataDir, dir)
	}
	return dir
}

// SMTPSubmissionListen returns the submission SMTP bind address (may be empty).
func (c *Config) SMTPSubmissionListen() string {
	return strings.TrimSpace(c.SMTP.SubmissionListen)
}

// ConfigPath returns data_dir/config.json.
func (c *Config) ConfigPath() string {
	return filepath.Join(c.DataDir, "config.json")
}

// StoreDriver returns the normalized KV driver name (default sqlite).
func (c *Config) StoreDriver() string {
	d := strings.ToLower(strings.TrimSpace(c.Store.Driver))
	if d == "" {
		return StoreDriverSQLite
	}
	return d
}

// StoreDSN returns the MySQL/MariaDB DSN when configured.
func (c *Config) StoreDSN() string {
	return strings.TrimSpace(c.Store.DSN)
}

// StorePath returns the SQLite database file path.
func (c *Config) StorePath() string {
	return filepath.Join(c.DataDir, "store.sqlite")
}

// validateStore checks store.driver / store.dsn consistency.
func (c *Config) validateStore() error {
	switch c.StoreDriver() {
	case StoreDriverSQLite:
		return nil
	case StoreDriverMySQL:
		if c.StoreDSN() == "" {
			return errors.New("config: store.dsn is required when store.driver is mysql")
		}
		return nil
	default:
		return fmt.Errorf("config: unknown store.driver %q (want sqlite or mysql)", c.Store.Driver)
	}
}

// BlobDir returns the filesystem blob store root.
func (c *Config) BlobDir() string {
	return filepath.Join(c.DataDir, "blobs")
}

// TLSPair returns absolute cert and key paths when TLS is configured.
func (c *Config) TLSPair() (certFile, keyFile string, ok bool) {
	certFile = strings.TrimSpace(c.TLS.CertFile)
	keyFile = strings.TrimSpace(c.TLS.KeyFile)
	if certFile == "" || keyFile == "" {
		return "", "", false
	}
	if !filepath.IsAbs(certFile) {
		certFile = filepath.Join(c.DataDir, certFile)
	}
	if !filepath.IsAbs(keyFile) {
		keyFile = filepath.Join(c.DataDir, keyFile)
	}
	return certFile, keyFile, true
}

// TLSRequired reports whether plain-text auth must be rejected.
func (c *Config) TLSRequired() bool {
	return c.TLS.Required
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

// NewAuthGate builds the process-wide auth rate limit gate from config.
func (c *Config) NewAuthGate() security.AuthGate {
	if c.Auth.RateLimit.Disable {
		return security.NopGate{}
	}
	cfg := security.DefaultRateLimitConfig()
	if n := c.Auth.RateLimit.MaxAttempts; n > 0 {
		cfg.MaxAttempts = n
	}
	if s := strings.TrimSpace(c.Auth.RateLimit.Window); s != "" {
		d, err := ParseDuration(s)
		if err == nil && d > 0 {
			cfg.Window = d
		}
	}
	return security.NewRateLimitGate(cfg)
}

// NewSendGate builds the process-wide submission message rate limit gate from config.
func (c *Config) NewSendGate() security.SendGate {
	if c.SMTP.SubmissionRateLimit.Disable {
		return security.NopSendGate{}
	}
	cfg := security.DefaultSendLimitConfig()
	if n := c.SMTP.SubmissionRateLimit.MaxMessages; n > 0 {
		cfg.MaxMessages = n
	}
	if s := strings.TrimSpace(c.SMTP.SubmissionRateLimit.Window); s != "" {
		d, err := ParseDuration(s)
		if err == nil && d > 0 {
			cfg.Window = d
		}
	}
	return security.NewSendLimitGate(cfg)
}

// NewMTASTSResolver returns the outbound MTA-STS resolver, or nil when disabled.
func (c *Config) NewMTASTSResolver() *mtasts.Resolver {
	if c.SMTP.MTASTS.Disable {
		return nil
	}
	return mtasts.NewResolver()
}

// NewDKIMSigner loads the outbound DKIM signer when selector and key path are set.
func (c *Config) NewDKIMSigner() (*dkimout.Signer, error) {
	s := c.SMTP.DKIMSign
	if strings.TrimSpace(s.Selector) == "" || strings.TrimSpace(s.PrivateKeyPath) == "" {
		return nil, nil
	}
	path := s.PrivateKeyPath
	if !filepath.IsAbs(path) {
		path = filepath.Join(c.DataDir, path)
	}
	return dkimout.New(dkimout.Config{
		Selector: s.Selector,
		Domain:   s.Domain,
		KeyPath:  path,
	})
}
