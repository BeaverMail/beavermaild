package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/dkimout"
	"github.com/BeaverMail/beaver/internal/security"
)

func TestStoreDriverMySQLRequiresDSN(t *testing.T) {
	t.Parallel()
	cfg := config.Default(t.TempDir())
	cfg.Store.Driver = config.StoreDriverMySQL
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected dsn required")
	}
	cfg.Store.DSN = "user:pass@tcp(127.0.0.1:3306)/beaver"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreDriverEnv(t *testing.T) {
	cfg := config.Default(t.TempDir())
	t.Setenv("BEAVER_STORE_DRIVER", "mysql")
	t.Setenv("BEAVER_STORE_DSN", "u:p@tcp(127.0.0.1:3306)/db")
	cfg.ApplyEnv()
	if cfg.StoreDriver() != config.StoreDriverMySQL {
		t.Fatalf("driver %q", cfg.StoreDriver())
	}
	if cfg.StoreDSN() != "u:p@tcp(127.0.0.1:3306)/db" {
		t.Fatalf("dsn %q", cfg.StoreDSN())
	}
}

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

func TestHTTPEnabledRequiresAuthKey(t *testing.T) {
	t.Parallel()
	cfg := config.Default(t.TempDir())
	cfg.HTTP.Enabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected auth_key required")
	}
	cfg.Secrets.AuthKey = "0123456789abcdef0123456789abcdef"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPListen() != "127.0.0.1:8080" {
		t.Fatalf("listen %q", cfg.HTTPListen())
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

func TestSMTPOutboundTLSInsecureEnv(t *testing.T) {
	cfg := config.Default(t.TempDir())
	t.Setenv("BEAVER_SMTP_OUTBOUND_TLS_INSECURE", "true")
	cfg.ApplyEnv()
	if !cfg.SMTPOutboundTLSInsecureSkip() {
		t.Fatal("expected outbound TLS insecure skip")
	}
}

func TestPluginsSMTPDefaults(t *testing.T) {
	t.Parallel()
	cfg := config.Default(t.TempDir())
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Plugins.SMTP.FilterTimeoutMs != 10000 {
		t.Fatalf("timeout %d", cfg.Plugins.SMTP.FilterTimeoutMs)
	}
	if cfg.Plugins.SMTP.TimeoutPolicy != "accept" {
		t.Fatalf("policy %q", cfg.Plugins.SMTP.TimeoutPolicy)
	}
	if !cfg.PluginsSMTPTimeoutFailOpen() {
		t.Fatal("expected fail-open default")
	}
	if cfg.Plugins.SMTP.RestartBackoffMs != 1000 {
		t.Fatalf("restart backoff %d", cfg.Plugins.SMTP.RestartBackoffMs)
	}
	if cfg.PluginsSMTPRestartBackoff() != 1000*time.Millisecond {
		t.Fatalf("restart backoff duration %v", cfg.PluginsSMTPRestartBackoff())
	}
	wantSocket := filepath.Join(cfg.DataDir, "run", "plugins")
	if got := cfg.PluginsSMTPSocketDir(); got != wantSocket {
		t.Fatalf("socket dir %q want %q", got, wantSocket)
	}
}

func TestPluginsSMTPTimeoutPolicyValidation(t *testing.T) {
	cfg := config.Default(t.TempDir())
	cfg.Plugins.SMTP.TimeoutPolicy = "drop"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDefaultConfigPathSystem(t *testing.T) {
	t.Setenv("BEAVER_CONFIG", "")
	got := config.DefaultConfigPath()
	if got != config.SystemConfigPath {
		t.Fatalf("got %q want %q", got, config.SystemConfigPath)
	}
}

func TestDefaultConfigPathEnv(t *testing.T) {
	t.Setenv("BEAVER_CONFIG", "/tmp/beaver-test/config.json")
	got := config.DefaultConfigPath()
	want := "/tmp/beaver-test/config.json"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSMTPVRFYEnv(t *testing.T) {
	cfg := config.Default(t.TempDir())
	t.Setenv("BEAVER_SMTP_VRFY_ENABLED", "true")
	cfg.ApplyEnv()
	if !cfg.SMTPVRFYEnabled() {
		t.Fatal("expected vrfy enabled")
	}
}

func TestNewAuthGate(t *testing.T) {
	cfg := config.Default(t.TempDir())
	if _, ok := cfg.NewAuthGate().(*security.RateLimitGate); !ok {
		t.Fatalf("default gate type %T", cfg.NewAuthGate())
	}

	cfg.Auth.RateLimit.Disable = true
	if _, ok := cfg.NewAuthGate().(security.NopGate); !ok {
		t.Fatalf("disabled gate type %T", cfg.NewAuthGate())
	}
}

func TestNewAuthGateEnvDisable(t *testing.T) {
	cfg := config.Default(t.TempDir())
	t.Setenv("BEAVER_AUTH_RATE_LIMIT_DISABLE", "true")
	cfg.ApplyEnv()
	if _, ok := cfg.NewAuthGate().(security.NopGate); !ok {
		t.Fatalf("env disabled gate type %T", cfg.NewAuthGate())
	}
}

func TestNewMTASTSResolver(t *testing.T) {
	cfg := config.Default(t.TempDir())
	if cfg.NewMTASTSResolver() == nil {
		t.Fatal("expected resolver by default")
	}
	cfg.SMTP.MTASTS.Disable = true
	if cfg.NewMTASTSResolver() != nil {
		t.Fatal("expected nil when disabled")
	}
}

func TestNewMTASTSResolverEnvDisable(t *testing.T) {
	cfg := config.Default(t.TempDir())
	t.Setenv("BEAVER_SMTP_MTA_STS_DISABLE", "true")
	cfg.ApplyEnv()
	if cfg.NewMTASTSResolver() != nil {
		t.Fatal("expected nil when env disabled")
	}
}

func TestNewDKIMSigner(t *testing.T) {
	cfg := config.Default(t.TempDir())
	if _, err := cfg.NewDKIMSigner(); err != nil {
		t.Fatal(err)
	}
	if s, _ := cfg.NewDKIMSigner(); s != nil {
		t.Fatal("expected nil without config")
	}
	keyPath := filepath.Join(cfg.DataDir, "dkim.pem")
	if err := dkimout.GenerateTestKey(keyPath); err != nil {
		t.Fatal(err)
	}
	cfg.SMTP.DKIMSign = config.DKIMSignConfig{
		Selector:       "beaver",
		Domain:         "example.com",
		PrivateKeyPath: "dkim.pem",
	}
	s, err := cfg.NewDKIMSigner()
	if err != nil || s == nil {
		t.Fatalf("signer %v err %v", s, err)
	}
}
