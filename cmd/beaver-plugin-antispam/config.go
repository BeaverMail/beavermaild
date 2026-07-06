// Plugin config and reload for beaver-plugin-antispam.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type pluginConfig struct {
	Enabled           bool               `json:"enabled"`
	SkipAuthenticated bool               `json:"skip_authenticated"`
	HardReject        hardRejectConfig   `json:"hard_reject"`
	RBL               rblConfig          `json:"rbl"`
	Static            staticConfig       `json:"static"`
	Lists             listsConfig        `json:"lists"`
	Content           contentConfig      `json:"content"`
	Rules             []exprRule         `json:"rules"`
	Scores            map[string]float64 `json:"scores"`
	Thresholds        thresholdConfig    `json:"thresholds"`
	TagActions        map[string]string  `json:"tag_actions"`
	lastReload        time.Time
}

type listsConfig struct {
	SpamTraps      []string `json:"spam_traps"`
	TrustedDomains []string `json:"trusted_domains"`
	URLRedirectors []string `json:"url_redirectors"`
	BadExtensions  []string `json:"bad_extensions"`
}

type hardRejectConfig struct {
	RBLOnConnect     bool `json:"rbl_on_connect"`
	StaticOnConnect  bool `json:"static_on_connect"`
}

type rblConfig struct {
	Enabled             bool              `json:"enabled"`
	Zones               []string          `json:"zones"`
	TimeoutMs           int               `json:"timeout_ms"`
	OnDNSFail           string            `json:"on_dns_fail"`
	CacheTTLListedSec   int               `json:"cache_ttl_listed_sec"`
	CacheTTLMissSec     int               `json:"cache_ttl_miss_sec"`
	MaxChecksPerMessage int               `json:"max_checks_per_message"`
	TagPrefix           string            `json:"tag_prefix"`
	TagAliases          map[string]string `json:"tag_aliases"`
}

type staticConfig struct {
	DenyClientIP  []string `json:"deny_client_ip"`
	DenyMailFrom  []string `json:"deny_mail_from"`
	DenyRcptTo    []string `json:"deny_rcpt_to"`
}

type contentConfig struct {
	DenySubjectRegex []string `json:"deny_subject_regex"`
	MaxHeaderBytes   int      `json:"max_header_bytes"`
}

type thresholdConfig struct {
	Reject  float64 `json:"reject"`
	Discard float64 `json:"discard"`
	Spam    float64 `json:"spam"`
}

func defaultConfig() pluginConfig {
	return pluginConfig{
		Enabled: true,
		HardReject: hardRejectConfig{
			RBLOnConnect:    true,
			StaticOnConnect: true,
		},
		RBL: rblConfig{
			Enabled:           false,
			Zones:             []string{"zen.spamhaus.org"},
			TimeoutMs:         500,
			OnDNSFail:         "accept",
			CacheTTLListedSec: 3600,
			CacheTTLMissSec:   86400,
		},
		Scores: map[string]float64{
			"RBL_ZEN":                  3.0,
			"SPF_FAIL":                 5.0,
			"SPF_SOFTFAIL":             2.0,
			"DKIM_REJECT":              3.0,
			"DMARC_POLICY_REJECT":      8.0,
			"DMARC_POLICY_QUARANTINE":  4.0,
			"SUBJECT_BAD":              5.0,
			"GTUBE_TEST":               10.0,
			"SUBJ_ALL_CAPS":            2.0,
			"URL_IN_SUBJECT":           2.0,
			"SUBJECT_HAS_CURRENCY":     1.5,
			"MISSING_SUBJECT":          1.0,
			"EMPTY_SUBJECT":            1.0,
			"MISSING_DATE":             0.5,
			"DATE_IN_PAST":             0.5,
			"DATE_IN_FUTURE":           1.0,
			"HELO_BAREIP":              2.0,
			"HELO_NOT_FQDN":            2.0,
			"HELO_IPREV_MISMATCH":      3.0,
			"HELO_NORES_A_OR_MX":       2.0,
			"HELO_IP_A":                2.0,
			"RDNS_NONE":                2.0,
			"RDNS_DNSFAIL":             1.0,
			"RCVD_COUNT_ZERO":          1.0,
			"RCVD_DOUBLE_IP_SPAM":      2.0,
			"RCVD_NO_TLS_LAST":         0.5,
			"MISSING_MID":              1.0,
			"FORGED_SENDER":            4.0,
			"SPOOF_REPLYTO":            3.0,
			"SPAM_TRAP":                10.0,
			"MIME_HTML_ONLY":           1.5,
			"MIME_BAD_EXTENSION":       4.0,
			"PHISHING":                 5.0,
			"URL_ONLY":                 2.0,
			"REDIRECTOR_URL":           2.0,
			"HOMOGRAPH_URL":            3.0,
			"MISSING_ESSENTIAL_HEADERS": 1.0,
		},
		Thresholds: thresholdConfig{Reject: 10, Discard: 15, Spam: 5},
		TagActions: map[string]string{"IP_BLOCKED": "reject"},
		Content: contentConfig{MaxHeaderBytes: 65536},
	}
}

type configStore struct {
	mu      sync.RWMutex
	cfg     pluginConfig
	dataDir string
	sentinel time.Time
}

func newConfigStore(dataDir string) (*configStore, error) {
	s := &configStore{dataDir: dataDir, cfg: defaultConfig()}
	if err := s.reload(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *configStore) get() pluginConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *configStore) maybeReload() {
	path := filepath.Join(antispamDir(s.dataDir), ".reload")
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if !info.ModTime().After(s.sentinel) {
		return
	}
	_ = s.reload()
}

func (s *configStore) reload() error {
	path := filepath.Join(antispamDir(s.dataDir), "config.json")
	cfg := defaultConfig()
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return err
		}
	}
	cfg.lastReload = time.Now()
	s.mu.Lock()
	s.cfg = cfg
	if info, err := os.Stat(filepath.Join(antispamDir(s.dataDir), ".reload")); err == nil {
		s.sentinel = info.ModTime()
	} else {
		s.sentinel = time.Now()
	}
	s.mu.Unlock()
	return nil
}

func loadConfig(dataDir string) (pluginConfig, error) {
	s, err := newConfigStore(dataDir)
	if err != nil {
		return pluginConfig{}, err
	}
	return s.get(), nil
}
