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
	SpamRulesURL      string             `json:"spam_rules_url"`
	URLRedirects      urlRedirectConfig  `json:"url_redirects"`
	Scores            map[string]float64 `json:"scores"`
	Thresholds        thresholdConfig    `json:"thresholds"`
	TagActions        map[string]string  `json:"tag_actions"`
	lastReload        time.Time
}

type urlRedirectConfig struct {
	Enabled      bool `json:"enabled"`
	TimeoutMs    int  `json:"timeout_ms"`
	MaxRedirects int  `json:"max_redirects"`
}

type listsConfig struct {
	SpamTraps      []string `json:"spam_traps"`
	TrustedDomains []string `json:"trusted_domains"`
	URLRedirectors []string `json:"url_redirectors"`
	BadExtensions  []string `json:"bad_extensions"`
}

type hardRejectConfig struct {
	RBLOnConnect    bool `json:"rbl_on_connect"`
	StaticOnConnect bool `json:"static_on_connect"`
}

type rblConfig struct {
	Enabled             bool              `json:"enabled"`
	Zones               []string          `json:"zones"`
	ClientIPZones       []string          `json:"client_ip_zones"`
	DomainZones         []string          `json:"domain_zones"`
	URLZones            []string          `json:"url_zones"`
	TimeoutMs           int               `json:"timeout_ms"`
	OnDNSFail           string            `json:"on_dns_fail"`
	CacheTTLListedSec   int               `json:"cache_ttl_listed_sec"`
	CacheTTLMissSec     int               `json:"cache_ttl_miss_sec"`
	MaxChecksPerMessage int               `json:"max_checks_per_message"`
	TagPrefix           string            `json:"tag_prefix"`
	TagAliases          map[string]string `json:"tag_aliases"`
	// SpamhausDQSKey queries *.spamhaus.org zones through Spamhaus DQS
	// (<key>.<zone>.dq.spamhaus.net), which works from public resolvers. Tags keep the
	// public zone name (RBL_ZEN), so the key never reaches message headers.
	SpamhausDQSKey string `json:"spamhaus_dqs_key"`
	// ZoneCodes limits which A records count as a listing, per zone (public name, e.g.
	// "dbl.spamhaus.org"). Entries are "127.0.1.2" or a last-octet range "127.0.2.2-24".
	// Zones without an entry count any 127.x reply. Merged with the Spamhaus defaults.
	ZoneCodes map[string][]string `json:"zone_codes"`
}

// forScope returns a config with the scope-specific zones or legacy zones.
func (c rblConfig) forScope(scope string) rblConfig {
	var zones []string
	switch scope {
	case "client_ip":
		zones = c.ClientIPZones
	case "domain":
		zones = c.DomainZones
	case "url":
		zones = c.URLZones
	}
	if len(zones) > 0 {
		c.Zones = zones
	}
	return c
}

type staticConfig struct {
	DenyClientIP []string `json:"deny_client_ip"`
	DenyMailFrom []string `json:"deny_mail_from"`
	DenyRcptTo   []string `json:"deny_rcpt_to"`
	ClientIPTag  string   `json:"client_ip_tag"`
	MailFromTag  string   `json:"mail_from_tag"`
	RcptToTag    string   `json:"rcpt_to_tag"`
}

// tag returns the configured static-list tag or its stable default.
func (c staticConfig) tag(kind string) string {
	switch kind {
	case "client_ip":
		if c.ClientIPTag != "" {
			return c.ClientIPTag
		}
		return "IP_BLOCKED"
	case "mail_from":
		if c.MailFromTag != "" {
			return c.MailFromTag
		}
		return "ENV_FROM_BLOCKED"
	default:
		if c.RcptToTag != "" {
			return c.RcptToTag
		}
		return "RCPT_BLOCKED"
	}
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
			ZoneCodes: map[string][]string{
				// SBL, SBL CSS, XBL, DROP, PBL (dynamic/end-user ranges).
				"zen.spamhaus.org": {"127.0.0.2", "127.0.0.3", "127.0.0.4-7", "127.0.0.9", "127.0.0.10", "127.0.0.11"},
				// Spam, phish, malware, botnet C&C; not 127.0.1.102-106 (abused legit domains).
				"dbl.spamhaus.org": {"127.0.1.2", "127.0.1.4", "127.0.1.5", "127.0.1.6"},
				// Zero Reputation Domains: registered 2-24 hours ago.
				"zrd.spamhaus.org": {"127.0.2.2-24"},
			},
		},
		Scores: map[string]float64{
			// Weights from Stalwart spam-filter-rules catalog; operator scores merge on reload.
			"RBL_ZEN":                   4.0,
			"SPF_ALLOW":                 -0.2,
			"SPF_FAIL":                  1.0,
			"DKIM_ALLOW":                -0.2,
			"DKIM_REJECT":               1.0,
			"DMARC_POLICY_ALLOW":        -0.5,
			"DMARC_POLICY_REJECT":       4.0,
			"DMARC_POLICY_QUARANTINE":   1.5,
			"DMARC_POLICY_SOFTFAIL":     0.1,
			"ARC_ALLOW":                 -0.5,
			"ARC_REJECT":                2.0,
			"ARC_INVALID":               1.0,
			"SUBJECT_BAD":               5.0,
			"GTUBE_TEST":                1000.0,
			"SUBJ_ALL_CAPS":             3.0,
			"URL_IN_SUBJECT":            4.0,
			"SUBJECT_HAS_CURRENCY":      1.0,
			"MISSING_SUBJECT":           2.0,
			"EMPTY_SUBJECT":             1.0,
			"MISSING_DATE":              1.0,
			"DATE_IN_PAST":              1.0,
			"DATE_IN_FUTURE":            4.0,
			"HELO_BAREIP":               3.0,
			"HELO_NOT_FQDN":             2.0,
			"HELO_IPREV_MISMATCH":       1.0,
			"HELO_NORES_A_OR_MX":        0.3,
			"HELO_IP_A":                 1.0,
			"RDNS_NONE":                 2.0,
			"RCVD_COUNT_ZERO":           0.1,
			"RCVD_DOUBLE_IP_SPAM":       2.0,
			"RCVD_NO_TLS_LAST":          0.1,
			"MISSING_MID":               2.5,
			"FORGED_SENDER":             0.3,
			"SPOOF_REPLYTO":             6.0,
			"SPAM_TRAP":                 15.0,
			"MIME_HTML_ONLY":            0.2,
			"MIME_BAD_EXTENSION":        2.0,
			"PHISHING":                  4.0,
			"URL_ONLY":                  2.2,
			"HOMOGRAPH_URL":             5.0,
			"MISSING_ESSENTIAL_HEADERS": 7.0,
			"MULTIPLE_FROM":             8.0,
			"FROMHOST_NORES_A_OR_MX":    1.5,
			"FROM_INVALID":              2.0,
			"ENV_FROM_INVALID":          2.0,
			"MISSING_FROM":              2.0,
			"URL_REDIRECTED":            1.0,
		},
		Thresholds: thresholdConfig{Reject: 10, Discard: 15, Spam: 5},
		TagActions: map[string]string{"IP_BLOCKED": "reject", "GTUBE_TEST": "reject"},
		Content:    contentConfig{MaxHeaderBytes: 65536},
	}
}

type configStore struct {
	mu       sync.RWMutex
	cfg      pluginConfig
	dataDir  string
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
	if cfg.SpamRulesURL != "" {
		remote, err := loadRemoteRules(cfg.SpamRulesURL)
		if err != nil {
			return err
		}
		cfg.Rules = append(cfg.Rules, remote...)
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
