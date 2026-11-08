// Derived from rspamd (https://github.com/rspamd/rspamd), Copyright (c) Vsevolod Stakhov and the
// rspamd contributors, Apache License 2.0 (LICENSES/Apache-2.0.txt): conf/actions.conf, conf/scores.d/*_group.conf, conf/modules.d/rbl.conf and the
// default scores in rules/*.lua and src/plugins/lua/{greylist,url_redirector}.lua.
// Translated to Go and modified for BeaverMail; see NOTICE.

// Plugin configuration (<data_dir>/antispam/config.json), operator lists and default symbol scores.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Action names, as rspamd reports them.
const (
	actNone      = "no action"
	actGreylist  = "greylist"
	actAddHeader = "add header"
	actRewrite   = "rewrite subject"
	actReject    = "reject"
	actDiscard   = "discard"
)

// Config is the JSON document at <data_dir>/antispam/config.json. Absent keys keep their defaults.
type Config struct {
	// Actions maps rspamd action names (reject, rewrite_subject, add_header, greylist) to
	// score thresholds; null disables an action.
	Actions  map[string]*float64 `json:"actions"`
	Scores   map[string]float64  `json:"scores"` // per-symbol score overrides
	GTUBE    string              `json:"gtube"`  // reject (default), all, disabled
	Greylist struct {
		DelaySeconds  int `json:"delay_seconds"`
		ExpireSeconds int `json:"expire_seconds"`
	} `json:"greylist"`
	HFilter struct {
		DNSChecks bool `json:"dns_checks"` // resolve HELO / MAIL FROM / Message-ID hosts
	} `json:"hfilter"`
	RBL struct {
		Enabled     bool   `json:"enabled"`
		DQSKey      string `json:"dqs_key"`  // Spamhaus Data Query Service key; empty = public mirrors
		Resolver    string `json:"resolver"` // host:port of a recursive resolver; empty = system
		TimeoutMs   int    `json:"timeout_ms"`
		MaxLookups  int    `json:"max_lookups"` // per message, cache hits excluded
		CacheSecond int    `json:"cache_seconds"`
		Received    bool   `json:"received"` // also check public IPs found in Received headers
	} `json:"rbl"`
	URLRedirector struct {
		Enabled     bool `json:"enabled"`
		MaxURLs     int  `json:"max_urls"`
		NestedLimit int  `json:"nested_limit"`
		TimeoutMs   int  `json:"timeout_ms"` // per hop
	} `json:"url_redirector"`
	Spamtrap struct {
		Action string `json:"action"` // "", reject or discard
	} `json:"spamtrap"`
}

func f64(v float64) *float64 { return &v }

// defaultConfig mirrors rspamd conf/actions.conf and module defaults; network checks are off.
func defaultConfig() Config {
	var c Config
	c.Actions = map[string]*float64{"reject": f64(15), "add_header": f64(6), "greylist": f64(4), "rewrite_subject": nil}
	c.Scores = map[string]float64{}
	c.GTUBE = "reject"
	c.Greylist.DelaySeconds = 300
	c.Greylist.ExpireSeconds = 86400
	c.RBL.TimeoutMs = 2000
	c.RBL.MaxLookups = 24
	c.RBL.CacheSecond = 3600
	c.RBL.Received = true
	c.URLRedirector.MaxURLs = 5
	c.URLRedirector.NestedLimit = 2
	c.URLRedirector.TimeoutMs = 4000
	return c
}

var dqsKeyRe = regexp.MustCompile(`^[a-z0-9]{8,64}$`)

func (c *Config) validate() error {
	for k, v := range c.Actions {
		switch k {
		case "reject", "add_header", "greylist", "rewrite_subject":
		default:
			return fmt.Errorf("actions: unknown action %q", k)
		}
		if v != nil && *v <= 0 {
			return fmt.Errorf("actions.%s: threshold must be > 0 or null", k)
		}
	}
	switch c.GTUBE {
	case "reject", "all", "disabled":
	default:
		return fmt.Errorf("gtube: want reject, all or disabled")
	}
	switch c.Spamtrap.Action {
	case "", "reject", "discard":
	default:
		return fmt.Errorf("spamtrap.action: want \"\", reject or discard")
	}
	if c.RBL.DQSKey != "" && !dqsKeyRe.MatchString(c.RBL.DQSKey) {
		return errors.New("rbl.dqs_key: must be 8-64 lowercase letters/digits")
	}
	if c.Greylist.DelaySeconds < 0 || c.Greylist.ExpireSeconds <= c.Greylist.DelaySeconds {
		return errors.New("greylist: need 0 <= delay_seconds < expire_seconds")
	}
	if c.RBL.TimeoutMs <= 0 || c.RBL.MaxLookups < 0 || c.RBL.CacheSecond < 0 ||
		c.URLRedirector.TimeoutMs <= 0 || c.URLRedirector.MaxURLs < 0 || c.URLRedirector.NestedLimit < 1 {
		return errors.New("rbl/url_redirector: timeouts and limits must be positive")
	}
	return nil
}

// threshold returns the configured threshold for action key (config spelling) and whether it is on.
func (c *Config) threshold(key string) (float64, bool) {
	v := c.Actions[key]
	if v == nil {
		return 0, false
	}
	return *v, true
}

// Lists are the operator plain-text files next to config.json (one entry per line, # comments).
type Lists struct {
	SpamTraps   map[string]bool // full address or @domain
	Trusted     map[string]bool // From domains (whitelist with DMARC)
	Redirectors map[string]bool // URL redirector hosts
}

const (
	configFile      = "config.json"
	spamTrapsFile   = "spam-traps.txt"
	trustedFile     = "trusted-domains.txt"
	redirectorsFile = "url-redirectors.txt"
	reloadStampFile = "reload.stamp"
)

func antispamDir(dataDir string) string { return filepath.Join(dataDir, "antispam") }

// loadConfig reads config.json (defaults when absent) and the lists.
func loadConfig(dataDir string) (Config, Lists, error) {
	dir := antispamDir(dataDir)
	cfg := defaultConfig()
	b, err := os.ReadFile(filepath.Join(dir, configFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return cfg, Lists{}, err
	default:
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return cfg, Lists{}, fmt.Errorf("%s: %w", configFile, err)
		}
	}
	if err := cfg.validate(); err != nil {
		return cfg, Lists{}, fmt.Errorf("%s: %w", configFile, err)
	}
	var l Lists
	for _, f := range []struct {
		name string
		dst  *map[string]bool
	}{{spamTrapsFile, &l.SpamTraps}, {trustedFile, &l.Trusted}, {redirectorsFile, &l.Redirectors}} {
		m, err := readList(filepath.Join(dir, f.name))
		if err != nil {
			return cfg, Lists{}, err
		}
		*f.dst = m
	}
	return cfg, l, nil
}

// readList loads a lowercase set from a text file; a missing file is an empty list.
func readList(path string) (map[string]bool, error) {
	out := map[string]bool{}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.ToLower(strings.TrimSpace(line)); line != "" {
			out[strings.TrimSuffix(line, ".")] = true
		}
	}
	return out, sc.Err()
}

// defaultScores are rspamd's default symbol weights (conf/scores.d and the rule files).
var defaultScores = map[string]float64{
	// policies_group.conf
	"R_SPF_FAIL": 1, "R_SPF_SOFTFAIL": 0, "R_SPF_NEUTRAL": 0, "R_SPF_ALLOW": -0.2, "R_SPF_DNSFAIL": 0,
	"R_SPF_NA": 0, "R_SPF_PERMFAIL": 0, "R_DKIM_REJECT": 1, "R_DKIM_TEMPFAIL": 0, "R_DKIM_PERMFAIL": 0,
	"R_DKIM_ALLOW": -0.1, "R_DKIM_NA": 0, "DMARC_POLICY_ALLOW": -0.5, "DMARC_POLICY_REJECT": 2,
	"DMARC_POLICY_QUARANTINE": 1.5, "DMARC_POLICY_SOFTFAIL": 0.1, "DMARC_NA": 0, "DMARC_DNSFAIL": 0,
	"DMARC_BAD_POLICY": 0, "ARC_ALLOW": -1, "ARC_REJECT": 1, "ARC_INVALID": 0.5, "ARC_DNSFAIL": 0, "ARC_NA": 0,
	// whitelist_group.conf
	"WHITELIST_DMARC": -7, "BLACKLIST_DMARC": 6,
	// hfilter_group.conf
	"HFILTER_HELO_BAREIP": 3, "HFILTER_HELO_BADIP": 4.5, "HFILTER_HELO_1": 0.5, "HFILTER_HELO_2": 1,
	"HFILTER_HELO_3": 2, "HFILTER_HELO_4": 2.5, "HFILTER_HELO_5": 3, "HFILTER_HOSTNAME_1": 0.5,
	"HFILTER_HOSTNAME_2": 1, "HFILTER_HOSTNAME_3": 2, "HFILTER_HOSTNAME_4": 2.5, "HFILTER_HOSTNAME_5": 3,
	"HFILTER_HELO_NORESOLVE_MX": 0.2, "HFILTER_HELO_NORES_A_OR_MX": 0.3, "HFILTER_HELO_IP_A": 1,
	"HFILTER_HELO_NOT_FQDN": 2, "HFILTER_FROMHOST_NORESOLVE_MX": 0.5, "HFILTER_FROMHOST_NORES_A_OR_MX": 1.5,
	"HFILTER_FROMHOST_NOT_FQDN": 3, "HFILTER_FROM_BOUNCE": 0, "HFILTER_MID_NORESOLVE_MX": 0.5,
	"HFILTER_MID_NORES_A_OR_MX": 0.5, "HFILTER_MID_NOT_FQDN": 0.5, "HFILTER_HOSTNAME_UNKNOWN": 2.5,
	"HFILTER_RCPT_BOUNCEMOREONE": 1.5, "HFILTER_URL_ONLY": 2.2, "HFILTER_URL_ONELINE": 2.5,
	"RDNS_NONE": 2, "RDNS_DNSFAIL": 0,
	// rbl_group.conf / surbl_group.conf (Spamhaus)
	"RBL_SPAMHAUS": 0, "RBL_SPAMHAUS_SBL": 4, "RBL_SPAMHAUS_CSS": 2, "RBL_SPAMHAUS_XBL": 4,
	"RBL_SPAMHAUS_PBL": 2, "RBL_SPAMHAUS_DROP": 7, "RECEIVED_SPAMHAUS": 0, "RECEIVED_SPAMHAUS_SBL": 3,
	"RECEIVED_SPAMHAUS_CSS": 1, "RECEIVED_SPAMHAUS_XBL": 1, "RECEIVED_SPAMHAUS_PBL": 0,
	"RECEIVED_SPAMHAUS_DROP": 6, "DBL": 0, "DBL_SPAM": 6.5, "DBL_PHISH": 7.5, "DBL_MALWARE": 7.5,
	"DBL_BOTNET": 7.5, "DBL_ABUSE": 5, "DBL_ABUSE_REDIR": 5, "DBL_ABUSE_PHISH": 6.5,
	"DBL_ABUSE_MALWARE": 6.5, "DBL_ABUSE_BOTNET": 6.5,
	// rules/mid.lua
	"MID_BARE_IP": 2, "MID_RHS_NOT_FQDN": 0.5, "MID_MISSING_BRACKETS": 0.5, "MID_RHS_IP_LITERAL": 0.5,
	"MID_CONTAINS_FROM": 1, "MID_RHS_MATCH_FROM": 0, "MID_RHS_MATCH_FROMTLD": 0, "MID_CONTAINS_TO": 1,
	"MID_RHS_MATCH_TO": 1, "MID_END_EQ_FROM_USER_PART": 4,
	// rules/misc.lua
	"MISSING_DATE": 1, "INVALID_DATE": 1.5, "DATE_IN_FUTURE": 4, "DATE_IN_PAST": 1,
	// rules/subject_checks.lua
	"SUBJ_ALL_CAPS": 3, "LONG_SUBJ": 3,
	// rules/regexp/headers.lua
	"SUBJECT_NEEDS_ENCODING": 1, "FROM_NEEDS_ENCODING": 1, "TO_NEEDS_ENCODING": 1, "R_HTTP_URL_IN_FROM": 5,
	"R_NO_SPACE_IN_FROM": 1, "TO_WRAPPED_IN_SPACES": 2, "MISSING_SUBJECT": 2, "EMPTY_SUBJECT": 1,
	"MISSING_TO": 2, "R_UNDISC_RCPT": 3, "MISSING_MID": 2.5, "R_MISSING_CHARSET": 0.5, "TRACKER_ID": 3.84,
	"FROM_EXCESS_BASE64": 1.5, "FROM_EXCESS_QP": 1.2, "TO_EXCESS_BASE64": 1.5, "TO_EXCESS_QP": 1.2,
	"REPLYTO_EXCESS_BASE64": 1.5, "REPLYTO_EXCESS_QP": 1.2, "CC_EXCESS_BASE64": 1.5, "CC_EXCESS_QP": 1.2,
	"SUBJ_EXCESS_BASE64": 1.5, "SUBJ_EXCESS_QP": 1.2, "INVALID_MSGID": 1.7, "MIME_HEADER_CTYPE_ONLY": 2,
	"FAKE_REPLY": 1, "HEADER_FROM_EMPTY_DELIMITER": 1, "HEADER_TO_EMPTY_DELIMITER": 1,
	"HEADER_CC_EMPTY_DELIMITER": 1, "HEADER_REPLYTO_EMPTY_DELIMITER": 1, "HEADER_DATE_EMPTY_DELIMITER": 1,
	"CTE_CASE": 0.5, "CT_EXTRA_SEMI": 1, "SUBJECT_ENDS_QUESTION": 1, "SUBJECT_HAS_CURRENCY": 1,
	"SUBJECT_ENDS_SPACES": 0.5, "CD_MM_BODY": 2, "X_PHPOS_FAKE": 3, "HAS_LIST_UNSUB": -0.01,
	// rules/headers_checks.lua
	"REPLYTO_UNPARSEABLE": 1, "REPLYTO_EMAIL_HAS_TITLE": 2, "REPLYTO_EQ_TO_ADDR": 5, "REPLYTO_INVALID": 1,
	"REPLYTO_LOCALPART_LONG": 2, "REPLYTO_DOMAIN_LONG": 2, "MISSING_MIME_VERSION": 2,
	"MIME_MA_MISSING_TEXT": 2, "MIME_MA_MISSING_HTML": 1, "BROKEN_CONTENT_TYPE": 1.5,
	"HEADER_RCONFIRM_MISMATCH": 2, "HEADER_FORGED_MDN": 2, "MULTIPLE_UNIQUE_HEADERS": 7,
	"MISSING_ESSENTIAL_HEADERS": 7, "MISSING_FROM": 2, "MULTIPLE_FROM": 8, "MV_CASE": 0.5,
	"ENVFROM_INVALID": 2, "FROM_INVALID": 2, "FROM_DN_EQ_ADDR": 1, "FROM_NAME_EXCESS_SPACE": 1,
	"FROM_NAME_HAS_TITLE": 1, "TO_DN_RECIPIENTS": 2, "CTYPE_MISSING_DISPOSITION": 4, "CTYPE_MIXED_BOGUS": 1,
	"MIME_BASE64_TEXT": 0.1, "MIME_BASE64_TEXT_BOGUS": 1, "INVALID_FROM_8BIT": 6, "INVALID_RCPT_8BIT": 6,
	"XM_CASE": 0.5,
	// mime_types_group.conf
	"MIME_BAD_ATTACHMENT": 4, "MIME_ENCRYPTED_ARCHIVE": 2, "MIME_ARCHIVE_IN_ARCHIVE": 5,
	"MIME_DOUBLE_BAD_EXTENSION": 3, "MIME_BAD_EXTENSION": 2, "MIME_BAD_UNICODE": 2,
	// rules/html.lua
	"MIME_HTML_ONLY": 0.2, "HTML_SHORT_LINK_IMG_1": 2, "HTML_SHORT_LINK_IMG_2": 1, "HTML_SHORT_LINK_IMG_3": 0.5,
	"R_EMPTY_IMAGE": 2, "EXT_CSS": 1, "HTTP_TO_HTTPS": 0.5, "HTTP_TO_IP": 1,
	// url_suspect_group.conf / phishing_group.conf
	"URL_USER_PASSWORD": 2, "URL_USER_LONG": 3, "URL_USER_VERY_LONG": 5, "URL_NUMERIC_IP": 1.5,
	"URL_NUMERIC_IP_USER": 4, "URL_NUMERIC_PRIVATE_IP": 0.5, "URL_NO_TLD": 2, "URL_SUSPICIOUS_TLD": 3,
	"URL_RTL_OVERRIDE": 6, "URL_ZERO_WIDTH_SPACES": 7, "URL_MULTIPLE_AT_SIGNS": 3, "URL_BACKSLASH_PATH": 2,
	"URL_EXCESSIVE_DOTS": 2, "URL_VERY_LONG": 1.5, "URL_QUERY_MULTIPLE_URLS": 2, "PHISHING": 4,
	"URL_DISPLAY_MISMATCH": 0, "URL_REDIRECTOR_NESTED": 1,
	// spamtrap.lua, message.c
	"SPAMTRAP": 0, "GTUBE": 0,
}
