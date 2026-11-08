// Derived from rspamd (https://github.com/rspamd/rspamd), Copyright (c) Vsevolod Stakhov and the
// rspamd contributors, Apache License 2.0 (LICENSES/Apache-2.0.txt): src/plugins/lua/greylist.lua and conf/actions.conf.
// Translated to Go and modified for BeaverMail; see NOTICE.

// Scan pipeline: run the checks on one message, add up symbol scores, pick an rspamd-style action.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// request is the SMTP daemon filter wire request (docs/plugins-smtp-daemon.md, v2.2).
type request struct {
	ID            string       `json:"id"`
	Phase         string       `json:"phase"`
	From          string       `json:"from,omitempty"`
	To            []string     `json:"to,omitempty"`
	ClientIP      string       `json:"client_ip,omitempty"`
	BodyPath      string       `json:"body_path,omitempty"`
	TimeoutMs     int          `json:"timeout_ms,omitempty"`
	Listener      string       `json:"listener,omitempty"`
	TLS           bool         `json:"tls,omitempty"`
	Authenticated bool         `json:"authenticated,omitempty"`
	EHLODomain    string       `json:"ehlo_domain,omitempty"`
	IPRevPTR      string       `json:"iprev_ptr,omitempty"`
	IPRevResult   string       `json:"iprev_result,omitempty"`
	ASN           uint32       `json:"asn,omitempty"`
	Country       string       `json:"country,omitempty"`
	Auth          *authResults `json:"auth,omitempty"`
}

type authResults struct {
	SPFEhlo     string `json:"spf_ehlo,omitempty"`
	SPFMailFrom string `json:"spf_mail_from,omitempty"`
	DKIM        string `json:"dkim,omitempty"`
	DMARC       string `json:"dmarc,omitempty"`
	DMARCPolicy string `json:"dmarc_policy,omitempty"`
	ARC         string `json:"arc,omitempty"`
}

type response struct {
	ID      string            `json:"id"`
	Action  string            `json:"action"`
	Score   float64           `json:"score,omitempty"`
	Tags    []string          `json:"tags,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type hit struct {
	factor float64
	opts   []string
}

// result collects inserted symbols (rspamd task:insert_result) and a forced action (pre-result).
type result struct {
	syms   map[string]*hit
	forced string
}

func newResult() *result { return &result{syms: map[string]*hit{}} }

func (r *result) add(sym string, factor float64, opts ...string) {
	h := r.syms[sym]
	if h == nil {
		h = &hit{factor: factor}
		r.syms[sym] = h
	} else if factor > h.factor {
		h.factor = factor
	}
	for _, o := range opts {
		if len(h.opts) < 5 && o != "" {
			h.opts = append(h.opts, o)
		}
	}
}

func (r *result) has(sym string) bool { return r.syms[sym] != nil }

type symScore struct {
	name  string
	score float64
	opts  []string
}

type verdict struct {
	score   float64
	action  string
	symbols []symScore
}

// Filter holds one loaded configuration; reload swaps the whole value.
type Filter struct {
	cfg      Config
	lists    Lists
	rbl      *rblClient
	redir    *redirector
	resolver *net.Resolver
	grey     *greylist
	now      func() time.Time
}

func newFilter(cfg Config, lists Lists, grey *greylist) *Filter {
	if grey == nil {
		grey = newGreylist()
	}
	f := &Filter{cfg: cfg, lists: lists, grey: grey, now: time.Now, resolver: net.DefaultResolver}
	f.rbl = newRBLClient(cfg)
	f.redir = newRedirector(cfg, lists.Redirectors)
	return f
}

func (f *Filter) scoreOf(sym string) float64 {
	if s, ok := f.cfg.Scores[sym]; ok {
		return s
	}
	return defaultScores[sym]
}

// evaluate runs every check on raw for the SMTP context in req.
func (f *Filter) evaluate(ctx context.Context, req *request, raw []byte) verdict {
	r := newResult()
	msg := parseMessage(raw)
	ip := net.ParseIP(req.ClientIP)
	local := ip == nil || isLocalIP(ip)

	checkGTUBE(f.cfg.GTUBE, msg, r)
	checkAuth(req.Auth, r)
	f.checkWhitelist(msg, req.Auth, r)
	f.checkSpamtrap(req.To, r)
	if !local {
		checkHelloHost(req, r)
	}
	checkHFilterMessage(req, msg, r)
	if f.cfg.HFilter.DNSChecks && !local {
		f.checkHostsDNS(ctx, req, msg, r)
	}
	checkMID(msg, r)
	checkDate(msg, f.now(), r)
	checkSubject(msg, r)
	checkHeaders(msg, req, r)
	checkMIMEParts(msg, r)
	checkMIMETypes(msg, r)
	checkHTML(msg, r)
	if f.cfg.URLRedirector.Enabled {
		f.redir.expand(ctx, msg, r)
	}
	checkURLs(msg, r)
	checkPhishing(msg, req.Auth, r)
	if f.cfg.RBL.Enabled {
		f.rbl.check(ctx, f.rblTargets(req, msg, local), r)
	}
	return f.finish(r)
}

func (f *Filter) finish(r *result) verdict {
	v := verdict{}
	for name, h := range r.syms {
		s := f.scoreOf(name) * h.factor
		v.score += s
		v.symbols = append(v.symbols, symScore{name: name, score: s, opts: h.opts})
	}
	sort.Slice(v.symbols, func(i, j int) bool { return v.symbols[i].name < v.symbols[j].name })
	v.action = f.pickAction(v.score, r.forced)
	return v
}

func (f *Filter) pickAction(score float64, forced string) string {
	if forced != "" {
		return forced
	}
	for _, a := range []struct{ key, name string }{
		{"reject", actReject}, {"rewrite_subject", actRewrite}, {"add_header", actAddHeader}, {"greylist", actGreylist},
	} {
		if t, ok := f.cfg.threshold(a.key); ok && score >= t {
			return a.name
		}
	}
	return actNone
}

// filterEOM answers an eom request: score the body, map the action to the wire, add headers.
func (f *Filter) filterEOM(ctx context.Context, req *request) response {
	resp := response{ID: req.ID, Action: "accept"}
	// rspamd skips most checks for authenticated users; outbound mail is not scored here.
	if req.Authenticated || req.Listener == "submission" || req.BodyPath == "" {
		return resp
	}
	raw, err := readBody(req.BodyPath)
	if err != nil {
		logf("read body %s: %v", req.ID, err)
		return resp
	}
	v := f.evaluate(ctx, req, raw)
	resp.Score = round2(v.score)
	for _, s := range v.symbols {
		resp.Tags = append(resp.Tags, s.name)
	}
	switch v.action {
	case actReject:
		resp.Action = "reject"
		return resp
	case actDiscard:
		resp.Action = "discard"
		return resp
	case actGreylist:
		if !f.grey.pass(greylistKeys(req, raw), f.now(), f.cfg) {
			resp.Action = "tempfail"
			return resp
		}
	}
	resp.Headers = f.resultHeaders(v)
	return resp
}

func readBody(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	// shortcut: messages above 32 MiB are scored on their first 32 MiB; raise if the host limit grows.
	return io.ReadAll(io.LimitReader(fh, 32<<20))
}

func round2(v float64) float64 {
	if v < 0 {
		return -round2(-v)
	}
	return float64(int64(v*100+0.5)) / 100
}

const maxHeaderValue = 900

// resultHeaders renders the X-Spam-* headers appended by the host on accept.
func (f *Filter) resultHeaders(v verdict) map[string]string {
	required, ok := f.cfg.threshold("add_header")
	if !ok {
		required, _ = f.cfg.threshold("reject")
	}
	spam := v.action == actAddHeader || v.action == actRewrite
	yes := "No"
	if spam {
		yes = "Yes"
	}
	h := map[string]string{
		"X-Spam-Status": fmt.Sprintf("%s, score=%.2f required=%.2f", yes, v.score, required),
		"X-Spam-Score":  fmt.Sprintf("%.2f", v.score),
		"X-Spam-Action": v.action,
	}
	if spam {
		h["X-Spam-Flag"] = "YES"
	}
	var parts []string
	for _, s := range v.symbols {
		item := fmt.Sprintf("%s(%.2f)", s.name, s.score)
		if len(s.opts) > 0 {
			item += "[" + strings.Join(s.opts, ",") + "]"
		}
		parts = append(parts, item)
	}
	h["X-Spam-Symbols"] = clip(strings.Join(parts, ", "), maxHeaderValue)
	for k, val := range h {
		h[k] = f.scrub(val)
	}
	return h
}

// scrub keeps header values single-line, 7-bit, and free of the DQS key.
func (f *Filter) scrub(s string) string {
	if k := f.cfg.RBL.DQSKey; k != "" {
		s = strings.ReplaceAll(s, k, "<dqs>")
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// greylist is an in-memory port of rspamd's greylist.lua: a message scored into the greylist
// band is soft-rejected until its body or envelope hash was first seen at least delay ago.
type greylist struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newGreylist() *greylist { return &greylist{seen: map[string]time.Time{}} }

func (g *greylist) pass(keys []string, now time.Time, cfg Config) bool {
	delay := time.Duration(cfg.Greylist.DelaySeconds) * time.Second
	expire := time.Duration(cfg.Greylist.ExpireSeconds) * time.Second
	g.mu.Lock()
	defer g.mu.Unlock()
	// shortcut: in-memory and capped (lost on restart); move to the host store if that hurts.
	if len(g.seen) > 100000 {
		for k, t := range g.seen {
			if now.Sub(t) >= expire {
				delete(g.seen, k)
			}
		}
	}
	known := false
	for _, k := range keys {
		if t, ok := g.seen[k]; ok && now.Sub(t) < expire {
			known = true
			if now.Sub(t) >= delay {
				return true
			}
		}
	}
	if !known && len(g.seen) < 200000 {
		for _, k := range keys {
			g.seen[k] = now
		}
	}
	return false
}

// greylistKeys returns the body and envelope hashes (greylist.lua data_key / envelope_key).
func greylistKeys(req *request, raw []byte) []string {
	rcpts := append([]string(nil), req.To...)
	sort.Strings(rcpts)
	from := req.From
	if from == "" {
		from = "<>"
	}
	meta := sha256.New()
	fmt.Fprintf(meta, "m|%s|%s|%s", maskIP(req.ClientIP), strings.ToLower(from), strings.ToLower(strings.Join(rcpts, ",")))
	body := sha256.New()
	b := strings.TrimLeft(string(raw[headerEnd(raw):]), "\r\n")
	if len(b) > 10240 {
		b = b[:10240]
	}
	fmt.Fprintf(body, "b|%s|%s", b, strings.ToLower(strings.Join(rcpts, ",")))
	return []string{hex.EncodeToString(meta.Sum(nil)), hex.EncodeToString(body.Sum(nil))}
}

// maskIP applies greylist.lua's default ipv4_mask=19 / ipv6_mask=64.
func maskIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(19, 32)).String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

// isLocalIP matches rspamd's rspamd_inet_address_is_local: loopback, private, link-local, CGNAT.
func isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return cgnat.Contains(ip)
}
