// Harvest URLs, emails, domains, and IPs from message text (Phase 3).
package main

import (
	"net"
	"regexp"
	"strings"
)

var (
	reURL      = regexp.MustCompile(`https?://[^\s<>"']+`)
	reEmail    = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reBareIP   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reHTMLTag  = regexp.MustCompile(`(?i)<[^>]+>`)
	reDataURI  = regexp.MustCompile(`(?i)data:[^"'\s>]+`)
	reMetaRefresh = regexp.MustCompile(`(?i)http-equiv=["']?refresh["']?`)
)

type harvestSet struct {
	urls     map[string]struct{}
	emails   map[string]struct{}
	domains  map[string]struct{}
	ips      map[string]struct{}
	plain    string
	html     string
	hasHTML  bool
	hasPlain bool
}

func newHarvestSet() *harvestSet {
	return &harvestSet{
		urls:    make(map[string]struct{}),
		emails:  make(map[string]struct{}),
		domains: make(map[string]struct{}),
		ips:     make(map[string]struct{}),
	}
}

func (h *harvestSet) addURL(raw string) {
	raw = strings.TrimRight(raw, ".,);]")
	if raw == "" {
		return
	}
	h.urls[strings.ToLower(raw)] = struct{}{}
	host := urlHost(raw)
	if host != "" {
		h.domains[domainSLD(host)] = struct{}{}
	}
}

func (h *harvestSet) addEmail(e string) {
	e = strings.ToLower(strings.TrimSpace(e))
	if e != "" {
		h.emails[e] = struct{}{}
		pe := parseEmail(e)
		if pe.domain != "" {
			h.domains[pe.sld] = struct{}{}
		}
	}
}

func (h *harvestSet) addIP(ip string) {
	if net.ParseIP(ip) != nil {
		h.ips[ip] = struct{}{}
	}
}

func harvestFromText(h *harvestSet, s string) {
	for _, m := range reURL.FindAllString(s, -1) {
		h.addURL(m)
	}
	for _, m := range reEmail.FindAllString(s, -1) {
		h.addEmail(m)
	}
	for _, m := range reBareIP.FindAllString(s, -1) {
		h.addIP(m)
	}
}

func urlHost(raw string) string {
	raw = strings.TrimPrefix(strings.ToLower(raw), "http://")
	raw = strings.TrimPrefix(raw, "https://")
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '@'); i >= 0 {
		raw = raw[i+1:]
	}
	raw, _, _ = strings.Cut(raw, ":")
	return strings.Trim(raw, "[]")
}

func htmlToText(html string) string {
	s := reHTMLTag.ReplaceAllString(html, " ")
	return strings.Join(strings.Fields(s), " ")
}
