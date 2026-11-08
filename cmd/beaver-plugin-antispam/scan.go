// `beaver filter scan`: score stored messages of one account as if they arrived over SMTP.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/plugin"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
)

type scanRow struct {
	Mailbox string     `json:"mailbox"`
	UID     uint32     `json:"uid"`
	Score   float64    `json:"score"`
	Action  string     `json:"action"`
	Symbols []scanSymb `json:"symbols"`
}

type scanSymb struct {
	Name    string   `json:"name"`
	Score   float64  `json:"score"`
	Options []string `json:"options,omitempty"`
}

func keepRow(only string, minScore float64, v verdict) bool {
	if v.score < minScore {
		return false
	}
	switch only {
	case "spam":
		return v.action == actAddHeader || v.action == actRewrite || v.action == actReject
	case "reject":
		return v.action == actReject
	case "non-ham":
		return v.action != actNone
	}
	return true
}

func runScan(p map[string]string) (string, error) {
	switch p["only"] {
	case "", "spam", "reject", "non-ham":
	default:
		return "", fmt.Errorf("-only: want spam, reject or non-ham")
	}
	minScore := -1e9
	if s := p["min_score"]; s != "" {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return "", fmt.Errorf("-min-score: %w", err)
		}
		minScore = v
	}
	if ip := p["client_ip"]; ip != "" && net.ParseIP(ip) == nil {
		return "", fmt.Errorf("-client-ip: invalid IP %q", ip)
	}
	b, err := os.ReadFile(p["manifest"])
	if err != nil {
		return "", fmt.Errorf("manifest: %w", err)
	}
	var man plugin.AccountScanManifest
	if err := json.Unmarshal(b, &man); err != nil {
		return "", fmt.Errorf("manifest: %w", err)
	}
	cfg, lists, err := loadConfig(dataDir())
	if err != nil {
		return "", err
	}
	// Bulk scans stay off the network unless asked: no redirector or HELO/MAIL FROM DNS probing.
	cfg.RBL.Enabled = p["rbl"] == "true"
	cfg.URLRedirector.Enabled = false
	cfg.HFilter.DNSChecks = false
	f := newFilter(cfg, lists, nil)

	base := request{Phase: "eom", To: []string{man.AccountEmail}, ClientIP: p["client_ip"], EHLODomain: p["ehlo_domain"]}
	if base.ClientIP != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		names, err := net.DefaultResolver.LookupAddr(ctx, base.ClientIP)
		cancel()
		switch {
		case err == nil && len(names) > 0:
			base.IPRevResult, base.IPRevPTR = "pass", strings.TrimSuffix(names[0], ".")
		case isNotFound(err):
			base.IPRevResult = "none"
		case err != nil:
			base.IPRevResult = "temperror"
		}
	}

	var out io.Writer
	var file *os.File
	if path := p["output"]; path != "" {
		if file, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err != nil {
			return "", err
		}
		defer file.Close()
		out = file
		fmt.Fprintln(out, "mailbox\tuid\tscore\taction\tsymbols")
	} else if p["json"] != "true" {
		emitReport("mailbox\tuid\tscore\taction\tsymbols")
	}

	counts := map[string]int{}
	shown := 0
	for _, msg := range man.Messages {
		raw, err := readBody(msg.BodyPath)
		if err != nil {
			logf("scan %s/%d: %v", msg.Mailbox, msg.UID, err)
			continue
		}
		req := base
		req.From = returnPath(raw)
		if p["mail_auth"] == "true" {
			req.Auth = verifyAuth(raw)
		}
		f.now = func() time.Time { return receivedTime(raw) }
		v := f.evaluate(context.Background(), &req, raw)
		counts[v.action]++
		if !keepRow(p["only"], minScore, v) {
			continue
		}
		shown++
		row := scanRow{Mailbox: msg.Mailbox, UID: msg.UID, Score: round2(v.score), Action: v.action}
		var syms []string
		for _, s := range v.symbols {
			row.Symbols = append(row.Symbols, scanSymb{Name: s.name, Score: round2(s.score), Options: s.opts})
			syms = append(syms, fmt.Sprintf("%s(%.2f)", s.name, s.score))
		}
		line := fmt.Sprintf("%s\t%d\t%.2f\t%s\t%s", row.Mailbox, row.UID, row.Score, row.Action, strings.Join(syms, ","))
		switch {
		case out != nil:
			fmt.Fprintln(out, line)
		case p["json"] == "true":
			b, _ := json.Marshal(row)
			fmt.Fprintf(os.Stderr, "%s\n", b)
		default:
			emitReport(line)
		}
	}
	return fmt.Sprintf("scanned=%d shown=%d reject=%d add_header=%d rewrite_subject=%d greylist=%d no_action=%d",
		len(man.Messages), shown, counts[actReject], counts[actAddHeader], counts[actRewrite], counts[actGreylist], counts[actNone]), nil
}

func headerValue(raw []byte, name string) string {
	hdrs := parseHeaderBlock(string(raw[:headerEnd(raw)]))
	for _, h := range hdrs {
		if strings.EqualFold(h.name, name) {
			return h.raw
		}
	}
	return ""
}

func headerEnd(raw []byte) int {
	end := len(raw)
	for _, sep := range []string{"\r\n\r\n", "\n\n"} {
		if i := bytes.Index(raw, []byte(sep)); i >= 0 && i < end {
			end = i
		}
	}
	return end
}

// returnPath is the envelope sender recorded by the delivering MTA.
func returnPath(raw []byte) string {
	return strings.Trim(headerValue(raw, "Return-Path"), "<> ")
}

// receivedTime is the date of the topmost Received header (our receipt), else now.
func receivedTime(raw []byte) time.Time {
	if v := headerValue(raw, "Received"); v != "" {
		if i := strings.LastIndexByte(v, ';'); i >= 0 {
			if t, err := mail.ParseDate(strings.TrimSpace(v[i+1:])); err == nil {
				return t
			}
		}
	}
	return time.Now()
}

// verifyAuth re-runs DKIM and DMARC (DKIM alignment only: the original client IP is unknown, so no SPF).
func verifyAuth(raw []byte) *authResults {
	a := &authResults{DKIM: "none", DMARC: "none"}
	verifs, err := dkim.Verify(bytes.NewReader(raw))
	var passDomains []string
	switch {
	case err != nil:
		a.DKIM = "permerror"
	case len(verifs) > 0:
		a.DKIM = "fail"
		for _, v := range verifs {
			switch {
			case v.Err == nil:
				a.DKIM = "pass"
				passDomains = append(passDomains, strings.ToLower(v.Domain))
			case dkim.IsTempFail(v.Err) && a.DKIM != "pass":
				a.DKIM = "temperror"
			case dkim.IsPermFail(v.Err) && a.DKIM == "fail":
				a.DKIM = "permerror"
			}
		}
	}
	m := parseMessage(raw)
	from := fromDomain(m)
	if from == "" {
		return a
	}
	policyDomain := from
	rec, err := dmarc.Lookup(from)
	if errors.Is(err, dmarc.ErrNoPolicy) && esld(from) != from {
		policyDomain = esld(from)
		rec, err = dmarc.Lookup(policyDomain)
	}
	switch {
	case errors.Is(err, dmarc.ErrNoPolicy):
		return a
	case err != nil && dmarc.IsTempFail(err):
		a.DMARC = "temperror"
		return a
	case err != nil:
		a.DMARC = "permerror"
		return a
	}
	for _, d := range passDomains {
		if d == from || (rec.DKIMAlignment != dmarc.AlignmentStrict && esld(d) == esld(from)) {
			a.DMARC = "pass"
			return a
		}
	}
	a.DMARC = "fail"
	a.DMARCPolicy = string(rec.Policy)
	if policyDomain != from && rec.SubdomainPolicy != "" {
		a.DMARCPolicy = string(rec.SubdomainPolicy)
	}
	return a
}
