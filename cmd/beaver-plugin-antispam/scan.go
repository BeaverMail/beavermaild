// Offline account scan (dry-run) for beaver-plugin-antispam.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mailauth"
	"github.com/BeaverMail/beavermaild/plugin"
)

type scanParams struct {
	AccountEmail string
	ClientIP     string
	EHLODomain   string
	MailAuth     bool
	RBL          bool
	scanReportOpts
	Messages []scanMessage
}

type scanMessage struct {
	BodyPath string `json:"body_path"`
	Mailbox  string `json:"mailbox"`
	UID      uint32 `json:"uid"`
}

func parseScanParams(req plugin.CliRequest) (scanParams, error) {
	var raw map[string]string
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &raw); err != nil {
			return scanParams{}, err
		}
	}
	manifestPath := strings.TrimSpace(raw["manifest"])
	if manifestPath == "" {
		return scanParams{}, fmt.Errorf("scan manifest missing (host error)")
	}
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return scanParams{}, err
	}
	var man plugin.AccountScanManifest
	if err := json.Unmarshal(b, &man); err != nil {
		return scanParams{}, err
	}
	out := scanParams{
		AccountEmail: man.AccountEmail,
		Messages:     make([]scanMessage, len(man.Messages)),
	}
	for i, m := range man.Messages {
		out.Messages[i] = scanMessage{
			BodyPath: m.BodyPath,
			Mailbox:  m.Mailbox,
			UID:      m.UID,
		}
	}
	out.ClientIP = "127.0.0.1"
	out.EHLODomain = "scan.local"
	if v := strings.TrimSpace(raw["client_ip"]); v != "" {
		out.ClientIP = v
	}
	if v := strings.TrimSpace(raw["ehlo_domain"]); v != "" {
		out.EHLODomain = v
	}
	out.MailAuth = truthy(raw["mail_auth"])
	out.RBL = truthy(raw["rbl"])
	out.scanReportOpts = parseScanReportOpts(raw)
	return out, nil
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func runScan(dataDir string, req plugin.CliRequest) error {
	params, err := parseScanParams(req)
	if err != nil {
		return err
	}
	if len(params.Messages) == 0 {
		emitDone(fmt.Sprintf("account=%s scanned=0 (no messages)", params.AccountEmail))
		return nil
	}
	eng, err := newEngine(dataDir)
	if err != nil {
		return err
	}
	eng.maybeReload()

	var verifier *mailauth.Verifier
	if params.MailAuth {
		verifier = mailauth.New(mailauth.Config{
			Enabled:      true,
			SPFEnabled:   true,
			DKIMEnabled:  true,
			DMARCEnabled: true,
			ARCEnabled:   true,
		})
	}

	var total, rejected, spam, ham, reported int
	reporter, err := newScanReporter(params.scanReportOpts)
	if err != nil {
		return err
	}
	defer reporter.Close()

	for _, msg := range params.Messages {
		resp := eng.scanFile(msg, params, verifier)
		total++
		class := spamClass(resp)
		switch {
		case resp.Action == "reject" || resp.Action == "discard":
			rejected++
		case class == "spam":
			spam++
		default:
			ham++
		}
		if !includeScanRow(resp, params.scanReportOpts) {
			continue
		}
		meta := parseMessageMeta(msg.BodyPath)
		if err := reporter.WriteRow(msg, meta, resp); err != nil {
			return err
		}
		reported++
	}
	writeScanReportPathHint(params.OutputPath)
	emitDone(fmt.Sprintf("account=%s scanned=%d ham=%d spam=%d rejected=%d reported=%d (dry-run, no delivery)",
		params.AccountEmail, total, ham, spam, rejected, reported))
	return nil
}

func spamClass(resp filterResp) string {
	if strings.EqualFold(resp.Headers["X-Spam-Flag"], "YES") {
		return "spam"
	}
	if resp.Headers["X-Spam-Status"] != "" {
		return "ham"
	}
	if resp.Action == "reject" || resp.Action == "discard" {
		return resp.Action
	}
	return "ham"
}

func (e *engine) scanFile(msg scanMessage, opts scanParams, verifier *mailauth.Verifier) filterResp {
	cfg := e.store.get()
	if !cfg.Enabled {
		return filterResp{Action: "accept"}
	}
	id := fmt.Sprintf("%s-%d", msg.Mailbox, msg.UID)
	from, to := parseEnvelope(msg.BodyPath)
	var state mailauth.SessionState

	if opts.ClientIP != "" {
		scanCfg := cfg
		if !opts.RBL {
			scanCfg.RBL.Enabled = false
		}
		if r := e.handleConnect(filterReq{ID: id, Phase: "connect", ClientIP: opts.ClientIP}, scanCfg); r.Action != "accept" {
			return r
		}
	}
	if opts.EHLODomain != "" {
		if verifier != nil {
			if ip := net.ParseIP(opts.ClientIP); ip != nil {
				state.SPFEhlo = verifier.CheckSPF(context.Background(), ip, "", opts.EHLODomain)
			}
		}
		if r := e.handleHelo(filterReq{
			ID: id, Phase: "helo", ClientIP: opts.ClientIP, EHLODomain: opts.EHLODomain,
			Auth: scanWireAuth(state),
		}, cfg); r.Action != "accept" {
			return r
		}
	}
	if from != "" {
		if verifier != nil {
			if ip := net.ParseIP(opts.ClientIP); ip != nil {
				state.SPFMailFrom = verifier.CheckSPF(context.Background(), ip, from, opts.EHLODomain)
			}
		}
		if r := e.handleMail(filterReq{
			ID: id, Phase: "mail", From: from, ClientIP: opts.ClientIP,
			EHLODomain: opts.EHLODomain, Auth: scanWireAuth(state),
		}, cfg); r.Action != "accept" {
			return r
		}
	}
	if to != "" {
		if r := e.handleRcpt(filterReq{ID: id, Phase: "rcpt", From: from, To: []string{to}}, cfg); r.Action != "accept" {
			return r
		}
	}

	req := filterReq{
		ID:         id,
		Phase:      "eom",
		From:       from,
		To:         []string{to},
		BodyPath:   msg.BodyPath,
		ClientIP:   opts.ClientIP,
		EHLODomain: opts.EHLODomain,
	}
	if verifier != nil && verifier.Enabled() {
		state = verifier.FinishEom(context.Background(), msg.BodyPath, from, opts.EHLODomain, state)
		req.Auth = scanWireAuth(state)
	}
	return e.handleEom(req, cfg)
}

// scanWireAuth maps scan verifier state to the daemon wire.
func scanWireAuth(state mailauth.SessionState) *wireAuth {
	if state == (mailauth.SessionState{}) {
		return nil
	}
	return &wireAuth{
		SPFEhlo:     state.SPFEhlo,
		SPFMailFrom: state.SPFMailFrom,
		DKIM:        state.DKIM,
		DMARC:       state.DMARC,
		DMARCPolicy: state.DMARCPolicy,
		ARC:         state.ARC,
	}
}

func parseEnvelope(path string) (from, to string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "from:"):
			from = parseAddr(strings.TrimSpace(line[5:]))
		case strings.HasPrefix(lower, "to:"):
			to = parseAddr(strings.TrimSpace(line[3:]))
		}
	}
	return from, to
}

func parseAddr(s string) string {
	if i := strings.IndexByte(s, '<'); i >= 0 {
		if j := strings.IndexByte(s[i:], '>'); j > 0 {
			return strings.TrimSpace(s[i+1 : i+j])
		}
	}
	return strings.TrimSpace(s)
}
