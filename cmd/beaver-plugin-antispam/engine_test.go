package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfigLoad(t *testing.T) {
	dir := t.TempDir()
	cfg, lists, err := loadConfig(dir)
	if err != nil || cfg.RBL.Enabled || cfg.URLRedirector.Enabled || len(lists.SpamTraps) != 0 {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	if v, _ := cfg.threshold("reject"); v != 15 {
		t.Fatalf("reject default %v", v)
	}
	os.MkdirAll(antispamDir(dir), 0o755)
	write := func(name, s string) { os.WriteFile(filepath.Join(antispamDir(dir), name), []byte(s), 0o644) }
	write(configFile, `{"actions":{"greylist":null,"reject":20},"scores":{"MISSING_MID":0},"rbl":{"enabled":true}}`)
	write(spamTrapsFile, "# traps\nTrap@Example.org\n\n@traps.example # catch-all\n")
	cfg, lists, err = loadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, on := cfg.threshold("greylist"); on {
		t.Error("greylist should be disabled by null")
	}
	if v, _ := cfg.threshold("add_header"); v != 6 {
		t.Error("add_header default lost on merge")
	}
	if !cfg.RBL.Enabled || cfg.RBL.TimeoutMs != 2000 || !lists.SpamTraps["trap@example.org"] || !lists.SpamTraps["@traps.example"] {
		t.Errorf("merge: %+v %v", cfg.RBL, lists.SpamTraps)
	}
	for _, bad := range []string{`{"actions":{"spam":1}}`, `{"gtube":"maybe"}`, `{"rbl":{"dqs_key":"ab.cd"}}`,
		`{"unknown":1}`, `{"spamtrap":{"action":"bounce"}}`, `{"actions":{"reject":-1}}`} {
		write(configFile, bad)
		if _, _, err := loadConfig(dir); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestActionsAndHeaders(t *testing.T) {
	cfg := defaultConfig()
	cfg.RBL.DQSKey = "secretkey123"
	cfg.Actions["rewrite_subject"] = f64(10)
	f := newFilter(cfg, Lists{}, nil)
	for _, tc := range []struct {
		score float64
		want  string
	}{{0, actNone}, {4, actGreylist}, {6.5, actAddHeader}, {10, actRewrite}, {15, actReject}} {
		if got := f.pickAction(tc.score, ""); got != tc.want {
			t.Errorf("%v: %s want %s", tc.score, got, tc.want)
		}
	}
	h := f.resultHeaders(verdict{score: 7, action: actAddHeader, symbols: []symScore{{name: "X", score: 7, opts: []string{"secretkey123.zen\r\nInjected: 1"}}}})
	if h["X-Spam-Flag"] != "YES" || !strings.HasPrefix(h["X-Spam-Status"], "Yes, score=7.00") {
		t.Errorf("headers: %v", h)
	}
	for k, v := range h {
		if strings.Contains(v, "secretkey123") || strings.ContainsAny(v, "\r\n") {
			t.Errorf("%s leaks or breaks lines: %q", k, v)
		}
	}
}

func TestGreylist(t *testing.T) {
	g := newGreylist()
	cfg := defaultConfig()
	t0 := time.Unix(1000, 0)
	keys := []string{"a", "b"}
	if g.pass(keys, t0, cfg) || g.pass(keys, t0.Add(time.Minute), cfg) {
		t.Fatal("passed before delay")
	}
	if !g.pass(keys, t0.Add(6*time.Minute), cfg) {
		t.Fatal("not passed after delay")
	}
	if g.pass([]string{"c"}, t0.Add(48*time.Hour), cfg) {
		t.Fatal("new key passed")
	}
	req := &request{ClientIP: "198.51.100.7", From: "a@example.com", To: []string{"b@example.org"}}
	k1 := greylistKeys(req, []byte("Subject: x\r\n\r\nbody"))
	req.ClientIP = "198.51.100.200" // same /19
	if k2 := greylistKeys(req, []byte("Subject: x\r\n\r\nbody")); k1[0] != k2[0] {
		t.Error("meta key should ignore host bits below /19")
	}
}

func writeBody(t *testing.T, raw []byte) string {
	p := filepath.Join(t.TempDir(), "m.eml")
	os.WriteFile(p, raw, 0o600)
	return p
}

func TestHandlePhases(t *testing.T) {
	cfg := defaultConfig()
	f := newFilter(cfg, Lists{}, nil)
	f.now = func() time.Time { return testNow }
	gtube := writeBody(t, eml(cleanHeaders, "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\n"))
	clean := writeBody(t, eml(cleanHeaders, "see you at noon\n"))
	base := request{ID: "1", Phase: "eom", ClientIP: "198.51.100.7", EHLODomain: "mail.example.com",
		IPRevResult: "pass", IPRevPTR: "mail.example.com", From: "alice@example.com", To: []string{"bob@example.org"},
		Auth: &authResults{SPFMailFrom: "pass", DKIM: "pass", DMARC: "pass"}}
	for _, tc := range []struct {
		name   string
		mod    func(r *request)
		action string
	}{
		{"connect accepts", func(r *request) { r.Phase = "connect"; r.BodyPath = gtube }, "accept"},
		{"gtube rejects", func(r *request) { r.BodyPath = gtube }, "reject"},
		{"submission skipped", func(r *request) { r.BodyPath = gtube; r.Listener = "submission" }, "accept"},
		{"authenticated skipped", func(r *request) { r.BodyPath = gtube; r.Authenticated = true }, "accept"},
		{"clean accepted", func(r *request) { r.BodyPath = clean }, "accept"},
	} {
		req := base
		tc.mod(&req)
		resp := handle(f, &req)
		if resp.Action != tc.action || resp.ID != "1" {
			t.Errorf("%s: %+v", tc.name, resp)
		}
		t.Logf("%s: %s %v %s", tc.name, resp.Action, resp.Score, resp.Headers["X-Spam-Symbols"])
		if tc.name == "clean accepted" && (resp.Headers["X-Spam-Status"] == "" || resp.Score >= 4) {
			t.Errorf("clean: %+v", resp)
		}
	}
}

func TestGreylistActionTempfails(t *testing.T) {
	cfg := defaultConfig()
	cfg.Scores["MISSING_MID"] = 4.5 // lands the message in the greylist band
	f := newFilter(cfg, Lists{}, nil)
	now := testNow
	f.now = func() time.Time { return now }
	req := &request{ID: "9", Phase: "eom", ClientIP: "198.51.100.7", From: "a@example.com", To: []string{"b@example.org"},
		EHLODomain: "mail.example.com", IPRevResult: "pass", IPRevPTR: "mail.example.com",
		BodyPath: writeBody(t, eml(with("Message-ID:-"), "hello\n"))}
	if r := handle(f, req); r.Action != "tempfail" {
		t.Fatalf("first: %+v", r)
	}
	now = now.Add(10 * time.Minute)
	if r := handle(f, req); r.Action != "accept" {
		t.Fatalf("retry: %+v", r)
	}
}

func TestRBL(t *testing.T) {
	answers := map[string][]string{
		"7.100.51.198.zen.spamhaus.org":   {"127.0.0.2", "127.0.0.11"},
		"9.100.51.198.zen.spamhaus.org":   {"127.255.255.254"},
		"spam.example.dbl.spamhaus.org":   {"127.0.1.2"},
		"weird.example.dbl.spamhaus.org":  {"127.0.1.200"},
		"broken.example.dbl.spamhaus.org": nil,
	}
	var calls int32
	newClient := func(cfg Config) *rblClient {
		c := newRBLClient(cfg)
		c.lookup = func(_ context.Context, name string) ([]string, error) {
			atomic.AddInt32(&calls, 1)
			if strings.HasPrefix(name, "broken.") {
				return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
			}
			if a, ok := answers[name]; ok {
				return a, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		return c
	}
	cfg := defaultConfig()
	c := newClient(cfg)
	targets := []rblTarget{{prefix: "RBL", origin: "from", value: "198.51.100.7"}, {prefix: "RECEIVED", origin: "received", value: "198.51.100.9"},
		{dbl: true, origin: "url", value: "spam.example"}, {dbl: true, origin: "url", value: "weird.example"},
		{dbl: true, origin: "url", value: "broken.example"}, {dbl: true, origin: "url", value: "clean.example"}}
	r := newResult()
	c.check(context.Background(), targets, r)
	expectSyms(t, r, []string{"RBL_SPAMHAUS_SBL", "RBL_SPAMHAUS_PBL", "DBL_SPAM"}, []string{"RECEIVED_SPAMHAUS", "DBL"})
	if len(r.syms) != 3 {
		t.Errorf("errors/blocked/unknown codes must not score: %v", symNames(r))
	}
	// Cached answers (NXDOMAIN included) cost no lookup; errors are retried.
	atomic.StoreInt32(&calls, 0)
	c.check(context.Background(), targets, newResult())
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("want only the failed query retried, got %d lookups", n)
	}
	// Per-message cap.
	cfg.RBL.MaxLookups = 2
	c = newClient(cfg)
	atomic.StoreInt32(&calls, 0)
	c.check(context.Background(), targets, newResult())
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("cap: %d lookups", n)
	}
	// DQS zones.
	cfg.RBL.DQSKey = "abcdefgh12"
	c = newRBLClient(cfg)
	if q := c.query(rblTarget{value: "2001:db8::1"}); q != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.abcdefgh12.zen.dq.spamhaus.net" {
		t.Errorf("ipv6 dqs query %s", q)
	}
	if q := c.query(rblTarget{dbl: true, value: "spam.example"}); q != "spam.example.abcdefgh12.dbl.dq.spamhaus.net" {
		t.Errorf("dbl dqs query %s", q)
	}
	if e := redactErr(errors.New("lookup x.abcdefgh12.zen.dq.spamhaus.net: timeout"), "x.abcdefgh12.zen.dq.spamhaus.net"); strings.Contains(e, "abcdefgh12") {
		t.Errorf("key leaked: %s", e)
	}
}

func TestRBLTargets(t *testing.T) {
	f := newFilter(defaultConfig(), Lists{Trusted: map[string]bool{"example.com": true}}, nil)
	m := parseMessage(eml(with("Received: from mx.example.net ([203.0.113.50]) by mail.example.org", "Reply-To: x@reply.example.net"),
		`see https://www.shop.example.co.uk/x and https://cdn.example.com/y`))
	req := &request{ClientIP: "198.51.100.7", From: "a@bounce.example.net", EHLODomain: "mx.example.net", IPRevPTR: "mx.example.net"}
	var got []string
	for _, t := range f.rblTargets(req, m, false) {
		got = append(got, t.origin+":"+t.value)
	}
	want := "from:198.51.100.7 received:203.0.113.50 from_smtp:bounce.example.net replyto:reply.example.net helo:mx.example.net rdns:mx.example.net url:example.co.uk"
	if strings.Join(got, " ") != want {
		t.Errorf("targets:\n got %s\nwant %s", strings.Join(got, " "), want)
	}
}

func TestPublicIPAndSafeControl(t *testing.T) {
	for s, want := range map[string]bool{"8.8.8.8": true, "2a00:1450::1": true, "127.0.0.1": false, "10.0.0.1": false,
		"169.254.169.254": false, "100.64.1.1": false, "192.0.2.1": false, "::1": false, "fd00::1": false,
		"64:ff9b::a00:1": false, "0.0.0.0": false, "224.0.0.1": false} {
		if publicIP(net.ParseIP(s)) != want {
			t.Errorf("publicIP(%s) != %v", s, want)
		}
	}
	if safeControl("tcp", "127.0.0.1:80", nil) == nil || safeControl("tcp", "8.8.8.8:25", nil) == nil || safeControl("tcp", "8.8.8.8:443", nil) != nil {
		t.Error("safeControl policy")
	}
	// The real client refuses a loopback server.
	srv := httptest.NewServer(http.RedirectHandler("http://example.net/", http.StatusFound))
	defer srv.Close()
	d := newRedirector(defaultConfig(), nil)
	if _, err := d.next(context.Background(), newURL(srv.URL, false)); err == nil {
		t.Error("loopback redirector was dialled")
	}
}

func TestRedirectorExpand(t *testing.T) {
	var hops int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hops, 1)
		http.Redirect(w, r, "http://hop"+string(rune('0'+n))+".example.net/", http.StatusMovedPermanently)
	}))
	defer srv.Close()
	cfg := defaultConfig()
	d := newRedirector(cfg, map[string]bool{"bit.example": true})
	// Test-only transport: every host goes to the local server (production dialing is SSRF-guarded).
	d.client.Transport = &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}}
	m := parseMessage(eml(cleanHeaders, "go http://bit.example/abc\n"))
	r := newResult()
	d.expand(context.Background(), m, r)
	var hosts []string
	for _, u := range m.urls {
		hosts = append(hosts, u.host)
	}
	if strings.Join(hosts, ",") != "bit.example,hop1.example.net,hop2.example.net" || !r.has("URL_REDIRECTOR_NESTED") {
		t.Errorf("hosts %v syms %v", hosts, symNames(r))
	}
}

func TestExampleConfigMatchesDefaults(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(antispamDir(dir), 0o755)
	for _, name := range []string{configFile, spamTrapsFile, trustedFile, redirectorsFile} {
		b, err := os.ReadFile(filepath.Join("examples", name+".example"))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(antispamDir(dir), name), b, 0o644)
	}
	cfg, lists, err := loadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, defaultConfig()) {
		t.Errorf("example differs from defaults:\n%+v\n%+v", cfg, defaultConfig())
	}
	if len(lists.SpamTraps) != 0 || len(lists.Trusted) != 0 || !lists.Redirectors["bit.ly"] {
		t.Errorf("example lists: %d traps, %d trusted, bit.ly=%v", len(lists.SpamTraps), len(lists.Trusted), lists.Redirectors["bit.ly"])
	}
}
