package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// eml joins header lines and a body into a CRLF message.
func eml(headers []string, body string) []byte {
	return []byte(strings.Join(headers, "\r\n") + "\r\n\r\n" + strings.ReplaceAll(body, "\n", "\r\n"))
}

var cleanHeaders = []string{
	"From: Alice <alice@example.com>",
	"To: Bob <bob@example.org>",
	"Subject: Lunch tomorrow",
	"Date: Mon, 02 Nov 2026 10:00:00 +0000",
	"Message-ID: <abc123@mail.example.com>",
	"MIME-Version: 1.0",
	"Content-Type: text/plain; charset=utf-8",
}

var testNow = time.Date(2026, 11, 2, 10, 30, 0, 0, time.UTC)

func with(over ...string) []string {
	out := append([]string(nil), cleanHeaders...)
	for _, o := range over {
		name, _, _ := strings.Cut(o, ":")
		replaced := false
		for i, h := range out {
			if hn, _, _ := strings.Cut(h, ":"); strings.EqualFold(hn, name) {
				if strings.HasSuffix(o, ":-") {
					out = append(out[:i], out[i+1:]...)
				} else {
					out[i] = o
				}
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, o)
		}
	}
	return out
}

func runChecks(raw []byte, fn func(m *message, r *result)) *result {
	r := newResult()
	fn(parseMessage(raw), r)
	return r
}

func expectSyms(t *testing.T, r *result, want, not []string) {
	t.Helper()
	for _, s := range want {
		if !r.has(s) {
			t.Errorf("missing %s; got %v", s, symNames(r))
		}
	}
	for _, s := range not {
		if r.has(s) {
			t.Errorf("unexpected %s", s)
		}
	}
}

func symNames(r *result) []string {
	var out []string
	for k := range r.syms {
		out = append(out, k)
	}
	return out
}

func TestHeaderChecks(t *testing.T) {
	all := func(m *message, r *result) {
		checkMID(m, r)
		checkDate(m, testNow, r)
		checkSubject(m, r)
		checkHeaders(m, &request{From: "alice@example.com"}, r)
	}
	tests := []struct {
		name      string
		hdrs      []string
		want, not []string
	}{
		{"clean", cleanHeaders, nil, []string{"MISSING_MID", "MISSING_DATE", "DATE_IN_PAST", "SUBJ_ALL_CAPS", "INVALID_MSGID", "MULTIPLE_UNIQUE_HEADERS"}},
		{"missing mid", with("Message-ID:-"), []string{"MISSING_MID"}, nil},
		{"mid no brackets bare ip", with("Message-ID: abc@192.0.2.1"), []string{"MID_MISSING_BRACKETS"}, []string{"MID_BARE_IP"}},
		{"mid bare ip", with("Message-ID: <abc@192.0.2.1>"), []string{"MID_BARE_IP"}, nil},
		{"mid not fqdn", with("Message-ID: <abc@localhost>"), []string{"MID_RHS_NOT_FQDN"}, nil},
		{"mid contains from", with("Message-ID: <alice@example.com.1@example.com>"), []string{"MID_CONTAINS_FROM"}, nil},
		{"mid realm eq from user", with("Message-ID: <x@alice>"), []string{"MID_END_EQ_FROM_USER_PART"}, nil},
		{"invalid msgid", with("Message-ID: <a b@c d>"), []string{"INVALID_MSGID"}, nil},
		{"missing date", with("Date:-"), []string{"MISSING_DATE"}, nil},
		{"invalid date", with("Date: yesterday"), []string{"INVALID_DATE"}, nil},
		{"future date", with("Date: Mon, 02 Nov 2026 16:00:00 +0000"), []string{"DATE_IN_FUTURE"}, nil},
		{"past date", with("Date: Mon, 26 Oct 2026 10:00:00 +0000"), []string{"DATE_IN_PAST"}, nil},
		{"caps subject", with("Subject: Re: FREE MONEY NOW"), []string{"SUBJ_ALL_CAPS"}, nil},
		{"long subject", with("Subject: " + strings.Repeat("ab ", 70)), []string{"LONG_SUBJ"}, nil},
		{"fake reply", with("Subject: RE: your invoice"), []string{"FAKE_REPLY"}, nil},
		{"real reply", with("Subject: RE: your invoice", "In-Reply-To: <x@example.com>"), nil, []string{"FAKE_REPLY"}},
		{"subject ends question", with("Subject: are you there?"), []string{"SUBJECT_ENDS_QUESTION"}, nil},
		{"subject currency", with("Subject: win €100"), []string{"SUBJECT_HAS_CURRENCY"}, nil},
		{"subject needs encoding", with("Subject: caf\xe9"), []string{"SUBJECT_NEEDS_ENCODING"}, nil},
		{"subject excess b64", with("Subject: =?utf-8?B?SGVsbG8=?="), []string{"SUBJ_EXCESS_BASE64"}, nil},
		{"subject b64 needed", with("Subject: =?utf-8?B?Y2Fmw6k=?="), nil, []string{"SUBJ_EXCESS_BASE64"}},
		{"missing subject", with("Subject:-"), []string{"MISSING_SUBJECT"}, nil},
		{"empty subject", with("Subject: "), []string{"EMPTY_SUBJECT"}, nil},
		{"missing to", with("To:-"), []string{"MISSING_TO"}, nil},
		{"undisclosed", with("To: undisclosed-recipients:;"), []string{"R_UNDISC_RCPT"}, nil},
		{"to wrapped", with("To: Bob < bob@example.org >"), []string{"TO_WRAPPED_IN_SPACES"}, nil},
		{"to dn recipients", with("To: Recipients <bob@example.org>"), []string{"TO_DN_RECIPIENTS"}, nil},
		{"http in from", with("From: \"http://win.example\" <alice@example.com>"), []string{"R_HTTP_URL_IN_FROM"}, nil},
		{"no space in from", with("From: Alice<alice@example.com>"), []string{"R_NO_SPACE_IN_FROM"}, nil},
		{"from empty delimiter", with("From:alice@example.com"), []string{"HEADER_FROM_EMPTY_DELIMITER"}, nil},
		{"from title", with("From: Mr. Smith <smith@example.com>"), []string{"FROM_NAME_HAS_TITLE"}, nil},
		{"from dn eq addr", with(`From: "alice@example.com" <alice@example.com>`), []string{"FROM_DN_EQ_ADDR"}, nil},
		{"multiple from", with("From: a@example.com, b@example.com"), []string{"MULTIPLE_FROM"}, nil},
		{"invalid from", with("From: <<<"), []string{"FROM_INVALID"}, nil},
		{"missing from", with("From:-"), []string{"MISSING_FROM"}, nil},
		{"duplicate subject", append(with(), "Subject: again"), []string{"MULTIPLE_UNIQUE_HEADERS"}, nil},
		{"replyto eq to", with("Reply-To: bob@example.org"), []string{"REPLYTO_EQ_TO_ADDR"}, nil},
		{"replyto unparseable", with("Reply-To: <<<"), []string{"REPLYTO_UNPARSEABLE"}, nil},
		{"mv case", with("MIME-Version:-", "Mime-Version: 1.0"), []string{"MV_CASE"}, nil},
		{"list unsub", with("List-Unsubscribe: <mailto:u@example.com>"), []string{"HAS_LIST_UNSUB"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectSyms(t, runChecks(eml(tc.hdrs, "hello\n"), all), tc.want, tc.not)
		})
	}
}

func TestMultipleUniqueHeadersFactor(t *testing.T) {
	r := runChecks(eml(append(with(), "Date: Tue, 03 Nov 2026 10:00:00 +0000"), "x"), func(m *message, r *result) { checkUniqueHeaders(m, r) })
	if h := r.syms["MULTIPLE_UNIQUE_HEADERS"]; h == nil || h.factor != 0.1 {
		t.Fatalf("want factor 0.1 for duplicate Date, got %+v", h)
	}
}

func TestSessionChecks(t *testing.T) {
	tests := []struct {
		name      string
		req       request
		want, not []string
	}{
		{"good helo and ptr", request{EHLODomain: "mail.example.com", IPRevResult: "pass", IPRevPTR: "mail.example.com"}, nil,
			[]string{"HFILTER_HELO_5", "RDNS_NONE", "HFILTER_HOSTNAME_UNKNOWN"}},
		{"helo bad ip", request{EHLODomain: "[192.168.1.1]"}, []string{"HFILTER_HELO_BADIP"}, nil},
		{"helo bare ip", request{EHLODomain: "[198.18.0.1]"}, []string{"HFILTER_HELO_BAREIP"}, nil},
		{"helo no dot", request{EHLODomain: "DESKTOP"}, []string{"HFILTER_HELO_5"}, nil},
		{"helo .local", request{EHLODomain: "box.local"}, []string{"HFILTER_HELO_5"}, nil},
		{"dynamic ptr", request{EHLODomain: "mail.example.com", IPRevResult: "pass", IPRevPTR: "dsl-198-51-100-7.dynamic.example.net"}, []string{"HFILTER_HOSTNAME_5"}, nil},
		{"no ptr", request{IPRevResult: "none"}, []string{"RDNS_NONE", "HFILTER_HOSTNAME_UNKNOWN"}, nil},
		{"ptr dnsfail", request{IPRevResult: "temperror"}, []string{"RDNS_DNSFAIL"}, []string{"RDNS_NONE"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newResult()
			checkHelloHost(&tc.req, r)
			expectSyms(t, r, tc.want, tc.not)
		})
	}
}

func TestAuthMapping(t *testing.T) {
	tests := []struct {
		a    authResults
		want []string
	}{
		{authResults{SPFMailFrom: "pass", DKIM: "pass", DMARC: "pass", ARC: "pass"}, []string{"R_SPF_ALLOW", "R_DKIM_ALLOW", "DMARC_POLICY_ALLOW", "ARC_ALLOW"}},
		{authResults{SPFMailFrom: "fail", DKIM: "fail", DMARC: "fail", DMARCPolicy: "reject"}, []string{"R_SPF_FAIL", "R_DKIM_REJECT", "DMARC_POLICY_REJECT"}},
		{authResults{SPFEhlo: "softfail", DMARC: "fail", DMARCPolicy: "quarantine"}, []string{"R_SPF_SOFTFAIL", "DMARC_POLICY_QUARANTINE"}},
		{authResults{DMARC: "fail", DMARCPolicy: "none"}, []string{"DMARC_POLICY_SOFTFAIL"}},
		{authResults{SPFMailFrom: "temperror", DKIM: "temperror", DMARC: "temperror", ARC: "temperror"}, []string{"R_SPF_DNSFAIL", "R_DKIM_TEMPFAIL", "DMARC_DNSFAIL", "ARC_DNSFAIL"}},
		{authResults{SPFMailFrom: "permerror", DKIM: "permerror", ARC: "invalid"}, []string{"R_SPF_PERMFAIL", "R_DKIM_PERMFAIL", "ARC_INVALID"}},
		{authResults{SPFMailFrom: "none", DKIM: "none", DMARC: "none", ARC: "none"}, []string{"R_SPF_NA", "R_DKIM_NA", "DMARC_NA", "ARC_NA"}},
	}
	for _, tc := range tests {
		r := newResult()
		checkAuth(&tc.a, r)
		expectSyms(t, r, tc.want, nil)
		if len(r.syms) != len(tc.want) {
			t.Errorf("%+v: got %v", tc.a, symNames(r))
		}
	}
}

func TestSpamtrapAndWhitelist(t *testing.T) {
	cfg := defaultConfig()
	cfg.Spamtrap.Action = "discard"
	f := newFilter(cfg, Lists{SpamTraps: map[string]bool{"trap@example.org": true, "@traps.example": true},
		Trusted: map[string]bool{"example.com": true}}, nil)
	for _, tc := range []struct {
		to   []string
		want bool
	}{{[]string{"trap@example.org"}, true}, {[]string{"x@traps.example"}, true}, {[]string{"bob@example.org"}, false},
		{[]string{"trap@example.org", "bob@example.org"}, false}} {
		r := newResult()
		f.checkSpamtrap(tc.to, r)
		if r.has("SPAMTRAP") != tc.want || (tc.want && r.forced != actDiscard) {
			t.Errorf("%v: got %v forced=%q", tc.to, symNames(r), r.forced)
		}
	}
	m := parseMessage(eml(with("From: a@news.example.com"), "x"))
	for _, tc := range []struct{ dmarc, want string }{{"pass", "WHITELIST_DMARC"}, {"fail", "BLACKLIST_DMARC"}} {
		r := newResult()
		f.checkWhitelist(m, &authResults{DMARC: tc.dmarc}, r)
		expectSyms(t, r, []string{tc.want}, nil)
	}
}

func TestIsFQDN(t *testing.T) {
	for s, want := range map[string]bool{"mail.example.com": true, "a.io": true, "localhost": false, "-a.example.com": false,
		"a_b.example.com": false, "x.c": false, "mail.example.com.": true} {
		if isFQDN(s) != want {
			t.Errorf("isFQDN(%q) != %v", s, want)
		}
	}
}

func TestHFilterURLOnly(t *testing.T) {
	r := runChecks(eml(cleanHeaders, "https://click.example.net/a/very/long/path/to/somewhere\n"), func(m *message, r *result) {
		checkHFilterMessage(&request{From: "a@example.com"}, m, r)
	})
	expectSyms(t, r, []string{"HFILTER_URL_ONLY", "HFILTER_URL_ONELINE"}, nil)
}

func zipWith(names ...string) string {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, n := range names {
		w, _ := zw.Create(n)
		w.Write([]byte("x"))
	}
	zw.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func mixedMsg(parts ...string) []byte {
	body := "--B\n" + strings.Join(parts, "\n--B\n") + "\n--B--\n"
	return eml(with("Content-Type: multipart/mixed; boundary=B"), body)
}

func attachment(name, ctype, b64 string) string {
	return "Content-Type: " + ctype + "; name=\"" + name + "\"\nContent-Disposition: attachment; filename=\"" + name +
		"\"\nContent-Transfer-Encoding: base64\n\n" + b64
}

func TestMIMETypes(t *testing.T) {
	text := "Content-Type: text/plain; charset=utf-8\n\nsee attached"
	tests := []struct {
		name string
		raw  []byte
		want []string
		not  []string
	}{
		{"pdf ok", mixedMsg(text, attachment("invoice.pdf", "application/pdf", "eA==")), nil, []string{"MIME_BAD_EXTENSION", "MIME_DOUBLE_BAD_EXTENSION"}},
		{"exe", mixedMsg(text, attachment("setup.exe", "application/octet-stream", "eA==")), []string{"MIME_BAD_EXTENSION"}, nil},
		{"double ext", mixedMsg(text, attachment("invoice.pdf.exe", "application/octet-stream", "eA==")), []string{"MIME_DOUBLE_BAD_EXTENSION"}, nil},
		{"dated name", mixedMsg(text, attachment("report.2026.pdf", "application/pdf", "eA==")), nil, []string{"MIME_DOUBLE_BAD_EXTENSION"}},
		{"zip.gz cloak", mixedMsg(text, attachment("docs.zip.gz", "application/gzip", "eA==")), []string{"MIME_ARCHIVE_IN_ARCHIVE"}, nil},
		{"html as pdf", mixedMsg(text, attachment("page.html", "application/pdf", "eA==")), []string{"MIME_BAD_ATTACHMENT"}, nil},
		{"zip with vbs", mixedMsg(text, attachment("a.zip", "application/zip", zipWith("run.vbs"))), []string{"MIME_BAD_EXTENSION"}, nil},
		{"zip in zip", mixedMsg(text, attachment("a.zip", "application/zip", zipWith("inner.zip", "b.txt"))), []string{"MIME_ARCHIVE_IN_ARCHIVE"}, nil},
		{"rtl name", mixedMsg(text, attachment("invoice‮fdp.exe", "application/octet-stream", "eA==")), []string{"MIME_BAD_UNICODE"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectSyms(t, runChecks(tc.raw, func(m *message, r *result) { checkMIMETypes(m, r) }), tc.want, tc.not)
		})
	}
}

func TestMIMEStructure(t *testing.T) {
	alt := eml(with("Content-Type: multipart/alternative; boundary=B"),
		"--B\nContent-Type: text/html\n\n<p>hi</p>\n--B--\n")
	r := runChecks(alt, func(m *message, r *result) { checkMIMEParts(m, r); checkHTML(m, r) })
	expectSyms(t, r, []string{"MIME_MA_MISSING_TEXT", "MIME_HTML_ONLY"}, []string{"MIME_MA_MISSING_HTML"})

	noVer := eml(with("MIME-Version:-"), "x")
	expectSyms(t, runChecks(noVer, func(m *message, r *result) { checkMIMEParts(m, r) }), []string{"MISSING_MIME_VERSION"}, nil)

	b64 := eml(with("Content-Transfer-Encoding: base64"), "aGVsbG8gd29ybGQ=")
	expectSyms(t, runChecks(b64, func(m *message, r *result) { checkMIMEParts(m, r) }), []string{"MIME_BASE64_TEXT", "MIME_BASE64_TEXT_BOGUS"}, nil)

	octet := mixedMsg("Content-Type: text/plain\n\nx", "Content-Type: application/octet-stream\n\nbinary")
	expectSyms(t, runChecks(octet, func(m *message, r *result) { checkMIMEParts(m, r) }), []string{"CTYPE_MISSING_DISPOSITION"}, nil)
}

func TestGTUBE(t *testing.T) {
	body := "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\n"
	for _, tc := range []struct{ policy, body, forced string }{
		{"reject", body, actReject}, {"disabled", body, ""}, {"reject", "Y" + body[1:], ""}, {"all", "Y" + body[1:], actAddHeader},
	} {
		r := runChecks(eml(cleanHeaders, tc.body), func(m *message, r *result) { checkGTUBE(tc.policy, m, r) })
		if r.forced != tc.forced {
			t.Errorf("%s/%c: forced=%q want %q", tc.policy, tc.body[0], r.forced, tc.forced)
		}
	}
}

func htmlMsg(h string) []byte {
	return eml(with("Content-Type: text/html; charset=utf-8"), h)
}

func TestHTMLAndURLChecks(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
		not  []string
	}{
		{"http to ip", `<a href="http://198.51.100.7/login">click</a>`, []string{"HTTP_TO_IP", "URL_NUMERIC_IP"}, nil},
		{"http to https", `<a href="http://example.net/">https://example.net/</a>`, []string{"HTTP_TO_HTTPS"}, nil},
		{"ext css", `<link rel="stylesheet" href="https://cdn.example.net/x.css?v=1"><p>hi</p>`, []string{"EXT_CSS"}, nil},
		{"short link img", `<a href="https://shop.example.net/"><img src="cid:1" width="300" height="200"></a>`, []string{"HTML_SHORT_LINK_IMG_1"}, nil},
		{"empty image", `<img src="https://img.example.net/a.png" width="400" height="300">`, []string{"R_EMPTY_IMAGE"}, nil},
		{"user password", `<a href="https://user:pw@example.net/">x</a>`, []string{"URL_USER_PASSWORD"}, nil},
		{"private ip", `<a href="http://10.1.2.3/">x</a>`, []string{"URL_NUMERIC_PRIVATE_IP"}, []string{"URL_NUMERIC_IP"}},
		{"no tld", `<a href="http://intranet/">x</a>`, []string{"URL_NO_TLD"}, nil},
		{"suspicious tld", `<a href="http://prize.tk/">x</a>`, []string{"URL_SUSPICIOUS_TLD"}, nil},
		{"many dots", `<a href="http://a.b.c.d.e.f.g.example.com/">x</a>`, []string{"URL_EXCESSIVE_DOTS"}, nil},
		{"query urls", `<a href="https://r.example.net/?u=https://a.example&v=http://b.example">x</a>`, []string{"URL_QUERY_MULTIPLE_URLS"}, nil},
		{"phishing", `<a href="https://evil-login.example.net/">https://www.paypal.com/signin</a>`, []string{"PHISHING", "URL_DISPLAY_MISMATCH"}, nil},
		{"same site", `<a href="https://news.example.com/x">https://www.example.com/</a>`, nil, []string{"PHISHING", "URL_DISPLAY_MISMATCH"}},
		{"plain anchor", `<a href="https://example.net/">read more</a>`, nil, []string{"PHISHING", "HTTP_TO_IP", "URL_NO_TLD"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runChecks(htmlMsg(tc.html), func(m *message, r *result) { checkHTML(m, r); checkURLs(m, r); checkPhishing(m, nil, r) })
			expectSyms(t, r, tc.want, tc.not)
		})
	}
}

func TestPhishWeight(t *testing.T) {
	if w := phishWeight("example.com", "example.com", true); w != 0 {
		t.Errorf("same: %v", w)
	}
	if w := phishWeight("paypa1.com", "paypal.com", true); w < 0.9 {
		t.Errorf("lookalike should weigh ~1, got %v", w)
	}
	if w := phishWeight("evil.example", "paypal.com", true); w <= 0 || w > 1 {
		t.Errorf("different: %v", w)
	}
}
