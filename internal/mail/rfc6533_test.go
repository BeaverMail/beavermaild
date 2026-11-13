package mail

import (
	"encoding/base64"
	"strings"
	"testing"
)

// RFC 6533 3: the "utf-8" ORCPT address type, with \x{HEX} escapes or (with SMTPUTF8) UTF-8. An
// escape that decodes to a control character would break the notification line: refused.
func TestRFC6533Orcpt(t *testing.T) {
	for v, want := range map[string]bool{
		`utf-8;al\x{EF}ce@example.org`:  true,
		"utf-8;al\u00efce@example.org":  true,
		`UTF-8;\x{3B4}@example.org`:     true,
		`utf-8;a\x{0D}\x{0A}b@x.org`:    false,
		`utf-8;a\x{85}b@example.org`:    false, // C1 NEL
		`utf-8;a\x{D800}b@example.org`:  false, // surrogate
		`utf-8;a\x{110000}@example.org`: false,
		`utf-8;a\x{}@example.org`:       false,
		`utf-8;a\b@example.org`:         false,
		"utf-8;a+b@example.org":         false,
		"utf-8;a b@example.org":         false,
		"utf-8;":                        false,
		"utf-8;a\xff@example.org":       false, // invalid UTF-8
		"rfc822;b+40example.org":        true,
	} {
		if got := ValidOrcpt(v); got != want {
			t.Errorf("ValidOrcpt(%q) = %v, want %v", v, got, want)
		}
	}
	if got := OrcptText(`utf-8;al\x{EF}ce@example.org`, true); got != "utf-8;al\u00efce@example.org" {
		t.Errorf("global Original-Recipient %q", got)
	}
	if got := OrcptText("utf-8;al\u00efce@example.org", false); got != `utf-8;al\x{EF}ce@example.org` {
		t.Errorf("7-bit Original-Recipient %q", got)
	}
	if got := OrcptASCII("utf-8;\u03b4@example.org"); got != `utf-8;\x{3B4}@example.org` {
		t.Errorf("OrcptASCII %q", got)
	}
}

// RFC 6533 4: the notification of an internationalized message uses
// message/global-delivery-status, utf-8 addresses, and message/global (base64, 4.5) for the
// returned content; an ASCII message keeps the RFC 3464 types.
func TestBuildDSNGlobal(t *testing.T) {
	raw := "Subject: caf\u00e9\r\nFrom: \u03b4@example.org\r\n\r\nbody\r\n"
	out := string(BuildDSN(DSNBuildOpts{ReturnPath: "\u03b4@example.org", FinalRcpt: "\u00e9lise@example.net",
		Orcpt: `utf-8;\x{E9}lise@example.net`, Ret: RetFull, Action: DSNActionFailed, Status: "5.1.1",
		OriginalRaw: []byte(raw), Hostname: "mx.example.net"}))
	for _, want := range []string{
		"Content-Type: message/global-delivery-status\r\nContent-Transfer-Encoding: 8bit\r\n",
		"Original-Recipient: utf-8;\u00e9lise@example.net\r\n",
		"Final-Recipient: utf-8; \u00e9lise@example.net\r\n",
		"Content-Type: message/global\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(raw)),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	hdrs := string(BuildDSN(DSNBuildOpts{ReturnPath: "a@example.org", FinalRcpt: "b@example.net", Ret: RetHdrs,
		Action: DSNActionFailed, OriginalRaw: []byte(raw), Hostname: "mx.example.net"}))
	if !strings.Contains(hdrs, "Content-Type: message/global-delivery-status\r\n\r\n") || !strings.Contains(hdrs, "Content-Type: message/global-headers\r\nContent-Transfer-Encoding: base64\r\n") {
		t.Errorf("headers-only global DSN:\n%s", hdrs)
	}
	ascii := string(BuildDSN(DSNBuildOpts{ReturnPath: "a@example.org", FinalRcpt: "b@example.net", Ret: RetFull,
		Action: DSNActionFailed, OriginalRaw: []byte("Subject: s\r\n\r\ncaf\u00e9\r\n"), Hostname: "mx.example.net"}))
	if strings.Contains(ascii, "global") || !strings.Contains(ascii, "Content-Type: message/delivery-status") {
		t.Errorf("8-bit body alone made a global DSN:\n%s", ascii)
	}
}
