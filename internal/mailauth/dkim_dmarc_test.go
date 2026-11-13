package mailauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// testDNS serves DKIM keys and DMARC records; every other name does not exist.
type testDNS struct {
	pub     ed25519.PublicKey
	records map[string]string
	block   bool // wait for the context instead of answering
}

func (d *testDNS) lookup(ctx context.Context, name string) ([]string, error) {
	if d.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	name = strings.TrimSuffix(name, ".")
	if strings.HasPrefix(name, "sel._domainkey.") {
		return []string{"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(d.pub)}, nil
	}
	if r, ok := d.records[name]; ok {
		return []string{r}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func newDNS(t *testing.T) (*testDNS, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testDNS{pub: pub, records: map[string]string{
		"_dmarc.victim.example": "v=DMARC1; p=reject",
		"_dmarc.victim.co.uk":   "v=DMARC1; p=reject",
	}}, priv
}

// sign adds a valid DKIM-Signature for domain on top of msg.
func sign(t *testing.T, key ed25519.PrivateKey, domain, msg string) string {
	t.Helper()
	var out bytes.Buffer
	if err := dkim.Sign(&out, strings.NewReader(msg), &dkim.SignOptions{Domain: domain, Selector: "sel", Signer: key}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func eom(t *testing.T, dns *testDNS, timeout time.Duration, msg string) SessionState {
	t.Helper()
	path := filepath.Join(t.TempDir(), "msg.eml")
	if err := os.WriteFile(path, []byte(msg), 0o600); err != nil {
		t.Fatal(err)
	}
	v := New(Config{Enabled: true, DKIMEnabled: true, DMARCEnabled: true, DNSTimeout: timeout, LookupTXT: dns.lookup})
	return v.FinishEom(context.Background(), path, "bounce@sender.example", "mx.sender.example", SessionState{})
}

func msgFrom(from string) string {
	return "From: " + from + "\r\nTo: bob@rcpt.example\r\nSubject: hi\r\n\r\nbody\r\n"
}

// K1: only verified signatures count for alignment. A forged DKIM-Signature naming the victim, put
// on top of a valid signature from the attacker's domain, used to make DMARC pass.
func TestDMARCAlignsOnlyPassingSignatures(t *testing.T) {
	t.Parallel()
	dns, key := newDNS(t)
	forged := "DKIM-Signature: v=1; a=ed25519-sha256; d=victim.example; s=sel; h=from; bh=AAAA; b=AAAA\r\n"
	st := eom(t, dns, time.Second, forged+sign(t, key, "attacker.example", msgFrom("<ceo@victim.example>")))
	if st.DKIM != "pass" || st.DMARC != "fail" || st.DMARCPolicy != "reject" {
		t.Fatalf("forged d= on top: dkim %q dmarc %q %q; want pass, fail reject", st.DKIM, st.DMARC, st.DMARCPolicy)
	}
	// Two valid signatures, the aligned one second (an ESP signs first): DMARC passes.
	st = eom(t, dns, time.Second, sign(t, key, "esp.example", sign(t, key, "victim.example", msgFrom("<ceo@victim.example>"))))
	if st.DMARC != "pass" {
		t.Fatalf("aligned second signature: dmarc %q", st.DMARC)
	}
}

// K2: relaxed alignment uses the Public Suffix List, not the last two labels.
func TestDMARCOrganizationalDomain(t *testing.T) {
	t.Parallel()
	dns, key := newDNS(t)
	if st := eom(t, dns, time.Second, sign(t, key, "attacker.co.uk", msgFrom("<ceo@victim.co.uk>"))); st.DMARC != "fail" {
		t.Fatalf("attacker.co.uk aligned with victim.co.uk: %q", st.DMARC)
	}
	if st := eom(t, dns, time.Second, sign(t, key, "mail.victim.co.uk", msgFrom("<ceo@victim.co.uk>"))); st.DMARC != "pass" {
		t.Fatalf("mail.victim.co.uk not aligned with victim.co.uk: %q", st.DMARC)
	}
}

// K5: From is parsed as RFC 5322 defines it; zero, several From fields or several mailboxes are
// refused (RFC 7489 6.6.1) instead of escaping the policy.
func TestDMARCFromField(t *testing.T) {
	t.Parallel()
	dns, key := newDNS(t)
	if st := eom(t, dns, time.Second, sign(t, key, "victim.example", msgFrom("ceo@victim.example (CEO)"))); st.DMARC != "pass" || st.FromDomain != "victim.example" {
		t.Fatalf("From with a comment: dmarc %q from %q", st.DMARC, st.FromDomain)
	}
	if st := eom(t, dns, time.Second, msgFrom("ceo@victim.example (x)")); st.DMARC != "fail" || st.DMARCPolicy != "reject" {
		t.Fatalf("unsigned From with a comment escaped the policy: %q %q", st.DMARC, st.DMARCPolicy)
	}
	for name, msg := range map[string]string{
		"two From fields":   "From: <a@attacker.example>\r\n" + msgFrom("<ceo@victim.example>"),
		"two mailboxes":     msgFrom("<a@attacker.example>, <ceo@victim.example>"),
		"no From":           "To: bob@rcpt.example\r\n\r\nbody\r\n",
		"unparsable":        msgFrom("not an address"),
		"group, no mailbox": msgFrom("undisclosed:;"),
	} {
		if st := eom(t, dns, time.Second, sign(t, key, "attacker.example", msg)); st.DMARC != "fail" || st.DMARCPolicy != "reject" {
			t.Errorf("%s: dmarc %q %q; want fail reject", name, st.DMARC, st.DMARCPolicy)
		}
	}
}

// K3: our DNS timeout is a transient failure, not a missing key.
func TestDKIMTimeoutIsTemperror(t *testing.T) {
	t.Parallel()
	dns, key := newDNS(t)
	dns.block = true
	if st := eom(t, dns, 50*time.Millisecond, sign(t, key, "victim.example", msgFrom("<ceo@victim.example>"))); st.DKIM != "temperror" {
		t.Fatalf("dkim %q, want temperror", st.DKIM)
	}
}

// K4: with more than 8 signatures the first 8 are still verified.
func TestDKIMTooManySignatures(t *testing.T) {
	t.Parallel()
	dns, key := newDNS(t)
	msg := sign(t, key, "victim.example", msgFrom("<ceo@victim.example>"))
	for range 8 {
		msg = "DKIM-Signature: v=1; a=ed25519-sha256; d=junk.example; s=sel; h=from; bh=AAAA; b=AAAA\r\n" + msg
	}
	// 9 signatures, the valid one last: past the limit, so not verified; put one valid on top too.
	msg = sign(t, key, "victim.example", msg)
	if st := eom(t, dns, time.Second, msg); st.DKIM != "pass" || st.DMARC != "pass" {
		t.Fatalf("dkim %q dmarc %q, want pass with 10 signatures", st.DKIM, st.DMARC)
	}
}

// K2: the Organizational Domain comes from the Public Suffix List (RFC 7489 3.2).
func TestOrgDomain(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"attacker.co.uk":    "attacker.co.uk", // was "co.uk", shared with every .co.uk domain
		"mail.victim.co.uk": "victim.co.uk",
		"a.b.example.com":   "example.com",
		"user.github.io":    "user.github.io", // private suffix: each user is its own organization
		"co.uk":             "co.uk",
		"localhost":         "localhost",
	} {
		if got := orgDomain(in); got != want {
			t.Errorf("orgDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
