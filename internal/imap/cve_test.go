package imap

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// within fails t when fn runs longer than limit: these classes turn a small message into minutes
// of CPU, so a generous bound still tells linear from quadratic. The race detector slows code
// down about tenfold, so the bound grows with it.
func within(t *testing.T, limit time.Duration, fn func()) {
	t.Helper()
	if raceEnabled {
		limit *= 10
	}
	start := time.Now()
	fn()
	if d := time.Since(start); d > limit {
		t.Fatalf("took %v, want under %v", d, limit)
	}
}

// CVE-2026-27859 class (Dovecot): a Content-Type with very many parameters must not cost
// quadratic CPU in BODYSTRUCTURE. The parameter list used to be sorted with an O(n²) loop.
func TestCVE_2026_27859_ManyMIMEParams(t *testing.T) {
	var ct strings.Builder
	ct.WriteString("text/plain")
	for i := range 50000 {
		fmt.Fprintf(&ct, "; p%d=v", i)
	}
	raw := []byte("Content-Type: " + ct.String() + "\r\n\r\nbody\r\n")
	within(t, 2*time.Second, func() {
		if bs := formatBodyStructure(raw); !strings.Contains(bs, `"P49999" "v"`) {
			t.Fatalf("parameter missing: %.200s", bs)
		}
	})
}

// RFC 2046 5.1.1: a boundary delimiter is "--boundary" followed only by optional white space and
// the line end (or "--"). Matching it as a prefix made "--b10" split boundary "b1", so IMAP showed
// a different structure from every other MIME parser (filter evasion).
func TestMultipartBoundaryIsNotAPrefix(t *testing.T) {
	raw := []byte("Content-Type: multipart/mixed; boundary=b1\r\n\r\n" +
		"--b1\r\nContent-Type: text/plain\r\n\r\none\r\n--b10\r\nnot a part\r\n" +
		"--b1 \t\r\nContent-Type: text/html\r\n\r\ntwo\r\n--b1--\r\n")
	parts := splitMultipart([]byte(strings.SplitN(string(raw), "\r\n\r\n", 2)[1]), "b1")
	if len(parts) != 2 || !strings.Contains(string(parts[0]), "--b10") || !strings.Contains(string(parts[1]), "two") {
		t.Fatalf("parts = %q", parts)
	}
}

// Deeply nested SEARCH keys are refused: parsing and matching recurse once per level, and 30000
// parentheses in one line cost ~120 MB of goroutine stack per command.
func TestSearchNestingLimit(t *testing.T) {
	ok := "(" + strings.Repeat("NOT (", 40) + "ALL" + strings.Repeat(")", 41)
	if _, valid := parseSearchExpr(ok); !valid {
		t.Fatal("80 levels refused")
	}
	for _, deep := range []string{
		strings.Repeat("(", 30000) + "ALL" + strings.Repeat(")", 30000),
		strings.Repeat("NOT ", 15000) + "ALL",
		strings.Repeat("OR ", 8000) + strings.Repeat("ALL ", 8001),
	} {
		if _, valid := parseSearchExpr(deep); valid {
			t.Fatalf("accepted %d bytes of nesting", len(deep))
		}
	}
}

// LIST patterns: only * and % are wildcards (RFC 3501 6.3.8). Regexp metacharacters such as ? used
// to pass through: "?*" matched every mailbox and "a???*" panicked the session.
func TestListPatternLiteralCharacters(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"?*", "INBOX", false},
		{"?*", "?x", true},
		{"a???*", "a???b", true},
		{"a???*", "abcd", false},
		{"a.b%", "a.bc", true},
		{"a.b%", "axbc", false},
		{"x\\y*", `x\y1`, true},
	} {
		if got := compileListPattern(tc.pattern)(tc.name); got != tc.want {
			t.Errorf("pattern %q name %q = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

// nestedMultipart builds n levels of multipart/mixed around one text part.
func nestedMultipart(n int) []byte {
	var b strings.Builder
	b.WriteString("Content-Type: multipart/mixed; boundary=b000000\r\n\r\n")
	for i := range n {
		fmt.Fprintf(&b, "--b%06d\r\nContent-Type: multipart/mixed; boundary=b%06d\r\n\r\n", i, i+1)
	}
	fmt.Fprintf(&b, "--b%06d\r\nContent-Type: text/plain\r\n\r\nx\r\n", n)
	for i := n; i >= 0; i-- {
		fmt.Fprintf(&b, "--b%06d--\r\n", i)
	}
	return []byte(b.String())
}

// nestedMessages builds n message/rfc822 parts, each encapsulating the next.
func nestedMessages(n int) []byte {
	var b strings.Builder
	for range n {
		b.WriteString("Subject: m\r\nContent-Type: message/rfc822\r\n\r\n")
	}
	b.WriteString("Subject: last\r\n\r\nx\r\n")
	return []byte(b.String())
}

// CVE-2020-12100 class (Dovecot): deeply nested MIME parts. Every level scanned its whole body
// (and message/rfc822 copied it), so the cost grew with depth x size: 24000 levels in 1.8 MB took
// 12.8 s per BODYSTRUCTURE. Past maxMIMEDepth a part is one opaque leaf, the same in BODYSTRUCTURE,
// BODY[section] and BINARY.
func TestCVE_2020_12100_DeepMIMENesting(t *testing.T) {
	for name, raw := range map[string][]byte{"multipart": nestedMultipart(24000), "message": nestedMessages(24000)} {
		within(t, 2*time.Second, func() {
			bs := formatBodyStructure(raw)
			if !strings.Contains(bs, `"APPLICATION" "OCTET-STREAM"`) {
				t.Fatalf("%s: no opaque leaf at the depth limit", name)
			}
			if depth := strings.Count(bs, "(("); depth > 2*maxMIMEDepth {
				t.Fatalf("%s: structure %d levels deep", name, depth)
			}
			_ = base64NULParts(append(raw, 0))
		})
	}

	// Sections agree with BODYSTRUCTURE: the part at the limit is a leaf holding the rest.
	raw := nestedMultipart(150)
	path := strings.TrimSuffix(strings.Repeat("1.", maxMIMEDepth), ".")
	leaf := extractBodySection(raw, path, nil)
	if !strings.HasPrefix(string(leaf), fmt.Sprintf("--b%06d\r\n", maxMIMEDepth)) {
		t.Fatalf("BODY[%d x 1] = %.60q, want the opaque part's body", maxMIMEDepth, leaf)
	}
	if deeper := extractBodySection(raw, path+".1", nil); len(deeper) != 0 {
		t.Fatalf("section inside the opaque leaf returned %d bytes", len(deeper))
	}
}

// Before login an idle connection is dropped after preAuthTimeout, not after the 30 minutes RFC
// 3501 5.4 asks for authenticated sessions (slowloris on the pre-login slots).
func TestPreAuthIdleTimeout(t *testing.T) {
	defer func(d time.Duration) { preAuthTimeout = d }(preAuthTimeout)
	preAuthTimeout = 50 * time.Millisecond
	server, client := net.Pipe()
	defer client.Close()
	s := newSession(slog.New(slog.DiscardHandler), server, nil, nil, nil, false, false, nil, 30*time.Minute)
	start := time.Now()
	if _, err := s.readLine(); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("idle pre-login read: err=%v after %v", err, time.Since(start))
	}
	s.principal.AccountID = 1 // logged in: the configured 30 minutes apply
	go func() {
		time.Sleep(200 * time.Millisecond)
		_, _ = client.Write([]byte("a NOOP\r\n"))
	}()
	if line, err := s.readLine(); err != nil || line != "a NOOP" {
		t.Fatalf("authenticated session got the pre-login timeout: %q %v", line, err)
	}
}
