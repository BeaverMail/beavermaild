package smtp

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Every reply the server writes in any test of this package is checked against the RFC grammar, so a
// test that only looks at the reply code still catches a malformed reply.
func TestMain(m *testing.M) {
	var mu sync.Mutex
	var bad []string
	replyHook = func(cmd, reply string) {
		if err := checkReply(cmd, reply); err != nil {
			mu.Lock()
			bad = append(bad, fmt.Sprintf("after %q: %v\n    reply %q", cmd, err, reply))
			mu.Unlock()
		}
	}
	code := m.Run()
	if len(bad) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d SMTP replies break RFC 5321 / RFC 2034:\n  %s\n", len(bad), strings.Join(bad, "\n  "))
		code = 1
	}
	os.Exit(code)
}

var (
	// RFC 5321 4.2: Reply-code = %x32-35 %x30-35 %x30-39; textstring = 1*(%d09 / %d32-126).
	replyLineRE = regexp.MustCompile(`^([2-5][0-5][0-9])(?:([- ])([\t\x20-\x7e]+)?)?$`)
	// RFC 2034 4: status-code = class "." subject "." detail, followed by one or more spaces.
	statusCodeRE = regexp.MustCompile(`^([245])\.[0-9]{1,3}\.[0-9]{1,3}(?: |$)`)
	// RFC 5321 4.1.2: Domain or address-literal, the first word of the greeting and of the HELO/EHLO reply.
	domainRE = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*|\[[^\[\]\\]+\])$`)
	// RFC 5321 4.1.1.1: ehlo-line = ehlo-keyword *( SP ehlo-param ).
	ehloLineRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*(?: [\x21-\x7e]+)*$`)
)

// checkReply validates one complete reply (all its lines) sent in answer to cmd.
func checkReply(cmd, reply string) error {
	if !strings.HasSuffix(reply, "\r\n") {
		return fmt.Errorf("RFC 5321 4.2: reply does not end with CRLF")
	}
	lines := strings.Split(strings.TrimSuffix(reply, "\r\n"), "\r\n")
	verb, _, _ := strings.Cut(cmd, " ")
	greeting, hello := verb == "", verb == "HELO" || verb == "EHLO"
	var code string
	for i, line := range lines {
		if len(line)+2 > 512 {
			return fmt.Errorf("RFC 5321 4.5.3.1.5: line %d is %d octets with CRLF, max 512", i+1, len(line)+2)
		}
		m := replyLineRE.FindStringSubmatch(line)
		if m == nil {
			return fmt.Errorf("RFC 5321 4.2: line %d %q is not a Reply-line", i+1, line)
		}
		if i == 0 {
			code = m[1]
		} else if m[1] != code {
			return fmt.Errorf("RFC 5321 4.2.1: line %d has code %s, first line %s", i+1, m[1], code)
		}
		last := i == len(lines)-1
		if last && m[2] == "-" || !last && m[2] != "-" {
			return fmt.Errorf("RFC 5321 4.2.1: line %d: only the last line may use SP after the code", i+1)
		}
		text := m[3]
		switch {
		case (greeting && code == "220") || (hello && code == "250"):
			// RFC 5321 4.2 Greeting, 4.1.1.1 ehlo-ok-rsp: the domain first, then (EHLO) one keyword per line.
			if i == 0 {
				if statusCodeRE.MatchString(text) {
					return fmt.Errorf("RFC 2034 4: no enhanced status code in the greeting or HELO/EHLO reply")
				}
				if d, _, _ := strings.Cut(text, " "); !domainRE.MatchString(d) {
					return fmt.Errorf("RFC 5321 4.1.1.1/4.2: first line must start with the server domain, got %q", d)
				}
			} else if verb == "EHLO" && !ehloLineRE.MatchString(text) {
				return fmt.Errorf("RFC 5321 4.1.1.1: line %d %q is not an ehlo-line (no enhanced status codes here, RFC 2034 4)", i+1, text)
			}
		case greeting || hello || code[0] == '3':
			// RFC 2034 4: the status code is required everywhere except the greeting, HELO/EHLO and 3xx.
		default:
			sm := statusCodeRE.FindStringSubmatch(text)
			if sm == nil {
				return fmt.Errorf("RFC 2034 4: line %d of a %s reply lacks the enhanced status code", i+1, code)
			}
			if sm[1][0] != code[0] {
				return fmt.Errorf("RFC 2034 4: enhanced class %s.x.x does not match reply %s", sm[1], code)
			}
		}
	}
	return nil
}

func TestCheckReply(t *testing.T) {
	for _, tc := range []struct {
		cmd, reply string
		ok         bool
	}{
		{"", "220 mx.example.org ESMTP ready\r\n", true},
		{"", "220 2.0.0 mx.example.org\r\n", false},
		{"", "421 4.3.2 too many connections\r\n", true},
		{"EHLO", "250-mx.example.org\r\n250-PIPELINING\r\n250 SIZE 1000\r\n", true},
		{"EHLO", "250-mx.example.org\r\n250-PIPELINING\r\n250 2.0.0 Ok\r\n", false},
		{"EHLO", "250-mx.example.org\r\n250 PIPELINING\r\n250 SIZE 1\r\n", false},
		{"EHLO", "250-mx.example.org\r\n251 PIPELINING\r\n", false},
		{"HELO", "250 mx.example.org\r\n", true},
		{"EHLO", "501 5.5.4 Syntax: EHLO hostname\r\n", true},
		{"MAIL FROM:<a@example.org>", "250 2.1.0 Ok\r\n", true},
		{"MAIL FROM:<a@example.org>", "250 Ok\r\n", false},
		{"RCPT TO:<b@example.org>", "550 4.1.1 no such user\r\n", false},
		{"DATA", "354 End data with <CR><LF>.<CR><LF>\r\n", true},
		{"AUTH", "334 VXNlcm5hbWU6\r\n", true},
		{"NOOP", "250 2.0.0 Ok", false},
		{"NOOP", "250 2.0.0 Ok\nx\r\n", false},
		{"NOOP", "250-2.0.0 a\r\n250 b\r\n", false},
		{"NOOP", "250 2.0.0 " + strings.Repeat("x", 600) + "\r\n", false},
		{"NOOP", "250 2.0.0 caf\xc3\xa9\r\n", false},
		{"NOOP", "600 6.0.0 x\r\n", false},
		{"QUIT", "221 2.0.0 Bye\r\n", true},
	} {
		if err := checkReply(tc.cmd, tc.reply); (err == nil) != tc.ok {
			t.Errorf("checkReply(%q, %q) = %v, want ok=%v", tc.cmd, tc.reply, err, tc.ok)
		}
	}
}
