package smtp

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

func TestParseMailArg(t *testing.T) {
	t.Parallel()

	addr, size, params, ok := parseMailArg("FROM:<alice@localhost>")
	if !ok || addr != "alice@localhost" || size != 0 {
		t.Fatalf("got %q %d ok=%v", addr, size, ok)
	}

	addr, size, params, ok = parseMailArg("FROM:<alice@localhost> SIZE=1024 BODY=8BITMIME")
	if !ok || addr != "alice@localhost" || size != 1024 || params.Body != "8BITMIME" {
		t.Fatalf("got %q %d params=%+v ok=%v", addr, size, params, ok)
	}

	if _, _, _, ok := parseMailArg("FROM:<bad"); ok {
		t.Fatal("bad syntax")
	}
	if _, _, _, ok := parseMailArg("FROM:<a@b> SIZE=xy"); ok {
		t.Fatal("bad size")
	}

	addr, size, params, ok = parseMailArg("FROM:<a@b> RET=FULL ENVID=abc123 SIZE=10")
	if !ok || addr != "a@b" || size != 10 || params.Ret != mail.RetFull || params.Envid != "abc123" {
		t.Fatalf("dsn params: %q %d params=%+v ok=%v", addr, size, params, ok)
	}

	addr, _, params, ok = parseMailArg("FROM:<üser@example.com> SMTPUTF8")
	if !ok || addr != "üser@example.com" || !params.SMTPUTF8 {
		t.Fatalf("utf8 mail: %q params=%+v ok=%v", addr, params, ok)
	}

	addr, rcptParams, ok := parseRcptArg("TO:<bob@localhost> NOTIFY=FAILURE ORCPT=rfc822;bob@localhost")
	if !ok || addr != "bob@localhost" || rcptParams.Notify != mail.NotifyFailure {
		t.Fatalf("rcpt dsn: %q params=%+v ok=%v", addr, rcptParams, ok)
	}
	if _, _, ok := parseRcptArg("TO:<bad"); ok {
		t.Fatal("bad rcpt")
	}

	_, rcptParams, ok = parseRcptArg("TO:<x@y> NOTIFY=NEVER")
	if !ok || rcptParams.Notify != mail.NotifyNever {
		t.Fatalf("notify never: %+v", rcptParams)
	}

	_, _, params, ok = parseMailArg("FROM:<a@b> HOLD=20260101000000")
	if !ok || params.Unsupported == "" {
		t.Fatal("expected HOLD reject marker")
	}
	_, rcptParams, ok = parseRcptArg("TO:<x@y> BY=20260101000000")
	if !ok || rcptParams.Unsupported == "" {
		t.Fatal("expected BY reject marker")
	}

	sizeChunk, last, ok := parseBDAT("100 LAST")
	if !ok || sizeChunk != 100 || !last {
		t.Fatalf("bdat last: %d last=%v ok=%v", sizeChunk, last, ok)
	}
	sizeChunk, last, ok = parseBDAT("50")
	if !ok || sizeChunk != 50 || last {
		t.Fatalf("bdat cont: %d last=%v ok=%v", sizeChunk, last, ok)
	}
	if _, _, ok := parseBDAT("x LAST"); ok {
		t.Fatal("bad bdat")
	}
	// RFC 6152 2: body-value is 7BIT or 8BITMIME, never empty; a known keyword without its value
	// is a syntax error (501), not an unknown parameter (555).
	for _, arg := range []string{"FROM:<> BODY=", "FROM:<> BODY", "FROM:<> SIZE", "FROM:<> RET", "FROM:<> ENVID", "FROM:<> AUTH"} {
		if _, _, _, ok := parseMailArg(arg); ok {
			t.Errorf("%q accepted", arg)
		}
	}
	if _, _, p, ok := parseMailArg("FROM:<> SMTPUTF8 BODY=8bitmime"); !ok || !p.SMTPUTF8 || p.Body != "8BITMIME" {
		t.Errorf("SMTPUTF8 BODY=8bitmime: %+v %v", p, ok)
	}
	// RFC 3030 2: chunk-size = 1*DIGIT; strconv.Atoi alone took a sign.
	for _, arg := range []string{"+5", "-0", "+0 LAST", "5x", "99999999999999999999999", "5 LAST more"} {
		if _, _, ok := parseBDAT(arg); ok {
			t.Errorf("BDAT %q accepted", arg)
		}
	}
	if n, last, ok := parseBDAT("007 last"); !ok || n != 7 || !last {
		t.Errorf("BDAT 007 last: %d %v %v", n, last, ok)
	}
}
