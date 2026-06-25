package smtp

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
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
}
