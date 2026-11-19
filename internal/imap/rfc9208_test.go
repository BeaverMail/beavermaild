package imap_test

import (
	"strings"
	"testing"
)

// RFC 9208: QUOTA=RES-* capabilities (3.1.1), GETQUOTAROOT with its QUOTA also for a mailbox not
// created yet (4.1.2), NO for an unknown root (4.1.1), STATUS DELETED and DELETED-STORAGE (4.1.4).
func TestRFC9208Quota(t *testing.T) {
	t.Parallel()
	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	for _, body := range []string{"one", "second"} {
		if _, err := inbox.Deliver(ctx, accID, []byte("From: a@example.org\r\n\r\n"+body+"\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	msgs := uint32(10)
	if err := inbox.SetQuotaLimits(ctx, accID, nil, &msgs); err != nil {
		t.Fatal(err)
	}
	a, ra := rfc7162Dial(t, ln)
	if lines, _ := rfc7162Run(t, a, ra, "c", "CAPABILITY"); !strings.Contains(lines[0], " QUOTA=RES-STORAGE QUOTA=RES-MESSAGE") {
		t.Fatalf("capabilities: %q", lines)
	}
	lines, tagged := rfc7162Run(t, a, ra, "r", "GETQUOTAROOT NotYet")
	if strings.Join(lines, "\n") != "* QUOTAROOT \"NotYet\" \"\"\n* QUOTA \"\" (MESSAGE 2 10)" || !strings.HasPrefix(tagged, "r OK") {
		t.Fatalf("GETQUOTAROOT: %q %q", lines, tagged)
	}
	if _, tagged := rfc7162Run(t, a, ra, "q", `GETQUOTA "other"`); !strings.HasPrefix(tagged, "q NO") {
		t.Fatalf("GETQUOTA unknown root: %q", tagged)
	}

	rfc7162Run(t, a, ra, "s", "SELECT INBOX")
	rfc7162Run(t, a, ra, "f", `STORE 2 +FLAGS (\Deleted)`)
	lines, _ = rfc7162Run(t, a, ra, "z", "FETCH 2 (RFC822.SIZE)")
	size := strings.TrimSuffix(strings.Fields(lines[0])[4], ")")
	lines, _ = rfc7162Run(t, a, ra, "t", "STATUS INBOX (MESSAGES DELETED DELETED-STORAGE)")
	if want := "* STATUS INBOX (MESSAGES 2 DELETED 1 DELETED-STORAGE " + size + ")"; lines[0] != want {
		t.Fatalf("STATUS: %q, want %q", lines, want)
	}
	rfc7162Run(t, a, ra, "e", "EXPUNGE")
	lines, _ = rfc7162Run(t, a, ra, "u", `GETQUOTA ""`)
	if lines[0] != `* QUOTA "" (MESSAGE 1 10)` {
		t.Fatalf("after expunge: %q", lines)
	}
}
