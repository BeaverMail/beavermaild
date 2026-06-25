package mail_test

import (
	"errors"
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
)

func TestValidateMailboxName(t *testing.T) {
	t.Parallel()

	if err := mail.ValidateMailboxName("INBOX"); err != nil {
		t.Fatal(err)
	}
	if err := mail.ValidateMailboxName("Archive"); err != nil {
		t.Fatal(err)
	}
	if err := mail.ValidateMailboxName("bad\rname"); !errors.Is(err, mail.ErrInvalidMailboxName) {
		t.Fatalf("ctl err %v", err)
	}
	if err := mail.ValidateMailboxName("{box}"); !errors.Is(err, mail.ErrInvalidMailboxName) {
		t.Fatalf("brace err %v", err)
	}
}
