package mail_test

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
)

func TestMailboxSelectState(t *testing.T) {
	t.Parallel()

	msgs := []mail.Message{
		{UID: 5, Meta: storage.EmailMeta{Flags: mail.FlagSeen, ModSeq: 3}},
		{UID: 12, Meta: storage.EmailMeta{ModSeq: 7}},
	}
	uidNext, unseen, highest := mail.MailboxSelectState(msgs, 4)
	if uidNext != 13 || unseen != 1 || highest != 7 {
		t.Fatalf("got uidNext=%d unseen=%d highest=%d", uidNext, unseen, highest)
	}
	_, _, highest = mail.MailboxSelectState(nil, 9)
	if highest != 9 {
		t.Fatalf("stored highest want 9 got %d", highest)
	}
}
