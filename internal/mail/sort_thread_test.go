package mail_test

import (
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
)

func TestSortMessagesByArrivalAndSubject(t *testing.T) {
	t.Parallel()

	base := time.Date(2025, 1, 10, 12, 0, 0, 0, time.UTC).Unix()
	msgs := []mail.Message{
		{UID: 1, Meta: storage.EmailMeta{ReceivedAt: base + 2, Size: 100}},
		{UID: 2, Meta: storage.EmailMeta{ReceivedAt: base, Size: 50}},
		{UID: 3, Meta: storage.EmailMeta{ReceivedAt: base + 1, Size: 200}},
	}
	load := mail.RawLoader(func(m mail.Message) ([]byte, error) {
		switch m.UID {
		case 1:
			return []byte("From: a@b\r\nSubject: zebra\r\nDate: Fri, 10 Jan 2025 12:02:00 +0000\r\n\r\n\r\n"), nil
		case 2:
			return []byte("From: a@b\r\nSubject: alpha\r\nDate: Fri, 10 Jan 2025 12:00:00 +0000\r\n\r\n\r\n"), nil
		case 3:
			return []byte("From: a@b\r\nSubject: beta\r\nDate: Fri, 10 Jan 2025 12:01:00 +0000\r\n\r\n\r\n"), nil
		default:
			return nil, nil
		}
	})
	expr := mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}

	got := mail.SortMessages(msgs, []mail.SortKey{mail.SortArrival}, false, expr, load)
	if len(got) != 3 || got[0] != 2 || got[1] != 3 || got[2] != 1 {
		t.Fatalf("arrival %v", got)
	}

	got = mail.SortMessages(msgs, []mail.SortKey{mail.SortSubject}, false, expr, load)
	if got[0] != 2 || got[1] != 3 || got[2] != 1 {
		t.Fatalf("subject %v", got)
	}

	got = mail.SortMessages(msgs, []mail.SortKey{mail.SortArrival}, true, expr, load)
	if got[0] != 1 || got[2] != 2 {
		t.Fatalf("reverse arrival %v", got)
	}
}

func TestThreadReferencesLinksReplies(t *testing.T) {
	t.Parallel()

	msgs := []mail.Message{
		{UID: 1, Meta: storage.EmailMeta{ReceivedAt: 1}},
		{UID: 2, Meta: storage.EmailMeta{ReceivedAt: 2}},
		{UID: 3, Meta: storage.EmailMeta{ReceivedAt: 3}},
	}
	load := mail.RawLoader(func(m mail.Message) ([]byte, error) {
		switch m.UID {
		case 1:
			return []byte("Message-ID: <root@x>\r\n\r\n\r\n"), nil
		case 2:
			return []byte("Message-ID: <reply@x>\r\nIn-Reply-To: <root@x>\r\nReferences: <root@x>\r\n\r\n\r\n"), nil
		case 3:
			return []byte("Message-ID: <solo@x>\r\n\r\n\r\n"), nil
		default:
			return nil, nil
		}
	})
	expr := mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}
	threads := mail.ThreadReferences(msgs, expr, load)
	if len(threads) != 2 {
		t.Fatalf("threads %d", len(threads))
	}
	if len(threads[0]) != 2 || threads[0][0] != 1 || threads[0][1] != 2 {
		t.Fatalf("linked %v", threads[0])
	}
	if len(threads[1]) != 1 || threads[1][0] != 3 {
		t.Fatalf("solo %v", threads[1])
	}
}
