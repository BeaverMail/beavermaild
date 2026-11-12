package mail_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// headerMsgs returns one message per header block, loaded from those blocks.
func headerMsgs(headers []string) ([]mail.Message, mail.RawLoader) {
	msgs := make([]mail.Message, len(headers))
	for i := range msgs {
		msgs[i].UID = uint32(i + 1)
		msgs[i].Meta.ReceivedAt = int64(i)
	}
	return msgs, mail.BytesLoader(func(m mail.Message) ([]byte, error) {
		return []byte(headers[m.UID-1] + "\r\n\r\nbody\r\n"), nil
	})
}

var allExpr = mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}

// TestSortDisplayTo follows imaptest sort-display-to: display name, else mailbox@host, else the
// mailbox, and a group by its name (RFC 5957).
func TestSortDisplayTo(t *testing.T) {
	t.Parallel()

	msgs, load := headerMsgs([]string{
		"To: foo bar <a@example.com>",
		"To: b@example.com",
		"To: d",
		"To: =?iso-8859-1?q?foo_aar?= <e@example.com>",
		"To: =?iso-8859-1?q?foo_car?= <f@example.com>",
		"To: a: xx@example.org, yy@example.org;",
		"To: z: aa@example.org, bb@example.org;",
		"To: empty:;",
	})
	got := mail.SortMessages(msgs, []mail.SortCriterion{{Key: mail.SortDisplayTo}}, allExpr, load)
	if want := []uint32{6, 2, 3, 8, 4, 1, 5, 7}; !slices.Equal(got, want) {
		t.Fatalf("displayto %v, want %v", got, want)
	}
}

func TestThreadOrderedSubject(t *testing.T) {
	t.Parallel()

	msgs, load := headerMsgs([]string{
		"Subject: Re: a\r\nDate: Fri, 10 Jan 2025 12:03:00 +0000",
		"Subject: b\r\nDate: Fri, 10 Jan 2025 12:01:00 +0000",
		"Subject: a\r\nDate: Fri, 10 Jan 2025 12:02:00 +0000",
		"Subject: B\r\nDate: Fri, 10 Jan 2025 12:04:00 +0000",
		"Subject: c\r\nDate: Fri, 10 Jan 2025 12:00:00 +0000",
		"Subject: [fwd: a]\r\nDate: Fri, 10 Jan 2025 12:05:00 +0000",
	})
	threads, err := mail.ThreadOrderedSubjectContext(context.Background(), msgs, allExpr, load)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, th := range threads {
		var kids []uint32
		for _, c := range th.Children {
			kids = append(kids, c.Seq)
		}
		got = append(got, fmt.Sprint(th.Seq, kids))
	}
	// Threads by their first message's date: c, b, a; replies flat under the first message.
	if want := []string{"5 []", "2 [4]", "3 [1 6]"}; !slices.Equal(got, want) {
		t.Fatalf("threads %q, want %q", got, want)
	}
}
