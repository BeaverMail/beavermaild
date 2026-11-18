package imap

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// An updating SORT context places new members by binary search on sort values kept per member:
// each message's header is read once, not the whole result again on every arrival. Exact ties keep
// mailbox (UID) order, as SORT does.
func TestSortContextInsertsWithoutResort(t *testing.T) {
	subjects := map[uint32]string{1: "b", 2: "d", 3: "f", 4: "c", 5: "a", 6: "e", 7: "a"}
	loads := 0
	load := func(m mail.Message) (io.ReadCloser, error) {
		loads++
		return io.NopCloser(strings.NewReader("Subject: " + subjects[m.UID] + "\r\n\r\n")), nil
	}
	msgs := func(n uint32) []mail.Message {
		var out []mail.Message
		for uid := uint32(1); uid <= n; uid++ {
			out = append(out, mail.Message{UID: uid})
		}
		return out
	}
	crits := []mail.SortCriterion{{Key: mail.SortSubject}}
	all := mail.SearchExpr{Crit: mail.SearchCriteria{All: true}}
	out := fetchOutput(t, nil, func(s *session) error {
		s.selected = true
		s.messages = msgs(3)
		if err := s.addSearchContext("t", true, crits, all, []uint32{1, 2, 3}, nil); err != nil {
			return err
		}
		s.messages = msgs(5)
		if err := s.refreshContext(context.Background(), s.contexts[0], load); err != nil {
			return err
		}
		if loads != 5 {
			t.Errorf("first arrival: %d header loads, want 5", loads)
		}
		s.messages = msgs(7)
		if err := s.refreshContext(context.Background(), s.contexts[0], load); err != nil {
			return err
		}
		if loads != 7 {
			t.Errorf("second arrival: %d header loads in all, want 7 (one per new message)", loads)
		}
		return nil
	})
	want := "* ESEARCH (TAG \"t\") UID ADDTO (1 5 3 4)\r\n* ESEARCH (TAG \"t\") UID ADDTO (2 7 6 6)\r\n"
	if out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}
