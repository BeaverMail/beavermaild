package mail_test

import (
	"slices"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// TestSortKeysFromEnvelope: SORT keys derive from the ENVELOPE address list (RFC 5957 4, RFC 5256
// 3), never from the raw header, also when net/mail cannot read the list or its charset.
func TestSortKeysFromEnvelope(t *testing.T) {
	t.Parallel()

	msgs, load := headerMsgs([]string{
		"From: =?windows-1252?Q?Zo=EB?= <a@x.example>", // Zoë
		`From: "Bob" <bob@x.example>, garbage;;`,       // Bob
		"From: =?utf-8?Q?Andr=C3=A9?= <c@x.example>",   // André
		"From: undisclosed-recipients:;",               // a group: its name
		"From: Carl (comment) <carl@x.example>",        // Carl
		"From: <anon@x.example>",                       // anon@x.example
		"From: =?utf-8?Q??= <empty@x.example>",         // empty name: empty@x.example
	})
	got := mail.SortMessages(msgs, []mail.SortCriterion{{Key: mail.SortDisplayFrom}}, allExpr, load)
	if want := []uint32{3, 6, 2, 5, 7, 4, 1}; !slices.Equal(got, want) {
		t.Fatalf("DISPLAYFROM %v, want %v", got, want)
	}
	// FROM: the first addr-mailbox (a, bob, c, the group name, carl, anon, empty).
	got = mail.SortMessages(msgs, []mail.SortCriterion{{Key: mail.SortFrom}}, allExpr, load)
	if want := []uint32{1, 6, 2, 3, 5, 7, 4}; !slices.Equal(got, want) {
		t.Fatalf("FROM %v, want %v", got, want)
	}
	// SEARCH FROM decodes the windows-1252 name too.
	if got := mail.MatchSearchUIDWithLoader(msgs, mail.SearchCriteria{From: "Zoë"}, load); !slices.Equal(got, []uint32{1}) {
		t.Fatalf("SEARCH FROM Zoë: %v", got)
	}
}
