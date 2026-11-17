package mail_test

import (
	"slices"
	"strconv"
	"strings"
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
	load := mail.BytesLoader(func(m mail.Message) ([]byte, error) {
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

	got := mail.SortMessages(msgs, []mail.SortCriterion{{Key: mail.SortArrival}}, expr, load)
	if len(got) != 3 || got[0] != 2 || got[1] != 3 || got[2] != 1 {
		t.Fatalf("arrival %v", got)
	}

	got = mail.SortMessages(msgs, []mail.SortCriterion{{Key: mail.SortSubject}}, expr, load)
	if got[0] != 2 || got[1] != 3 || got[2] != 1 {
		t.Fatalf("subject %v", got)
	}

	got = mail.SortMessages(msgs, []mail.SortCriterion{{Key: mail.SortArrival, Reverse: true}}, expr, load)
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
	load := mail.BytesLoader(func(m mail.Message) ([]byte, error) {
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
	if r := threads[0]; r.Seq != 1 || len(r.Children) != 1 || r.Children[0].Seq != 2 {
		t.Fatalf("linked %+v", r)
	}
	if r := threads[1]; r.Seq != 3 || len(r.Children) != 0 {
		t.Fatalf("solo %+v", r)
	}
}

// TestSortPerKeyReverseAndTies follows imaptest sort-size: REVERSE applies to its key only, and
// exact ties stay in mailbox order even when reversed (RFC 5256).
func TestSortPerKeyReverseAndTies(t *testing.T) {
	t.Parallel()

	sizes := []uint32{10, 20, 10, 20}
	msgs := make([]mail.Message, len(sizes))
	for i, sz := range sizes {
		msgs[i] = mail.Message{UID: uint32(i + 1), Meta: storage.EmailMeta{Size: sz, ReceivedAt: int64(10 - i)}}
	}
	expr := mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}
	got := mail.SortMessages(msgs, []mail.SortCriterion{{Key: mail.SortSize, Reverse: true}}, expr, nil)
	if want := []uint32{2, 4, 1, 3}; !slices.Equal(got, want) {
		t.Fatalf("reverse size %v want %v", got, want)
	}
	got = mail.SortMessages(msgs, []mail.SortCriterion{{Key: mail.SortSize}, {Key: mail.SortArrival, Reverse: true}}, expr, nil)
	if want := []uint32{1, 3, 2, 4}; !slices.Equal(got, want) {
		t.Fatalf("size, reverse arrival %v want %v", got, want)
	}
}

// TestSortAddressAndSubjectKeys: FROM sorts on the first address's local part, SUBJECT on the
// base subject, DATE falls back to the internal date.
func TestSortAddressAndSubjectKeys(t *testing.T) {
	t.Parallel()

	raws := []string{
		"From: Zed <b-user@example.org>\r\nSubject: Re: [list] beta\r\n\r\n",
		"From: a-user@example.org\r\nSubject: alpha (fwd)\r\nDate: Mon, 1 Jan 2007 00:00:00 +0000\r\n\r\n",
		"From: 0-group: z@example.org;\r\nSubject: Fwd: gamma\r\nDate: bogus\r\n\r\n",
	}
	msgs := []mail.Message{
		{UID: 1, Meta: storage.EmailMeta{ReceivedAt: time.Date(2006, 1, 1, 0, 0, 0, 0, time.UTC).Unix()}},
		{UID: 2},
		{UID: 3, Meta: storage.EmailMeta{ReceivedAt: time.Date(2008, 1, 1, 0, 0, 0, 0, time.UTC).Unix()}},
	}
	load := mail.BytesLoader(func(m mail.Message) ([]byte, error) { return []byte(raws[m.UID-1]), nil })
	expr := mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}
	for key, want := range map[mail.SortKey][]uint32{
		mail.SortFrom:    {3, 2, 1}, // the group name "0-group" is the key, not "z"
		mail.SortSubject: {2, 1, 3},
		mail.SortDate:    {1, 2, 3},
	} {
		if got := mail.SortMessages(msgs, []mail.SortCriterion{{Key: key}}, expr, load); !slices.Equal(got, want) {
			t.Errorf("key %d: got %v want %v", key, got, want)
		}
	}
}

func TestBaseSubject(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]struct {
		base  string
		reply bool
	}{
		"Re: Fwd: [list] Re[2]: hello (fwd)": {"hello", true},
		"[fwd: re: hi]":                      {"hi", true},
		"  plain   subject ":                 {"plain subject", false},
		"[only blob]":                        {"[only blob]", false},
		"[list] news":                        {"news", false},
		"Reply to all":                       {"Reply to all", false},
	} {
		if base, reply := mail.BaseSubject(in); base != want.base || reply != want.reply {
			t.Errorf("%q: got %q %v want %q %v", in, base, reply, want.base, want.reply)
		}
	}
}

// TestThreadReferencesTree checks the RFC 5256 REFERENCES shapes imaptest expects: nested replies,
// a dummy for a missing parent, and grouping by base subject.
func TestThreadReferencesTree(t *testing.T) {
	t.Parallel()

	expr := mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}
	shape := func(n *mail.ThreadNode) string {
		var f func(n *mail.ThreadNode) string
		f = func(n *mail.ThreadNode) string {
			s := strconv.Itoa(int(n.Seq))
			for _, c := range n.Children {
				s += "(" + f(c) + ")"
			}
			return s
		}
		return f(n)
	}
	run := func(raws ...string) []string {
		msgs := make([]mail.Message, len(raws))
		for i := range msgs {
			msgs[i] = mail.Message{UID: uint32(i + 1), Meta: storage.EmailMeta{ReceivedAt: int64(i)}}
		}
		load := mail.BytesLoader(func(m mail.Message) ([]byte, error) { return []byte(raws[m.UID-1] + "\r\n\r\n"), nil })
		var out []string
		for _, th := range mail.ThreadReferences(msgs, expr, load) {
			out = append(out, shape(th))
		}
		return out
	}
	for name, tc := range map[string]struct {
		raws []string
		want []string
	}{
		"nested": {[]string{
			"Message-ID: <1@x>",
			"Message-ID: <2@x>\r\nReferences: <1@x>",
			"Message-ID: <3@x>\r\nReferences: <1@x>",
			"Message-ID: <4@x>\r\nReferences: <1@x> <2@x>",
		}, []string{"1(2(4))(3)"}},
		"missing parent": {[]string{
			"Message-ID: <1@x>\r\nReferences: <gone@x>",
			"Message-ID: <2@x>\r\nReferences: <gone@x>",
		}, []string{"0(1)(2)"}},
		"subject": {[]string{
			"Message-ID: <1@x>\r\nSubject: hello",
			"Message-ID: <2@x>\r\nSubject: Re: hello",
			"Message-ID: <3@x>\r\nSubject: other",
		}, []string{"1(2)", "3"}},
	} {
		if got := run(tc.raws...); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v want %v", name, got, tc.want)
		}
	}
}

// subjectMsgs returns one message per subject, UIDs from 1, all with the same date.
func subjectMsgs(subjects ...string) ([]mail.Message, mail.RawLoader) {
	msgs := make([]mail.Message, len(subjects))
	for i := range subjects {
		msgs[i] = mail.Message{UID: uint32(i + 1)}
	}
	load := mail.BytesLoader(func(m mail.Message) ([]byte, error) {
		return []byte("From: a@b\r\nSubject: " + subjects[m.UID-1] + "\r\nDate: Fri, 10 Jan 2025 12:00:00 +0000\r\n\r\n"), nil
	})
	return msgs, load
}

// RFC 5256 7 and RFC 5051: strings collate as i;unicode-casemap (titlecase, then decomposition).
// Upper-casing alone put a precomposed "É" after "Z" and kept "Ⅳ" apart from "IV".
func TestSortUnicodeCasemap(t *testing.T) {
	t.Parallel()
	all := mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}
	msgs, load := subjectMsgs("zeta", "Élan", "alpha", "éclair", "Ⅳ", "iv b")
	got := mail.SortMessages(msgs, []mail.SortCriterion{{Key: mail.SortSubject}}, all, load)
	if want := []uint32{3, 4, 2, 5, 6, 1}; !slices.Equal(got, want) {
		t.Fatalf("SORT SUBJECT %v, want %v", got, want)
	}
	// Invalid UTF-8 is compared as octets, not dropped.
	msgs, load = subjectMsgs("b", "\xff", "a")
	if got := mail.SortMessages(msgs, []mail.SortCriterion{{Key: mail.SortSubject}}, all, load); !slices.Equal(got, []uint32{3, 1, 2}) {
		t.Fatalf("invalid UTF-8: %v", got)
	}
}

// RFC 5256 4 step 6: the subject table compares with the same collation.
func TestThreadSubjectCasemap(t *testing.T) {
	t.Parallel()
	all := mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}
	msgs, load := subjectMsgs("Hello", "Re: HELLO", "été", "Re: ÉTÉ")
	if got := mail.ThreadReferences(msgs, all, load); len(got) != 2 {
		t.Fatalf("%d threads, want 2", len(got))
	}
}

// A References field of 20000 ids (inside the 256 KiB header limit) built its chain in O(K^2):
// about 0.25 s per message, for every THREAD of the folder.
func TestThreadLongReferences(t *testing.T) {
	t.Parallel()
	msgs := make([]mail.Message, 10)
	for i := range msgs {
		msgs[i].UID = uint32(i + 1)
	}
	load := mail.BytesLoader(func(m mail.Message) ([]byte, error) {
		var b strings.Builder
		b.WriteString("References:")
		for i := range 20000 {
			b.WriteString(" <" + strconv.Itoa(int(m.UID)) + "." + strconv.Itoa(i) + "@x>")
		}
		b.WriteString("\r\n\r\n")
		return []byte(b.String()), nil
	})
	all := mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}
	start := time.Now()
	mail.ThreadReferences(msgs, all, load)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("THREAD of 10 messages took %v", d)
	}
}

// A chain far deeper than any real thread, built cheaply by a few large messages, then cited with
// a root that has children by thousands of small ones: each link walked the whole chain, minutes
// of CPU per THREAD at full scale. The walk is bounded per message.
func TestThreadDeepChainWalk(t *testing.T) {
	t.Parallel()
	const chains, chainLen, pairs = 5, 20000, 3000
	msgs := make([]mail.Message, chains+2*pairs)
	for i := range msgs {
		msgs[i].UID = uint32(i + 1)
	}
	bottom := "<c" + strconv.Itoa(chains*chainLen-1) + "@x>"
	load := mail.BytesLoader(func(m mail.Message) ([]byte, error) {
		var b strings.Builder
		b.WriteString("Message-ID: <m" + strconv.Itoa(int(m.UID)) + "@x>\r\nReferences:")
		switch i := int(m.UID) - 1; {
		case i < chains: // each chain message starts at the end of the previous one
			for j := max(0, i*chainLen-1); j < (i+1)*chainLen; j++ {
				b.WriteString(" <c" + strconv.Itoa(j) + "@x>")
			}
		case (i-chains)%2 == 0: // <p_k> gets a child
			b.WriteString(" <p" + strconv.Itoa((i-chains)/2) + "@x>")
		default: // the bottom of the chain, then <p_k>
			b.WriteString(" " + bottom + " <p" + strconv.Itoa((i-chains)/2) + "@x>")
		}
		b.WriteString("\r\n\r\n")
		return []byte(b.String()), nil
	})
	all := mail.SearchExpr{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{All: true}}
	start := time.Now()
	threads := mail.ThreadReferences(msgs, all, load)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("THREAD of %d messages took %v", len(msgs), d)
	}
	if len(threads) == 0 {
		t.Fatal("no threads")
	}
}
