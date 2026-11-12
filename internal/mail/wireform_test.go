package mail

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

type nopCloser struct{ io.Reader }

func (nopCloser) Close() error { return nil }

// The wire form (CRLF line ends) of LF, CRLF and mixed messages: the streamed reader gives exactly
// the bytes of wireForm, whatever the read sizes, and wireSize is their length (RFC822.SIZE).
func TestWireForm(t *testing.T) {
	for _, raw := range []string{
		"",
		"Subject: lf\n\nline one\nline two\n",
		"Subject: crlf\r\n\r\nbody\r\n",
		"Subject: mixed\r\nX: y\n\r\nbody\nmore\r\nend",
		"\n\n\r\n\n",
		"bare\rcr\r\rkept\r",
		strings.Repeat("a\nb\r\n", 5000),
	} {
		want := wireForm([]byte(raw))
		if int(wireSize([]byte(raw))) != len(want) {
			t.Fatalf("%.30q: wireSize %d, wire form %d bytes", raw, wireSize([]byte(raw)), len(want))
		}
		if strings.Contains(strings.ReplaceAll(string(want), "\r\n", ""), "\n") {
			t.Fatalf("%.30q: bare LF left in %q", raw, want)
		}
		for _, wrap := range []func(io.Reader) io.Reader{
			func(r io.Reader) io.Reader { return r },
			iotest.OneByteReader,
			iotest.HalfReader,
		} {
			cr := &crlfReader{r: bufio.NewReader(wrap(strings.NewReader(raw))), c: nopCloser{}}
			got, err := io.ReadAll(iotest.OneByteReader(cr))
			if err != nil || string(got) != string(want) {
				t.Fatalf("%.30q: streamed %q, want %q (%v)", raw, got, want, err)
			}
		}
	}
}

// Messages stored before VSize existed get it from the once-per-mailbox backfill run by List,
// so RFC822.SIZE matches the bytes FETCH sends.
func TestVSizeBackfill(t *testing.T) {
	ctx, inbox, acc := testInboxWithAccount(t)
	raw := []byte("Subject: old\n\nline one\nline two\n")
	id, err := inbox.Deliver(ctx, acc, raw)
	if err != nil {
		t.Fatal(err)
	}
	// Turn it into a message from before VSize: no VSize, mailbox not backfilled.
	err = inbox.update(ctx, acc, func(tx *txn) error {
		meta, err := tx.meta(acc, id)
		if err != nil {
			return err
		}
		meta.VSize = 0
		if err := tx.putMeta(acc, id, meta); err != nil {
			return err
		}
		mbox, err := tx.mailbox(acc, InboxMailboxID)
		if err != nil {
			return err
		}
		mbox.VSizeInit = false
		return tx.putMailbox(acc, mbox)
	})
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := inbox.List(ctx, acc, InboxMailboxID)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("list: %v %d", err, len(msgs))
	}
	if got, want := RFC822Size(msgs[0].Meta), uint32(len(raw)+4); got != want || msgs[0].Meta.Size != uint32(len(raw)) {
		t.Fatalf("RFC822Size %d (stored size %d), want %d", got, msgs[0].Meta.Size, want)
	}
	again, _ := inbox.List(ctx, acc, InboxMailboxID)
	if again[0].Meta.VSize != uint32(len(raw)+4) {
		t.Fatalf("VSize not persisted: %d", again[0].Meta.VSize)
	}
}

func testInboxWithAccount(t *testing.T) (context.Context, *Inbox, uint32) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	acc, err := directory.SeedDev(ctx, directory.NewLocal(store))
	if err != nil {
		t.Fatal(err)
	}
	return ctx, NewInbox(store, blob.NewFS(t.TempDir()+"/blobs")), acc.ID
}
