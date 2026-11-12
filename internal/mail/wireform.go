// The wire form of stored messages. Like Dovecot (mail_save_crlf = no), messages are stored as
// received, mostly with LF line ends (DATA), sometimes CRLF (APPEND, BDAT), even mixed; IMAP sees
// them with CRLF line ends (RFC 3501 2.3.4, RFC 5322 2.1), and RFC822.SIZE is that size (the
// "virtual size"), computed once and kept in EmailMeta.VSize.
package mail

import (
	"bufio"
	"context"
	"io"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// wireSize is the size of raw once every bare LF becomes CRLF.
func wireSize(raw []byte) uint32 {
	n := len(raw)
	for i, c := range raw {
		if c == '\n' && (i == 0 || raw[i-1] != '\r') {
			n++
		}
	}
	return uint32(n)
}

// wireForm returns raw with every bare LF turned into CRLF. Bare CR is left alone: ingest turns it
// into a line end (see BareCR), and turning it into CRLF here would change line counts.
func wireForm(raw []byte) []byte {
	if int(wireSize(raw)) == len(raw) {
		return raw
	}
	out := make([]byte, 0, wireSize(raw))
	for i, c := range raw {
		if c == '\n' && (i == 0 || raw[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, c)
	}
	return out
}

// RFC822Size is the IMAP RFC822.SIZE of a message: its size with CRLF line ends. Before the
// backfill of an old mailbox has run, the stored size stands in.
func RFC822Size(meta storage.EmailMeta) uint32 {
	if meta.VSize != 0 {
		return meta.VSize
	}
	return meta.Size
}

// LoadMessage returns the message in wire form (CRLF line ends), as IMAP sends it.
func (ib *Inbox) LoadMessage(ctx context.Context, meta storage.EmailMeta) ([]byte, error) {
	raw, err := ib.LoadRaw(ctx, meta)
	if err != nil {
		return nil, err
	}
	return wireForm(raw), nil
}

// OpenMessage streams the message in wire form; its length is RFC822Size(meta) once the mailbox
// backfill has run. The caller closes it.
func (ib *Inbox) OpenMessage(ctx context.Context, meta storage.EmailMeta) (io.ReadCloser, error) {
	f, err := ib.OpenRaw(ctx, meta)
	if err != nil {
		return nil, err
	}
	return &crlfReader{r: bufio.NewReader(f), c: f}, nil
}

// crlfReader turns bare LF into CRLF as it reads.
type crlfReader struct {
	r       *bufio.Reader
	c       io.Closer
	lastCR  bool // the previous byte read was CR
	pending bool // a LF is owed after the CR just returned
}

func (cr *crlfReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if cr.pending {
			p[n] = '\n'
			n++
			cr.pending, cr.lastCR = false, false
			continue
		}
		b, err := cr.r.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		if b == '\n' && !cr.lastCR {
			p[n] = '\r'
			n++
			cr.pending = true
			continue
		}
		p[n] = b
		n++
		cr.lastCR = b == '\r'
		if cr.r.Buffered() == 0 && n > 0 {
			break // do not block for more input once something is ready
		}
	}
	return n, nil
}

func (cr *crlfReader) Close() error { return cr.c.Close() }

// backfillVSize computes VSize for the messages of a mailbox stored before it existed, once per
// mailbox (like the IMAP UID backfill): RFC822.SIZE must match the bytes FETCH sends.
func (ib *Inbox) backfillVSize(ctx context.Context, accountID, mailboxID uint32, msgs []Message) error {
	var todo []int
	for i, m := range msgs {
		if m.Meta.VSize == 0 && m.Meta.HasBlob() {
			todo = append(todo, i)
		}
	}
	for start := 0; start < len(todo); start += 256 {
		batch := todo[start:min(start+256, len(todo))]
		sizes := make(map[int]uint32, len(batch))
		for _, i := range batch {
			raw, err := ib.LoadRaw(ctx, msgs[i].Meta)
			if err != nil {
				return err
			}
			sizes[i] = wireSize(raw)
		}
		err := ib.update(ctx, accountID, func(t *txn) error {
			for _, i := range batch {
				meta, err := t.meta(accountID, msgs[i].StorageID())
				if err != nil {
					continue // expunged meanwhile
				}
				meta.VSize = sizes[i]
				if err := t.putMeta(accountID, msgs[i].StorageID(), meta); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, i := range batch {
			msgs[i].Meta.VSize = sizes[i]
		}
	}
	return ib.update(ctx, accountID, func(t *txn) error {
		mbox, err := t.mailbox(accountID, mailboxID)
		if err != nil {
			return err
		}
		mbox.VSizeInit = true
		return t.putMailbox(accountID, mbox)
	})
}
