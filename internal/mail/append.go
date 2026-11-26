// Append stores a client-uploaded message into a mailbox (IMAP APPEND).
package mail

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
)

// MaxAppendBytes is the largest RFC 5322 blob accepted via IMAP APPEND.
const MaxAppendBytes = 32 << 20

// Append stores raw bytes in mailboxID with optional IMAP flags.
// receivedAt is Unix seconds for INTERNALDATE; when <= 0, uses the current time.
func (ib *Inbox) Append(ctx context.Context, accountID, mailboxID uint32, raw []byte, flags uint32, receivedAt int64) (uint32, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("mail: empty message")
	}
	if len(raw) > MaxAppendBytes {
		return 0, fmt.Errorf("mail: message too large")
	}
	if _, err := ib.mailboxRecord(ctx, accountID, mailboxID); err != nil {
		return 0, err
	}
	if receivedAt <= 0 {
		receivedAt = time.Now().Unix()
	}
	return ib.storeMessage(ctx, accountID, mailboxID, raw, flags, receivedAt)
}

// StoredBlob is a message already in the blob store: its digest, size and wire (CRLF) size.
type StoredBlob struct {
	Hash  [storage.Blake3DigestLen]byte
	Size  uint32
	VSize uint32
}

// AppendMessage is one message of AppendMany.
type AppendMessage struct {
	Blob       StoredBlob
	Flags      uint32
	Keywords   []string
	ReceivedAt int64 // Unix seconds; <= 0 means now
}

// Appended is where AppendMany stored one message.
type Appended struct {
	EmailID, UID uint32
}

// AppendMany stores msgs in mailboxID in one transaction, in order: all of them or none, and no
// other session sees a part of them (IMAP MULTIAPPEND, RFC 3502). The quota covers their total.
func (ib *Inbox) AppendMany(ctx context.Context, accountID, mailboxID uint32, msgs []AppendMessage) ([]Appended, error) {
	var total uint64
	now := time.Now().Unix()
	for i := range msgs {
		total += uint64(msgs[i].Blob.Size)
		if msgs[i].ReceivedAt <= 0 {
			msgs[i].ReceivedAt = now
		}
	}
	if err := ib.checkQuota(ctx, accountID, total, uint32(len(msgs))); err != nil {
		return nil, err
	}
	return ib.storeMessages(ctx, accountID, mailboxID, msgs)
}

// CheckQuota is an early refusal before a message is uploaded: ErrOverQuota when adding messages
// of addBytes would pass a limit. The store transaction checks again.
func (ib *Inbox) CheckQuota(ctx context.Context, accountID uint32, addBytes uint64, addMessages uint32) error {
	return ib.checkQuota(ctx, accountID, addBytes, addMessages)
}

// Upload streams one message to the blob store as it arrives, so an APPEND never holds it in
// memory (as Dovecot saves it). It is stored as sent, unless Finish must rewrite it.
type Upload struct {
	ib     *Inbox
	w      *blob.Writer
	size   int
	vsize  int  // size with every bare LF counted as CRLF (wireSize)
	prev   byte // last byte written
	bareCR bool // a CR not followed by LF: BareCR must rewrite the message
}

// NewUpload starts an Upload; Finish or Abort ends it.
func (ib *Inbox) NewUpload(ctx context.Context) (*Upload, error) {
	w, err := ib.blobs.Create(ctx)
	if err != nil {
		return nil, err
	}
	return &Upload{ib: ib, w: w}, nil
}

func (u *Upload) Write(p []byte) (int, error) {
	for _, c := range p {
		if u.prev == '\r' && c != '\n' {
			u.bareCR = true
		}
		if c == '\n' && u.prev != '\r' {
			u.vsize++
		}
		u.prev = c
	}
	u.size += len(p)
	u.vsize += len(p)
	return u.w.Write(p)
}

// Size is the number of bytes written so far.
func (u *Upload) Size() int { return u.size }

// NeedsRewrite reports whether Finish will load the message to rewrite it: with a bare CR
// (BareCR), or when the caller passes a rewrite of its own.
func (u *Upload) NeedsRewrite() bool { return u.bareCR || u.prev == '\r' }

// Finish stores the upload. When rewrite is not nil or the message holds a bare CR, the message is
// read back into memory, passed through rewrite, then BareCR, and stored again; the caller bounds
// how many do that at once.
func (u *Upload) Finish(ctx context.Context, rewrite func([]byte) []byte) (StoredBlob, error) {
	if rewrite == nil && !u.NeedsRewrite() {
		hash, err := u.w.Commit()
		return StoredBlob{Hash: hash, Size: uint32(u.size), VSize: uint32(u.vsize)}, err
	}
	raw, err := os.ReadFile(u.w.Name())
	u.w.Abort()
	if err != nil {
		return StoredBlob{}, err
	}
	if rewrite != nil {
		raw = rewrite(raw)
	}
	// Bare CR as Exim treats it (BareCR): never a line end inside a header field.
	raw = BareCR(raw)
	hash, err := u.ib.blobs.Put(ctx, raw)
	return StoredBlob{Hash: hash, Size: uint32(len(raw)), VSize: wireSize(raw)}, err
}

// Abort drops an upload not finished.
func (u *Upload) Abort() { u.w.Abort() }
