// Core persisted record types (msgpack in KV envelope).
package storage

// Tenant groups domains for multi-tenant installs (default install uses id 1).
type Tenant struct {
	ID   uint32 `msgpack:"id"`
	Name string `msgpack:"n"`
}

// Domain is a mail domain (e.g. example.com).
type Domain struct {
	ID       uint32 `msgpack:"id"`
	TenantID uint32 `msgpack:"tid"`
	Name     string `msgpack:"n"`
}

// Account is a mailbox owner within a domain.
type Account struct {
	ID        uint32 `msgpack:"id"`
	DomainID  uint32 `msgpack:"dom"`
	LocalPart string `msgpack:"lp"`
	Active    bool   `msgpack:"act"`
}

// Mailbox is an IMAP/JMAP mailbox belonging to an account.
type Mailbox struct {
	ID          uint32 `msgpack:"id"`
	Name        string `msgpack:"n"`
	Role        string `msgpack:"r,omitempty"`
	UIDNext     uint32 `msgpack:"un"`
	UIDValidity uint32 `msgpack:"uv"`
}

// EmailMeta is persisted mail metadata; raw body is inline KV or blob fs (BlobHash).
type EmailMeta struct {
	Version    uint8    `msgpack:"v"`
	MailboxID  uint32   `msgpack:"mb"`
	ThreadID   uint32   `msgpack:"th"`
	ReceivedAt int64    `msgpack:"rcv"`
	Size       uint32   `msgpack:"sz"`
	Flags      uint32   `msgpack:"fl"`
	BlobHash   [32]byte `msgpack:"bh,omitempty"`
}

// QueueRecipient is one RCPT in an outbound queue record.
type QueueRecipient struct {
	Address     string `msgpack:"a"`
	Retry       uint32 `msgpack:"r"`
	Flags       uint64 `msgpack:"f"`
	LastAttempt int64  `msgpack:"la,omitempty"` // unix milliseconds; 0 = never tried
	NextDue     int64  `msgpack:"nd,omitempty"` // unix milliseconds; 0 = due now
}

// QueueMessage is an SMTP queue entry (SubspaceQueue).
type QueueMessage struct {
	Created        uint64           `msgpack:"c"`
	BlobHash       [32]byte         `msgpack:"bh"`
	ReturnPath     string           `msgpack:"rp"`
	Recipients     []QueueRecipient `msgpack:"rc"`
	ReceivedFromIP [16]byte         `msgpack:"ip"`
	Flags          uint64           `msgpack:"fl"`
	Size           uint64           `msgpack:"sz"`
}

// HasBlob reports whether BlobHash points at filesystem blob storage.
func (m EmailMeta) HasBlob() bool {
	return m.BlobHash != [32]byte{}
}

// HasBlob reports whether BlobHash points at filesystem blob storage.
func (m QueueMessage) HasBlob() bool {
	return m.BlobHash != [32]byte{}
}
