// Core persisted record types (msgpack in KV envelope).
package storage

// Tenant groups domains for multi-tenant installs (default install uses id 1).
type Tenant struct {
	ID   uint32 `msgpack:"id"`
	Name string `msgpack:"n"`
	// ExternalID is an optional caller-chosen key, unique across tenants (idempotent create).
	ExternalID string `msgpack:"x,omitempty"`
	// StorageLimit caps the summed mailbox usage of all accounts in the tenant (bytes, 0 = unlimited).
	StorageLimit uint64 `msgpack:"sl,omitempty"`
	// LoginDisabled blocks IMAP/SMTP/API login for every account in the tenant; mail is still received.
	LoginDisabled bool `msgpack:"ld,omitempty"`
}

// APIKey is a long-lived integration credential; only the SHA-256 of its secret is stored.
type APIKey struct {
	ID      uint32 `msgpack:"id"`
	Name    string `msgpack:"n"`
	Role    string `msgpack:"r"`
	Hash    []byte `msgpack:"h"`
	Created int64  `msgpack:"c"` // Unix seconds
}

// Domain is a mail domain (e.g. example.com) with optional hosting settings.
type Domain struct {
	ID       uint32 `msgpack:"id"`
	TenantID uint32 `msgpack:"tid"`
	Name     string `msgpack:"n"`

	// CatchAllLocal is an existing mailbox local-part that receives unknown RCPT (empty = reject).
	CatchAllLocal string `msgpack:"ca,omitempty"`
	// MailHostname is the TLS/SNI name (e.g. mail.example.com); required for SSL modes other than none.
	MailHostname string `msgpack:"mh,omitempty"`

	// SSLMode is none (default), custom (PEM on disk), or acme (HTTP-01 Let's Encrypt).
	SSLMode string `msgpack:"ssm,omitempty"`

	DKIMEnabled  bool   `msgpack:"dk,omitempty"`
	DKIMSelector string `msgpack:"dks,omitempty"`

	AntiSpam bool `msgpack:"as,omitempty"`
	// LoginDisabled blocks IMAP/SMTP/API login for every account on the domain; mail is still received.
	LoginDisabled bool `msgpack:"ld,omitempty"`

	// SendMaxMessages / SendWindow override global submission rate (0 / empty = global).
	SendMaxMessages int    `msgpack:"smx,omitempty"`
	SendWindow      string `msgpack:"sw,omitempty"`

	// StorageBytes / Messages are default mailbox quotas for accounts on this domain (0 = global).
	StorageBytes uint64 `msgpack:"qb,omitempty"`
	Messages     uint32 `msgpack:"qm,omitempty"`

	// Relay* override global outbound relay when RelayHost is set.
	RelayHost     string `msgpack:"rh,omitempty"`
	RelayUser     string `msgpack:"ru,omitempty"`
	RelayPassword string `msgpack:"rp,omitempty"`
	RelayStartTLS bool   `msgpack:"rt,omitempty"`
}

// Domain SSL modes.
const (
	DomainSSLNone   = "none"
	DomainSSLCustom = "custom"
	DomainSSLACME   = "acme"
)

// Account is a mailbox owner within a domain.
type Account struct {
	ID        uint32 `msgpack:"id"`
	DomainID  uint32 `msgpack:"dom"`
	TenantID  uint32 `msgpack:"tid,omitempty"` // denormalized from domain; 0 = legacy, fill on read
	LocalPart string `msgpack:"lp"`
	Role      string `msgpack:"role,omitempty"` // user | admin | tenant_admin; empty = user
	Active    bool   `msgpack:"act"`
}

// Mailbox is an IMAP/JMAP mailbox belonging to an account.
type Mailbox struct {
	ID            uint32 `msgpack:"id"`
	Name          string `msgpack:"n"`
	Role          string `msgpack:"r,omitempty"`
	UIDNext       uint32 `msgpack:"un"`
	UIDValidity   uint32 `msgpack:"uv"`
	HighestModSeq uint64 `msgpack:"hm,omitempty"`
	UIDSeqInit    bool   `msgpack:"ui,omitempty"` // true once per-mailbox IMAP UID backfill completed
	MessageCount  uint32 `msgpack:"mc,omitempty"` // denormalized messages in folder; 0 until first sync/bump
	Subscribed    bool   `msgpack:"sub,omitempty"`
	SubSet        bool   `msgpack:"ss,omitempty"` // true once SUBSCRIBE/UNSUBSCRIBE touched this folder
}

// EmailMeta is persisted mail metadata; raw body is inline KV or blob fs (BlobHash).
type EmailMeta struct {
	Version    uint8    `msgpack:"v"`
	MailboxID  uint32   `msgpack:"mb"`
	ThreadID   uint32   `msgpack:"th"`
	ReceivedAt int64    `msgpack:"rcv"`
	Size       uint32   `msgpack:"sz"`
	Flags      uint32   `msgpack:"fl"`
	ModSeq     uint64   `msgpack:"ms,omitempty"`
	IMAPUID    uint32   `msgpack:"iu,omitempty"` // IMAP UID in MailboxID; 0 until assigned or legacy backfill
	BlobHash   [32]byte `msgpack:"bh,omitempty"`
	Keywords   []string `msgpack:"kw,omitempty"` // IMAP custom keywords (non-system flags)
}

// QueueRecipient is one RCPT in an outbound queue record.
type QueueRecipient struct {
	Address     string `msgpack:"a"`
	Retry       uint32 `msgpack:"r"`
	Flags       uint64 `msgpack:"f"`
	LastAttempt int64  `msgpack:"la,omitempty"` // unix milliseconds; 0 = never tried
	NextDue     int64  `msgpack:"nd,omitempty"` // unix milliseconds; 0 = due now
	Notify      uint8  `msgpack:"nt,omitempty"` // NotifyFlags; 0 = default FAILURE|DELAY
	Orcpt       string `msgpack:"oc,omitempty"`
	LastDiag    string `msgpack:"ld,omitempty"` // last SMTP diagnostic (error, or accepting server reply once delivered)
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
	Ret            string           `msgpack:"ret,omitempty"`  // FULL or HDRS
	Envid          string           `msgpack:"envid,omitempty"`
	Body           string           `msgpack:"body,omitempty"` // 7BIT or 8BITMIME
	Done           int64            `msgpack:"dn,omitempty"`   // unix ms when no recipient was left pending; kept as history until retention
}

// HasBlob reports whether BlobHash points at filesystem blob storage.
func (m EmailMeta) HasBlob() bool {
	return m.BlobHash != [32]byte{}
}

// HasBlob reports whether BlobHash points at filesystem blob storage.
func (m QueueMessage) HasBlob() bool {
	return m.BlobHash != [32]byte{}
}
