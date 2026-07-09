// Mailbox email membership keys in SubspaceIndex (range scan per folder).
package storage

import "encoding/binary"

// MailboxIndexSentinelEmailID marks a mailbox index as built (folder may be empty).
const MailboxIndexSentinelEmailID uint32 = 0

// MailboxIndexEntryValue is the minimal index payload (presence only).
var MailboxIndexEntryValue = []byte{1}

// MailboxIndexSuffix builds batch suffix: collection | mailbox_id | email_id (4 BE).
func MailboxIndexSuffix(mailboxID, emailID uint32) []byte {
	var tail [4]byte
	binary.BigEndian.PutUint32(tail[:], emailID)
	return BatchSuffix(byte(CollectionMailboxEmailIndex), mailboxID, tail[:])
}

// AppendMailboxIndexKey appends a full SubspaceIndex key for one mailbox membership row.
func AppendMailboxIndexKey(buf []byte, accountID, mailboxID, emailID uint32) []byte {
	return AppendKey(buf, SubspaceIndex, accountID, mailboxID, byte(CollectionMailboxEmailIndex), mailboxIndexEmailTail(emailID))
}

// MailboxIndexRange returns [from, to) keys for all emails in mailboxID (inclusive max email id).
func MailboxIndexRange(accountID, mailboxID uint32) (from, to []byte) {
	from = AppendKey(nil, SubspaceIndex, accountID, mailboxID, byte(CollectionMailboxEmailIndex), nil)
	to = AppendKey(nil, SubspaceIndex, accountID, mailboxID, byte(CollectionMailboxEmailIndex), []byte{0xff, 0xff, 0xff, 0xff})
	return from, to
}

// EmailIDFromMailboxIndexKey decodes email id from an index key suffix (document_id = mailbox id).
func EmailIDFromMailboxIndexKey(key []byte) (emailID uint32, err error) {
	parts, err := DecodeKey(key)
	if err != nil {
		return 0, err
	}
	if parts.Collection != byte(CollectionMailboxEmailIndex) || len(parts.Suffix) < 4 {
		return 0, ErrKeyTooShort
	}
	return binary.BigEndian.Uint32(parts.Suffix[:4]), nil
}

func mailboxIndexEmailTail(emailID uint32) []byte {
	var tail [4]byte
	binary.BigEndian.PutUint32(tail[:], emailID)
	return tail[:]
}
