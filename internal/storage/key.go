// Key encoding for the logical KV store (fixed big-endian prefix + optional suffix).
package storage

import (
	"encoding/binary"
	"errors"
)

// KeyPrefixLen is the fixed prefix size: subspace | account | collection | document.
const KeyPrefixLen = 10

// ErrKeyTooShort is returned when a key cannot hold a full prefix.
var ErrKeyTooShort = errors.New("storage: key shorter than prefix")

// KeyParts holds decoded key fields. Suffix references the original key slice.
type KeyParts struct {
	Subspace   byte
	AccountID  uint32
	Collection byte
	DocumentID uint32
	Suffix     []byte
}

// AppendKey appends a full key to buf and returns the extended buffer.
// Wire layout: subspace(1) | account_id(4 BE) | collection(1) | document_id(4 BE) | suffix.
func AppendKey(buf []byte, subspace byte, accountID, documentID uint32, collection byte, suffix []byte) []byte {
	buf = append(buf, subspace)
	var scratch [4]byte
	binary.BigEndian.PutUint32(scratch[:], accountID)
	buf = append(buf, scratch[:]...)
	buf = append(buf, collection)
	binary.BigEndian.PutUint32(scratch[:], documentID)
	buf = append(buf, scratch[:]...)
	if len(suffix) > 0 {
		buf = append(buf, suffix...)
	}
	return buf
}

// AppendKeyPrefix appends the first n bytes of the key prefix for range scans.
// n must be in [1, KeyPrefixLen]; panics otherwise (programmer error).
func AppendKeyPrefix(buf []byte, subspace byte, accountID, documentID uint32, collection byte, n int) []byte {
	if n < 1 || n > KeyPrefixLen {
		panic("storage: AppendKeyPrefix n out of range")
	}
	var full [KeyPrefixLen]byte
	full[0] = subspace
	binary.BigEndian.PutUint32(full[1:5], accountID)
	full[5] = collection
	binary.BigEndian.PutUint32(full[6:10], documentID)
	return append(buf, full[:n]...)
}

// DecodeKey splits key into prefix fields and suffix.
func DecodeKey(key []byte) (KeyParts, error) {
	if len(key) < KeyPrefixLen {
		return KeyParts{}, ErrKeyTooShort
	}
	return KeyParts{
		Subspace:   key[0],
		AccountID:  binary.BigEndian.Uint32(key[1:5]),
		Collection: key[5],
		DocumentID: binary.BigEndian.Uint32(key[6:10]),
		Suffix:     key[KeyPrefixLen:],
	}, nil
}
