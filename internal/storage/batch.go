// Batch collects ordered write operations for a single Commit transaction.
package storage

import (
	"encoding/binary"
	"errors"
)

// ErrBatchNoAccount is returned when a batch op runs without WithAccount.
var ErrBatchNoAccount = errors.New("storage: batch missing account")

// ErrBatchSuffixTooShort is returned when suffix lacks collection and document_id.
var ErrBatchSuffixTooShort = errors.New("storage: batch suffix shorter than 5 bytes")

// ErrCASConflict is returned when an Assert does not match the stored value.
var ErrCASConflict = errors.New("storage: compare-and-swap failed")

// ErrNotFound is returned when a key is absent.
var ErrNotFound = errors.New("storage: not found")

// ErrUnknownSubspace is returned for an unsupported subspace byte.
var ErrUnknownSubspace = errors.New("storage: unknown subspace")

// batchSuffixHeadLen is collection(1) + document_id(4) embedded in Set/Assert suffix.
const batchSuffixHeadLen = 5

// OpKind identifies a batch operation type.
type OpKind uint8

const (
	OpSet OpKind = iota
	OpAssert
	OpDelete
)

// BatchOp is one ordered write step executed inside Commit.
type BatchOp struct {
	Kind     OpKind
	Subspace byte
	Key      []byte
	Value    []byte
	Expect   []byte
}

// Batch holds pending writes for one account (see WithAccount).
type Batch struct {
	accountID uint32
	accountOK bool
	keyBuf    []byte
	ops       []BatchOp
}

// NewBatch returns a batch with a pre-allocated key buffer.
func NewBatch() *Batch {
	return &Batch{
		keyBuf: make([]byte, 0, DefaultBufCap),
	}
}

// WithAccount pins the account_id used to build keys from Set/Assert suffixes.
func (b *Batch) WithAccount(id uint32) *Batch {
	b.accountID = id
	b.accountOK = true
	return b
}

// Set queues an upsert. suffix is collection(1) | document_id(4 BE) | tail.
func (b *Batch) Set(subspace byte, suffix, value []byte) error {
	key, err := b.appendOpKey(subspace, suffix)
	if err != nil {
		return err
	}
	b.ops = append(b.ops, BatchOp{
		Kind:     OpSet,
		Subspace: subspace,
		Key:      append([]byte(nil), key...),
		Value:    append([]byte(nil), value...),
	})
	return nil
}

// SetRaw queues an upsert using a full wire key (no WithAccount required).
func (b *Batch) SetRaw(key, value []byte) error {
	if len(key) < KeyPrefixLen {
		return ErrKeyTooShort
	}
	if err := checkSubspace(key[0]); err != nil {
		return err
	}
	b.ops = append(b.ops, BatchOp{
		Kind:     OpSet,
		Subspace: key[0],
		Key:      append([]byte(nil), key...),
		Value:    append([]byte(nil), value...),
	})
	return nil
}

// Assert queues a CAS check. expect nil means the key must be absent.
func (b *Batch) Assert(subspace byte, suffix, expect []byte) error {
	key, err := b.appendOpKey(subspace, suffix)
	if err != nil {
		return err
	}
	var expCopy []byte
	if expect != nil {
		expCopy = append([]byte(nil), expect...)
	}
	b.ops = append(b.ops, BatchOp{
		Kind:     OpAssert,
		Subspace: subspace,
		Key:      append([]byte(nil), key...),
		Expect:   expCopy,
	})
	return nil
}

// Delete queues a key removal. suffix is collection(1) | document_id(4 BE) | tail.
func (b *Batch) Delete(subspace byte, suffix []byte) error {
	key, err := b.appendOpKey(subspace, suffix)
	if err != nil {
		return err
	}
	b.ops = append(b.ops, BatchOp{
		Kind:     OpDelete,
		Subspace: subspace,
		Key:      append([]byte(nil), key...),
	})
	return nil
}

// Ops returns pending operations in commit order.
func (b *Batch) Ops() []BatchOp {
	return b.ops
}

// Reset clears pending ops and reuses buffers.
func (b *Batch) Reset() {
	b.ops = b.ops[:0]
	b.keyBuf = b.keyBuf[:0]
}

func (b *Batch) appendOpKey(subspace byte, suffix []byte) ([]byte, error) {
	if !b.accountOK {
		return nil, ErrBatchNoAccount
	}
	if len(suffix) < batchSuffixHeadLen {
		return nil, ErrBatchSuffixTooShort
	}
	collection := suffix[0]
	documentID := binary.BigEndian.Uint32(suffix[1:batchSuffixHeadLen])
	tail := suffix[batchSuffixHeadLen:]
	b.keyBuf = b.keyBuf[:0]
	b.keyBuf = AppendKey(b.keyBuf, subspace, b.accountID, documentID, collection, tail)
	return b.keyBuf, nil
}

// checkSubspace returns ErrUnknownSubspace when sub is not a known table letter.
func checkSubspace(sub byte) error {
	for _, s := range Subspaces() {
		if s == sub {
			return nil
		}
	}
	return ErrUnknownSubspace
}

// BatchSuffix builds the suffix head for collection and document_id.
func BatchSuffix(collection byte, documentID uint32, tail []byte) []byte {
	buf := make([]byte, batchSuffixHeadLen+len(tail))
	buf[0] = collection
	binary.BigEndian.PutUint32(buf[1:batchSuffixHeadLen], documentID)
	copy(buf[batchSuffixHeadLen:], tail)
	return buf
}
