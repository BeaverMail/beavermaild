package storage_test

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/storage"
)

func TestMailboxIndexKeyRange(t *testing.T) {
	from, to := storage.MailboxIndexRange(9, 3)
	key := storage.AppendMailboxIndexKey(nil, 9, 3, 42)
	if string(key) < string(from) || string(key) > string(to) {
		t.Fatalf("key %x not in [%x, %x]", key, from, to)
	}
	emailID, err := storage.EmailIDFromMailboxIndexKey(key)
	if err != nil || emailID != 42 {
		t.Fatalf("emailID=%d err=%v", emailID, err)
	}
}

func TestMailboxIndexSuffixOrder(t *testing.T) {
	k1 := storage.AppendMailboxIndexKey(nil, 1, 2, 10)
	k2 := storage.AppendMailboxIndexKey(nil, 1, 2, 20)
	if string(k1) >= string(k2) {
		t.Fatalf("uid order: %x >= %x", k1, k2)
	}
}
