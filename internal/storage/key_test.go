package storage_test

import (
	"bytes"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

func TestDecodeKeyRoundtrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		subspace   byte
		accountID  uint32
		documentID uint32
		collection byte
		suffix     []byte
	}{
		{"zeros empty suffix", storage.SubspaceMail, 0, 0, 1, nil},
		{"max ids", storage.SubspaceIndex, ^uint32(0), ^uint32(0), ^byte(0), nil},
		{"with suffix", storage.SubspaceQueue, 42, 1001, 3, []byte{0xde, 0xad}},
		{"long suffix", storage.SubspaceTags, 1, 2, 4, bytes.Repeat([]byte{'x'}, 128)},
		{"all subspaces", storage.SubspaceAccount, 7, 9, 2, []byte("field")},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := storage.AppendKey(nil, tc.subspace, tc.accountID, tc.documentID, tc.collection, tc.suffix)
			got, err := storage.DecodeKey(key)
			if err != nil {
				t.Fatalf("DecodeKey: %v", err)
			}
			if got.Subspace != tc.subspace {
				t.Errorf("subspace: got %q want %q", got.Subspace, tc.subspace)
			}
			if got.AccountID != tc.accountID {
				t.Errorf("accountID: got %d want %d", got.AccountID, tc.accountID)
			}
			if got.Collection != tc.collection {
				t.Errorf("collection: got %d want %d", got.Collection, tc.collection)
			}
			if got.DocumentID != tc.documentID {
				t.Errorf("documentID: got %d want %d", got.DocumentID, tc.documentID)
			}
			if !bytes.Equal(got.Suffix, tc.suffix) {
				t.Errorf("suffix: got %q want %q", got.Suffix, tc.suffix)
			}
		})
	}
}

func TestAppendKeyBigEndianLayout(t *testing.T) {
	t.Parallel()

	key := storage.AppendKey(nil, 'm', 0x01020304, 0x05060708, 0x09, []byte{0xaa})
	want := []byte{
		'm',
		0x01, 0x02, 0x03, 0x04,
		0x09,
		0x05, 0x06, 0x07, 0x08,
		0xaa,
	}
	if !bytes.Equal(key, want) {
		t.Fatalf("key bytes:\n got % x\nwant % x", key, want)
	}
}

func TestAppendKeyReusesBuffer(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 0, storage.DefaultBufCap)
	origCap := cap(buf)

	for i := 0; i < 100; i++ {
		buf = buf[:0]
		buf = storage.AppendKey(buf, storage.SubspaceMail, uint32(i), uint32(i+1), 1, []byte{byte(i)})
		if cap(buf) != origCap {
			t.Fatalf("iteration %d: cap grew from %d to %d", i, origCap, cap(buf))
		}
	}
}

func TestDecodeKeyTooShort(t *testing.T) {
	t.Parallel()

	_, err := storage.DecodeKey(make([]byte, storage.KeyPrefixLen-1))
	if err != storage.ErrKeyTooShort {
		t.Fatalf("got err %v want %v", err, storage.ErrKeyTooShort)
	}
}

func TestKeyLexicographicOrderMatchesUint32BE(t *testing.T) {
	t.Parallel()

	keys := [][]byte{
		storage.AppendKey(nil, 'm', 1, 1, 1, nil),
		storage.AppendKey(nil, 'm', 1, 2, 1, nil),
		storage.AppendKey(nil, 'm', 1, 2, 1, []byte{0x00}),
		storage.AppendKey(nil, 'm', 2, 0, 0, nil),
	}
	for i := 1; i < len(keys); i++ {
		if bytes.Compare(keys[i-1], keys[i]) >= 0 {
			t.Fatalf("keys[%d] should sort before keys[%d]", i-1, i)
		}
	}
}

func TestAppendKeyPrefix(t *testing.T) {
	t.Parallel()

	full := storage.AppendKey(nil, 'i', 10, 20, 2, []byte("suffix"))
	prefix6 := storage.AppendKeyPrefix(nil, 'i', 10, 20, 2, 6)
	if !bytes.Equal(prefix6, full[:6]) {
		t.Fatalf("6-byte prefix:\n got % x\nwant % x", prefix6, full[:6])
	}
	prefix10 := storage.AppendKeyPrefix(nil, 'i', 10, 20, 2, 10)
	if !bytes.Equal(prefix10, full[:10]) {
		t.Fatalf("10-byte prefix:\n got % x\nwant % x", prefix10, full[:10])
	}
}
