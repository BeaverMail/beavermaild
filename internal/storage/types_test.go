package storage_test

import (
	"bytes"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

func TestMarshalPersistCoreTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		v    any
	}{
		{"tenant", storage.Tenant{ID: 1, Name: "default"}},
		{"domain", storage.Domain{ID: 1, TenantID: 1, Name: "example.com"}},
		{"account", storage.Account{ID: 2, DomainID: 1, TenantID: 1, LocalPart: "alice", Role: "admin", Active: true}},
		{"mailbox", storage.Mailbox{ID: 3, Name: "INBOX", Role: "inbox", UIDNext: 10, UIDValidity: 99}},
		{"email", storage.EmailMeta{
			Version: 1, MailboxID: 3, ThreadID: 4, ReceivedAt: 1710000000,
			Size: 1200, Flags: 1,
		}},
		{"email-blob", storage.EmailMeta{
			Version: 1, MailboxID: 3, Size: 70000,
			BlobHash: [32]byte{1, 2, 3},
		}},
		{"queue", storage.QueueMessage{
			Created: 1, ReturnPath: "a@b.c", Size: 99,
			Recipients: []storage.QueueRecipient{{Address: "x@y.z", Retry: 1}},
		}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wire, err := storage.MarshalPersist(nil, 1, tc.v)
			if err != nil {
				t.Fatal(err)
			}

			switch want := tc.v.(type) {
			case storage.Tenant:
				var got storage.Tenant
				if err := storage.UnmarshalPersist(wire, &got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("got %+v want %+v", got, want)
				}
			case storage.Domain:
				var got storage.Domain
				if err := storage.UnmarshalPersist(wire, &got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("got %+v want %+v", got, want)
				}
			case storage.Account:
				var got storage.Account
				if err := storage.UnmarshalPersist(wire, &got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("got %+v want %+v", got, want)
				}
			case storage.Mailbox:
				var got storage.Mailbox
				if err := storage.UnmarshalPersist(wire, &got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("got %+v want %+v", got, want)
				}
			case storage.EmailMeta:
				var got storage.EmailMeta
				if err := storage.UnmarshalPersist(wire, &got); err != nil {
					t.Fatal(err)
				}
				if got.Version != want.Version || got.MailboxID != want.MailboxID ||
					got.ThreadID != want.ThreadID || got.ReceivedAt != want.ReceivedAt ||
					got.Size != want.Size || got.Flags != want.Flags || got.BlobHash != want.BlobHash {
					t.Fatalf("got %+v want %+v", got, want)
				}
			case storage.QueueMessage:
				var got storage.QueueMessage
				if err := storage.UnmarshalPersist(wire, &got); err != nil {
					t.Fatal(err)
				}
				if got.Created != want.Created || got.ReturnPath != want.ReturnPath {
					t.Fatalf("got %+v want %+v", got, want)
				}
			}
		})
	}
}

func TestDocumentSuffixMatchesAppendKey(t *testing.T) {
	t.Parallel()

	suffix := storage.DocumentSuffix(storage.CollectionEmail, 42, []byte("hdr"))
	key := storage.AppendKey(nil, storage.SubspaceMail, 9, 42, byte(storage.CollectionEmail), []byte("hdr"))
	want := storage.AppendKey(nil, storage.SubspaceMail, 9, 42, byte(storage.CollectionEmail), []byte("hdr"))
	batch := storage.NewBatch().WithAccount(9)
	_ = batch.Set(storage.SubspaceMail, suffix, []byte("x"))
	if !bytes.Equal(batch.Ops()[0].Key, want) {
		t.Fatalf("batch key % x want % x", batch.Ops()[0].Key, key)
	}
}

func TestEmailMetaHasBlob(t *testing.T) {
	t.Parallel()

	if (storage.EmailMeta{}).HasBlob() {
		t.Fatal("zero hash should not have blob")
	}
	if !(storage.EmailMeta{BlobHash: [32]byte{1}}).HasBlob() {
		t.Fatal("non-zero hash should have blob")
	}
}
