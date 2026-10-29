package mail_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

func TestQuotaBlocksDeliverAndFreesOnDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dir := directory.NewLocal(store)
	acc, err := directory.SeedDev(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}

	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	inbox.SetQuotaDefaults(mail.QuotaDefaults{StorageBytes: 100, Messages: 2})

	raw := []byte("From: a@b\r\n\r\n1234567890\r\n")
	if _, err := inbox.Deliver(ctx, acc.ID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nx\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\ny\r\n")); err != mail.ErrOverQuota {
		t.Fatalf("deliver over quota err=%v", err)
	}

	st, err := inbox.QuotaStatus(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.MessagesUsed != 2 || st.StorageLimit != 100 {
		t.Fatalf("status %+v", st)
	}

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.DeleteMessage(ctx, acc.ID, msgs[0].StorageID()); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nz\r\n")); err != nil {
		t.Fatalf("after delete deliver err=%v", err)
	}
}

func TestQuotaUsesDomainDefaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dir := directory.NewLocal(store)
	dom, err := dir.CreateDomainWithOpts(ctx, directory.DefaultTenantID, "quota.test", directory.DomainCreateOpts{
		StorageBytes: 50,
		Messages:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	acc, err := dir.CreateAccount(ctx, dom.ID, "u", "secret")
	if err != nil {
		t.Fatal(err)
	}

	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	inbox.SetQuotaDefaults(mail.QuotaDefaults{StorageBytes: 10_000, Messages: 100})
	inbox.SetAccountQuotaDefaultsFunc(func(ctx context.Context, accountID uint32) (mail.QuotaDefaults, bool) {
		sb, msgs, ok := dir.DomainQuotaForAccount(ctx, accountID)
		if !ok {
			return mail.QuotaDefaults{}, false
		}
		return mail.QuotaDefaults{StorageBytes: sb, Messages: msgs}, true
	})

	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nok\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, acc.ID, []byte("From: a@b\r\n\r\nno\r\n")); err != mail.ErrOverQuota {
		t.Fatalf("want over quota got %v", err)
	}
	st, err := inbox.QuotaStatus(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.MessagesLimit != 1 || st.StorageLimit != 50 {
		t.Fatalf("status %+v", st)
	}
}

// The tenant cap sums usage across all domains of the tenant and leaves other tenants alone.
func TestTenantStorageCap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	capped, err := dir.CreateTenant(ctx, "Capped", "", 60)
	if err != nil {
		t.Fatal(err)
	}
	other, err := dir.CreateTenant(ctx, "Other", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	newAccount := func(tenantID uint32, domain string) uint32 {
		t.Helper()
		dom, _, err := dir.EnsureDomain(ctx, tenantID, domain)
		if err != nil {
			t.Fatal(err)
		}
		acc, err := dir.CreateAccountRole(ctx, dom.ID, "alice", "pw", directory.RoleUser)
		if err != nil {
			t.Fatal(err)
		}
		return acc.ID
	}
	a := newAccount(capped.ID, "one.example")
	b := newAccount(capped.ID, "two.example")
	c := newAccount(other.ID, "three.example")

	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	inbox.SetTenantStorageCapFunc(dir.TenantStorageCap)
	msg := []byte("Subject: x\r\n\r\n0123456789\r\n") // 26 bytes

	if _, err := inbox.Deliver(ctx, a, msg); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, b, msg); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, b, msg); err != mail.ErrOverQuota {
		t.Fatalf("third message (78 > 60) err=%v", err)
	}
	for range 3 {
		if _, err := inbox.Deliver(ctx, c, msg); err != nil {
			t.Fatalf("uncapped tenant: %v", err)
		}
	}
	if err := dir.SetTenantStorageLimit(ctx, capped.ID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Deliver(ctx, b, msg); err != nil {
		t.Fatalf("cap removed: %v", err)
	}
}
