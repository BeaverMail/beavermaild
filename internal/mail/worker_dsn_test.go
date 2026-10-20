package mail_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

type stubRemote struct {
	err error
	ok  bool
}

func (s stubRemote) DeliverRemote(ctx context.Context, mailFrom, rcptTo string, data []byte) (string, error) {
	if s.ok {
		return "250 OK", nil
	}
	return "", s.err
}

func TestWorkerPermanentFailDSN(t *testing.T) {
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

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)
	raw := mail.BuildSimpleMessage("alice@localhost", "remote@example.com", "fail me")
	env := mail.EnvelopeDSN{
		ReturnPath: "alice@localhost",
		Recipients: []mail.RcptDSN{{
			Address: "remote@example.com",
			Notify:  mail.NotifyFailure,
		}},
	}
	if _, err := queue.EnqueueDSN(ctx, env, raw); err != nil {
		t.Fatal(err)
	}

	remote := stubRemote{err: &smtp.ResponseError{Code: 550, Line: "5.1.1 user unknown"}}
	policy := mail.TestQueuePolicy()
	policy.DelayNotifyAfter = 0
	w := mail.NewWorker(log.New("error"), queue, inbox, dir, remote, nil, policy)
	w.ProcessOnce(ctx)

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox %d messages", len(msgs))
	}
	body, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "multipart/report") || !strings.Contains(string(body), "Action: failed") {
		t.Fatalf("body %q", body)
	}
}

func TestWorkerNotifyNeverNoDSN(t *testing.T) {
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

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)
	raw := mail.BuildSimpleMessage("alice@localhost", "remote@example.com", "silent fail")
	env := mail.EnvelopeDSN{
		ReturnPath: "alice@localhost",
		Recipients: []mail.RcptDSN{{
			Address: "remote@example.com",
			Notify:  mail.NotifyNever,
		}},
	}
	if _, err := queue.EnqueueDSN(ctx, env, raw); err != nil {
		t.Fatal(err)
	}

	remote := stubRemote{err: &smtp.ResponseError{Code: 550, Line: "nope"}}
	w := mail.NewWorker(log.New("error"), queue, inbox, dir, remote, nil, mail.TestQueuePolicy())
	w.ProcessOnce(ctx)

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("unexpected inbox messages %d", len(msgs))
	}
}

func TestWorkerSuccessDSN(t *testing.T) {
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

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)
	raw := mail.BuildSimpleMessage("alice@localhost", "remote@example.com", "ok")
	env := mail.EnvelopeDSN{
		ReturnPath: "alice@localhost",
		Recipients: []mail.RcptDSN{{
			Address: "remote@example.com",
			Notify:  mail.NotifySuccess,
		}},
	}
	if _, err := queue.EnqueueDSN(ctx, env, raw); err != nil {
		t.Fatal(err)
	}

	remote := stubRemote{ok: true}
	w := mail.NewWorker(log.New("error"), queue, inbox, dir, remote, nil, mail.TestQueuePolicy())
	w.ProcessOnce(ctx)

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox %d messages", len(msgs))
	}
	body, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Action: delivered") {
		t.Fatalf("body %q", body)
	}
}

func TestWorkerDelayDSN(t *testing.T) {
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

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)
	raw := mail.BuildSimpleMessage("alice@localhost", "remote@example.com", "delay")
	env := mail.EnvelopeDSN{
		ReturnPath: "alice@localhost",
		Recipients: []mail.RcptDSN{{
			Address: "remote@example.com",
			Notify:  mail.NotifyDelay,
		}},
	}
	if _, err := queue.EnqueueDSN(ctx, env, raw); err != nil {
		t.Fatal(err)
	}

	remote := stubRemote{err: &smtp.ResponseError{Code: 451, Line: "try later"}}
	policy := mail.TestQueuePolicy()
	policy.DelayNotifyAfter = 0
	w := mail.NewWorker(log.New("error"), queue, inbox, dir, remote, nil, policy)
	w.ProcessOnce(ctx)

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox %d messages", len(msgs))
	}
	body, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Action: delayed") {
		t.Fatalf("body %q", body)
	}
}

func TestWorkerNullReturnPathNoDSN(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dir := directory.NewLocal(store)
	if _, err := directory.SeedDev(ctx, dir); err != nil {
		t.Fatal(err)
	}

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)
	raw := mail.BuildSimpleMessage("", "remote@example.com", "null rp")
	env := mail.EnvelopeDSN{
		ReturnPath: "",
		Recipients: []mail.RcptDSN{{
			Address: "remote@example.com",
			Notify:  mail.NotifyFailure,
		}},
	}
	id, err := queue.EnqueueDSN(ctx, env, raw)
	if err != nil {
		t.Fatal(err)
	}

	policy := mail.TestQueuePolicy()
	policy.MaxLifetime = time.Millisecond
	w := mail.NewWorker(log.New("error"), queue, inbox, dir, nil, nil, policy)
	w.ProcessOnce(ctx)
	time.Sleep(5 * time.Millisecond)
	w.ProcessOnce(ctx)

	pending, err := queue.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("queue still pending")
	}
	_ = id
}

func TestQueueEnqueueDSNPersist(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	queue := mail.NewQueue(store, blobs)
	env := mail.EnvelopeDSN{
		ReturnPath: "a@b.c",
		Ret:        mail.RetFull,
		Envid:      "eid",
		Recipients: []mail.RcptDSN{{
			Address: "x@y.z",
			Notify:  mail.NotifySuccess | mail.NotifyFailure,
			Orcpt:   "rfc822;x@y.z",
		}},
	}
	id, err := queue.EnqueueDSN(ctx, env, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	all, err := queue.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range all {
		if e.ID != id {
			continue
		}
		found = true
		if e.Msg.Ret != "FULL" || e.Msg.Envid != "eid" {
			t.Fatalf("msg %+v", e.Msg)
		}
		if len(e.Msg.Recipients) != 1 || e.Msg.Recipients[0].Orcpt != "rfc822;x@y.z" {
			t.Fatalf("rcpt %+v", e.Msg.Recipients)
		}
	}
	if !found {
		t.Fatal("entry missing")
	}
}

func TestWorkerDNSPermanentFailDSN(t *testing.T) {
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

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)
	raw := mail.BuildSimpleMessage("alice@localhost", "nobody@invalid.invalid", "dns fail")
	env := mail.EnvelopeDSN{
		ReturnPath: "alice@localhost",
		Recipients: []mail.RcptDSN{{
			Address: "nobody@invalid.invalid",
			Notify:  mail.NotifyFailure,
		}},
	}
	if _, err := queue.EnqueueDSN(ctx, env, raw); err != nil {
		t.Fatal(err)
	}

	remote := stubRemote{err: smtp.WrapDNS(&net.DNSError{IsNotFound: true, Err: "no such host", Name: "invalid.invalid"})}
	policy := mail.TestQueuePolicy()
	policy.DelayNotifyAfter = 0
	w := mail.NewWorker(log.New("error"), queue, inbox, dir, remote, nil, policy)
	w.ProcessOnce(ctx)

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox %d messages", len(msgs))
	}
	body, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Action: failed") {
		t.Fatalf("body %q", body)
	}
}

// Finished entries stay listed with the accepting server's reply, then are purged after KeepCompleted.
func TestWorkerKeepsCompletedThenPurges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dir := directory.NewLocal(store)
	if _, err := directory.SeedDev(ctx, dir); err != nil {
		t.Fatal(err)
	}
	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)
	raw := mail.BuildSimpleMessage("alice@localhost", "remote@example.com", "keep me")
	if _, err := queue.Enqueue(ctx, "alice@localhost", []string{"remote@example.com"}, raw); err != nil {
		t.Fatal(err)
	}

	policy := mail.TestQueuePolicy()
	policy.KeepCompleted = 50 * time.Millisecond
	w := mail.NewWorker(log.New("error"), queue, inbox, dir, stubRemote{ok: true}, nil, policy)
	w.ProcessOnce(ctx)

	if pending, _ := queue.ListPending(ctx); len(pending) != 0 {
		t.Fatalf("still pending: %+v", pending)
	}
	all, err := queue.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Msg.Done == 0 {
		t.Fatalf("completed entry not kept: %+v", all)
	}
	rcpt := all[0].Msg.Recipients[0]
	if mail.RecipientStatus(rcpt) != "delivered" || rcpt.LastDiag != "250 OK" {
		t.Fatalf("rcpt %+v", rcpt)
	}

	time.Sleep(60 * time.Millisecond)
	w.ProcessOnce(ctx)
	if all, _ := queue.ListAll(ctx); len(all) != 0 {
		t.Fatalf("not purged: %+v", all)
	}
}
