package smtp_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
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

// Reports sent to dmarc-reports@ / tls-reports@ go to the domain report store as raw
// files, never into a user INBOX (even with a catch-all configured).
func TestSMTPReportAddressesGoToReportStore(t *testing.T) {
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
	dataDir := t.TempDir()
	dir.SetDataDir(dataDir)
	// Catch-all would normally swallow these addresses into alice's INBOX.
	if _, err := dir.UpdateDomainWithOpts(ctx, "localhost", directory.DomainCreateOpts{CatchAllLocal: "alice"}); err != nil {
		t.Fatal(err)
	}
	dom, err := dir.LookupDomain(ctx, "localhost")
	if err != nil {
		t.Fatal(err)
	}

	blobs := blob.NewFS(t.TempDir() + "/blobs")
	inbox := mail.NewInbox(store, blobs)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expect(t, read, "220")

	deliver := func(rcpt string, contentType, payload string) {
		t.Helper()
		send(t, conn, "HELO test")
		expect(t, read, "250")
		send(t, conn, "MAIL FROM:<reporter@example.com>")
		expect(t, read, "250")
		send(t, conn, "RCPT TO:<"+rcpt+">")
		expect(t, read, "250")
		send(t, conn, "DATA")
		expect(t, read, "354")
		send(t, conn, "From: reporter@example.com")
		send(t, conn, "To: "+rcpt)
		send(t, conn, "Content-Type: "+contentType)
		send(t, conn, "")
		send(t, conn, payload)
		send(t, conn, ".")
		expect(t, read, "250")
		send(t, conn, "RSET")
		expect(t, read, "250")
	}
	deliver("dmarc-reports@localhost", "application/gzip", "H4sIAAAAAAAAfakegzippayload")
	deliver("tls-reports@localhost", "application/json", `{"organization-name":"example"}`)
	send(t, conn, "QUIT")

	// Nothing may land in the catch-all user's INBOX.
	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("report addresses delivered %d message(s) to INBOX", len(msgs))
	}

	for _, tc := range []struct{ kind, rcpt, contentType, payload string }{
		{"dmarc", "dmarc-reports@localhost", "application/gzip", "H4sIAAAAAAAAfakegzippayload"},
		{"tls", "tls-reports@localhost", "application/json", `{"organization-name":"example"}`},
	} {
		emls, err := filepath.Glob(filepath.Join(directory.DomainDir(dataDir, dom.ID), "reports", tc.kind, "*.eml"))
		if err != nil {
			t.Fatal(err)
		}
		if len(emls) != 1 {
			t.Fatalf("%s: %d raw report files, want 1", tc.kind, len(emls))
		}
		raw, err := os.ReadFile(emls[0])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), tc.payload) {
			t.Fatalf("%s: raw file does not keep the original payload", tc.kind)
		}
		wire, err := os.ReadFile(strings.TrimSuffix(emls[0], ".eml") + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var meta directory.ReportMeta
		if err := json.Unmarshal(wire, &meta); err != nil {
			t.Fatal(err)
		}
		if meta.Kind != tc.kind || meta.From != "reporter@example.com" || meta.To != tc.rcpt {
			t.Fatalf("%s: meta %+v", tc.kind, meta)
		}
		if meta.ContentType != tc.contentType || meta.Format == "unknown" {
			t.Fatalf("%s: meta %+v", tc.kind, meta)
		}
		if meta.ReceivedAt == "" || meta.File != filepath.Base(emls[0]) {
			t.Fatalf("%s: meta %+v", tc.kind, meta)
		}
	}
}
