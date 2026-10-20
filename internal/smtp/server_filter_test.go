package smtp_test

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/mailauth"
	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
	"github.com/BeaverMail/beaver/internal/tlsload"
	"github.com/BeaverMail/beaver/internal/tlsload/tlstest"
	"github.com/miekg/dns"
)

type phaseFilter struct {
	phase  string
	action string
}

// captureFilter records filter requests for wire assertions.
type captureFilter struct {
	mu   sync.Mutex
	reqs []smtp.FilterRequest
}

// Filter records req and accepts the phase.
func (f *captureFilter) Filter(_ context.Context, req smtp.FilterRequest) (smtp.FilterOutcome, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	return smtp.FilterOutcome{Action: smtp.FilterActionAccept}, nil
}

// authAt returns the auth payload captured for phase.
func (f *captureFilter) authAt(phase string) *smtp.FilterAuth {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, req := range f.reqs {
		if req.Phase == phase {
			return req.Auth
		}
	}
	return nil
}

// spfResolver returns deterministic SPF records for SMTP tests.
type spfResolver struct{}

// Resolve returns pass for HELO and fail for the envelope sender domain.
func (spfResolver) Resolve(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	if len(req.Question) == 0 {
		return resp, nil
	}
	name := req.Question[0].Name
	policy := "v=spf1 -all"
	if strings.EqualFold(name, "helo.example.") {
		policy = "v=spf1 +all"
	}
	resp.Answer = append(resp.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{policy},
	})
	return resp, nil
}

func (f phaseFilter) Filter(_ context.Context, req smtp.FilterRequest) (smtp.FilterOutcome, error) {
	if req.Phase == f.phase {
		if f.action == "" {
			return smtp.FilterOutcome{Action: smtp.FilterActionReject}, nil
		}
		return smtp.FilterOutcome{Action: f.action}, nil
	}
	return smtp.FilterOutcome{Action: smtp.FilterActionAccept}, nil
}

func TestSMTPFilterRejectAtEom(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, inbox, dir := openSMTPTestStore(t, ctx)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{
		Filter:       phaseFilter{phase: smtp.FilterPhaseEom},
		FilterTmpDir: tmpDir,
	})
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
	send(t, conn, "HELO test")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: hi")
	send(t, conn, "")
	send(t, conn, "body")
	send(t, conn, ".")
	expectPrefix(t, read, "550")

	key := storage.AppendKey(nil, storage.SubspaceMail, 1, 1, byte(storage.CollectionEmail), nil)
	if _, err := store.Get(ctx, key); err == nil {
		t.Fatal("message should not be stored")
	}
}

func TestSMTPFilterAcceptDelivers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, inbox, dir := openSMTPTestStore(t, ctx)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{
		Filter:       phaseFilter{phase: smtp.FilterPhaseEom, action: smtp.FilterActionAccept},
		FilterTmpDir: t.TempDir(),
	})
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
	send(t, conn, "HELO test")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: hi")
	send(t, conn, "")
	send(t, conn, "hello inbox")
	send(t, conn, ".")
	expect(t, read, "250")

	key := storage.AppendKey(nil, storage.SubspaceMail, 1, 1, byte(storage.CollectionEmail), nil)
	if _, err := store.Get(ctx, key); err != nil {
		t.Fatalf("email not stored: %v", err)
	}
}

func TestSMTPFilterRejectAtMail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{
		Filter: phaseFilter{phase: smtp.FilterPhaseMail},
	})
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
	send(t, conn, "HELO test")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expectPrefix(t, read, "550")
}

func TestSMTPFilterTempfailAtEom(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{
		Filter:       phaseFilter{phase: smtp.FilterPhaseEom, action: smtp.FilterActionTempfail},
		FilterTmpDir: t.TempDir(),
	})
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
	send(t, conn, "HELO test")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: hi")
	send(t, conn, "")
	send(t, conn, "body")
	send(t, conn, ".")
	expectPrefix(t, read, "451")
}

func TestSMTPFilterReceivesCurrentSPFResults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)
	filter := &captureFilter{}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	verifier := mailauth.New(mailauth.Config{
		Enabled:     true,
		SPFEnabled:  true,
		SPFResolver: spfResolver{},
	})
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{
		Filter:   filter,
		MailAuth: verifier,
	})
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
	send(t, conn, "HELO helo.example")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")

	heloAuth := filter.authAt(smtp.FilterPhaseHelo)
	if heloAuth == nil || heloAuth.SPFEhlo != "pass" {
		t.Fatalf("helo auth: %+v", heloAuth)
	}
	mailAuth := filter.authAt(smtp.FilterPhaseMail)
	if mailAuth == nil || mailAuth.SPFEhlo != "pass" || mailAuth.SPFMailFrom != "fail" {
		t.Fatalf("mail auth: %+v", mailAuth)
	}
}

func openSMTPTestStore(t *testing.T, ctx context.Context) (storage.Store, *mail.Inbox, *directory.Local) {
	t.Helper()
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
	return store, inbox, dir
}

func expectPrefix(t *testing.T, r *bufio.Reader, prefix string) {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(line), prefix) {
		t.Fatalf("expected prefix %q got %q", prefix, strings.TrimSpace(line))
	}
}

// Inbound mail gets our Authentication-Results on top even without an antispam filter,
// and a forged one claiming our authserv-id is dropped.
func TestSMTPAddsAuthenticationResults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)
	acc, _, err := dir.ResolveEmail(ctx, "alice@localhost")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{
		MailAuth:     mailauth.New(mailauth.Config{Enabled: true, SPFEnabled: true, SPFResolver: spfResolver{}}),
		FilterTmpDir: t.TempDir(),
		Hostname:     "mx.example.net",
	})
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
	send(t, conn, "HELO helo.example")
	expect(t, read, "250")
	send(t, conn, "MAIL FROM:<sender@example.com>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=sender@example.com")
	send(t, conn, "Subject: hi")
	send(t, conn, "")
	send(t, conn, "body")
	send(t, conn, ".")
	expect(t, read, "250")

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("inbox %d, %v", len(msgs), err)
	}
	raw, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	// Top of a locally delivered message: Return-Path, our Received, our Authentication-Results.
	rp := strings.Index(got, "Return-Path: <sender@example.com>")
	rcv := strings.Index(got, "Received: from helo.example")
	ar := strings.Index(got, "Authentication-Results: mx.example.net;")
	if rp != 0 || rcv <= rp || ar <= rcv || !strings.Contains(got, "spf=fail smtp.mailfrom=sender@example.com") {
		t.Fatalf("trace/auth headers missing or out of order:\n%s", got)
	}
	if strings.Count(got, "Authentication-Results:") != 1 {
		t.Fatalf("forged Authentication-Results kept:\n%s", got)
	}
}

// Authenticated submission is not judged by SPF/DKIM/DMARC of the client hop: the filter
// gets no auth results, so own outbound mail cannot score SPF_FAIL/DMARC.
func TestSMTPSubmissionSkipsMailAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)
	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"localhost"})
	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := certs.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	filter := &captureFilter{}
	srv := smtp.NewServer(log.New("error"), "127.0.0.1:0", dir, inbox, nil, "", "", smtp.Options{
		Certs:        certs,
		Filter:       filter,
		FilterTmpDir: t.TempDir(),
		MailAuth:     mailauth.New(mailauth.Config{Enabled: true, SPFEnabled: true, SPFResolver: spfResolver{}}),
	})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeSubmissionListener(sctx, ln, true) }()
	time.Sleep(20 * time.Millisecond)

	conn, err := tlsload.DialTestClient(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO helo.example")
	readEHLO(t, read, "AUTH PLAIN")
	send(t, conn, "AUTH PLAIN "+plainCred("alice@localhost", directory.SeedPassword()))
	expect(t, read, "235")
	send(t, conn, "MAIL FROM:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, read, "250")
	send(t, conn, "DATA")
	expect(t, read, "354")
	send(t, conn, "Subject: hi")
	send(t, conn, "")
	send(t, conn, "body")
	send(t, conn, ".")
	expect(t, read, "250")

	for _, phase := range []string{smtp.FilterPhaseMail, smtp.FilterPhaseEom} {
		if a := filter.authAt(phase); a != nil {
			t.Fatalf("%s: submission got auth results %+v", phase, a)
		}
	}
}

// RFC 5321: a message with too many Received hops is rejected as a loop, and the local copy
// gets our Return-Path in place of any the sender put in.
func TestSMTPLoopDetectionAndReturnPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)
	acc, _, err := dir.ResolveEmail(ctx, "alice@localhost")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{Hostname: "mx.example.net"})
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
	send(t, conn, "EHLO client.example")
	readEHLO(t, read, "PIPELINING")

	deliver := func(headers []string) string {
		t.Helper()
		send(t, conn, "MAIL FROM:<sender@example.com>")
		expect(t, read, "250")
		send(t, conn, "RCPT TO:<alice@localhost>")
		expect(t, read, "250")
		send(t, conn, "DATA")
		expect(t, read, "354")
		for _, h := range headers {
			send(t, conn, h)
		}
		send(t, conn, "Subject: hi")
		send(t, conn, "")
		send(t, conn, "body")
		send(t, conn, ".")
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}

	loop := make([]string, 51)
	for i := range loop {
		loop[i] = "Received: from hop" + strconv.Itoa(i) + " by relay; Tue, 20 Oct 2026 10:00:00 +0000"
	}
	if got := deliver(loop); !strings.HasPrefix(got, "554 5.4.6") {
		t.Fatalf("51 hops: %q, want 554 5.4.6", got)
	}
	if got := deliver([]string{"Return-Path: <forged@example.org>"}); !strings.HasPrefix(got, "250") {
		t.Fatalf("normal message: %q", got)
	}

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("inbox %d, %v (the looping message must not be stored)", len(msgs), err)
	}
	raw, err := inbox.LoadRaw(ctx, msgs[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.HasPrefix(got, "Return-Path: <sender@example.com>") || strings.Contains(got, "forged@") ||
		!strings.Contains(got, "by mx.example.net (BeaverMail) with ESMTP id ") {
		t.Fatalf("stored message:\n%s", got)
	}
}
