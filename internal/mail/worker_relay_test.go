package mail_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
	"github.com/BeaverMail/beavermaild/internal/tlsload/tlstest"
)

// relayRemote adapts smtp.DeliverRemote for queue worker tests.
type relayRemote struct {
	cfg smtp.RemoteConfig
}

func (r relayRemote) DeliverRemote(ctx context.Context, mailFrom, rcptTo string, data []byte) (string, error) {
	return smtp.DeliverRemote(ctx, r.cfg, mailFrom, rcptTo, data)
}

func TestWorkerDeliversRemoteRelaySTARTTLS(t *testing.T) {
	t.Parallel()

	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"127.0.0.1"})
	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var delivered bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		relayReply(conn, "220 relay.test ESMTP\r\n")
		if err := relayReadLine(r, "EHLO"); err != nil {
			return
		}
		relayReply(conn, "250-relay.test\r\n250-STARTTLS\r\n250-AUTH PLAIN\r\n250 OK\r\n")
		if err := relayReadLine(r, "STARTTLS"); err != nil {
			return
		}
		relayReply(conn, "220 ready\r\n")
		tlsConn := certs.WrapServer(conn)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		defer tlsConn.Close()
		tr := bufio.NewReader(tlsConn)
		if err := relayReadLine(tr, "EHLO"); err != nil {
			return
		}
		relayReply(tlsConn, "250-relay.test\r\n250-AUTH PLAIN\r\n250 OK\r\n")
		line, err := tr.ReadString('\n')
		if err != nil || !strings.HasPrefix(strings.TrimSpace(line), "AUTH PLAIN") {
			return
		}
		cred, _ := strings.CutPrefix(strings.TrimSpace(line), "AUTH PLAIN ")
		raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
		parts := strings.Split(string(raw), "\x00")
		if len(parts) != 3 || parts[1] != "relayuser" || parts[2] != "relaypass" {
			relayReply(tlsConn, "535 bad\r\n")
			return
		}
		relayReply(tlsConn, "235 OK\r\n")
		for _, cmd := range []string{"MAIL", "RCPT", "DATA"} {
			if err := relayReadPrefix(tr, cmd); err != nil {
				return
			}
			if cmd == "DATA" {
				relayReply(tlsConn, "354 go\r\n")
				for {
					l, err := tr.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(l) == "." {
						break
					}
				}
				delivered = true
			}
			relayReply(tlsConn, "250 OK\r\n")
		}
		relayReply(tlsConn, "221 bye\r\n")
	}()

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
	queue := mail.NewQueue(store, blobs)
	raw := mail.BuildSimpleMessage("alice@localhost", "rcpt@example.com", "relay queue")
	if _, err := queue.Enqueue(ctx, "alice@localhost", []string{"rcpt@example.com"}, raw); err != nil {
		t.Fatal(err)
	}

	remote := relayRemote{cfg: smtp.RemoteConfig{
		Relay: ln.Addr().String(),
		RelayOptions: smtp.ClientOptions{
			STARTTLS:              true,
			TLSInsecureSkipVerify: true,
			User:                  "relayuser",
			Password:              "relaypass",
		},
	}}
	w := mail.NewWorker(log.New("error"), queue, mail.NewInbox(store, blobs), dir, remote, nil, mail.TestQueuePolicy())
	w.ProcessOnce(ctx)

	<-done
	if !delivered {
		t.Fatal("relay did not accept message")
	}
	pending, err := queue.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("queue still has %+v", pending)
	}
}

func relayReply(conn net.Conn, s string) {
	_, _ = conn.Write([]byte(s))
}

func relayReadLine(r *bufio.Reader, prefix string) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(line), prefix) {
		return fmt.Errorf("want %s got %q", prefix, line)
	}
	return nil
}

func relayReadPrefix(r *bufio.Reader, prefix string) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(line), prefix) {
		return fmt.Errorf("want prefix %s got %q", prefix, line)
	}
	return nil
}
