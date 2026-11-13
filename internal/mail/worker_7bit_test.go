package mail_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// sevenBitMX is a relay without 8BITMIME that records every message it receives.
func sevenBitMX(t *testing.T) (string, <-chan string, <-chan bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got, sawMail := make(chan string, 4), make(chan bool, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				w := func(s string) { _, _ = c.Write([]byte(s)) }
				w("220 old.test\r\n")
				mail := false
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						sawMail <- mail
						return
					}
					switch up := strings.ToUpper(strings.TrimSpace(l)); {
					case strings.HasPrefix(up, "EHLO"):
						w("250 old.test\r\n") // no 8BITMIME
					case strings.HasPrefix(up, "MAIL"):
						mail = true
						w("250 ok\r\n")
					case up == "DATA":
						w("354 go\r\n")
						var b strings.Builder
						for {
							d, err := r.ReadString('\n')
							if err != nil || d == ".\r\n" {
								break
							}
							b.WriteString(d)
						}
						got <- b.String()
						w("250 queued\r\n")
					case up == "QUIT":
						w("221 bye\r\n")
						sawMail <- mail
						return
					default:
						w("250 ok\r\n")
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), got, sawMail
}

// RFC 6152 3: a next hop without 8BITMIME never gets 8-bit octets. The message is not converted
// (as in Exim): the delivery fails for good with status 5.6.3 and the server never sees MAIL.
func TestWorkerRefuses8BitForOldRelay(t *testing.T) {
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
	inbox, queue := mail.NewInbox(store, blobs), mail.NewQueue(store, blobs)
	addr, got, sawMail := sevenBitMX(t)
	remote := relayRemote{cfg: smtp.RemoteConfig{Relay: addr}}

	body := "MIME-Version: 1.0\r\nSubject: s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\ncaf\xc3\xa9\r\n"
	if _, err := queue.EnqueueDSN(ctx, mail.EnvelopeDSN{ReturnPath: "alice@localhost", Recipients: []mail.RcptDSN{{Address: "bob@example.net"}}}, []byte(body)); err != nil {
		t.Fatal(err)
	}
	mail.NewWorker(log.New("error"), queue, inbox, dir, remote, nil, mail.TestQueuePolicy()).ProcessOnce(ctx)

	msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
	if err != nil {
		t.Fatal(err)
	}
	var dsn string
	for _, m := range msgs {
		raw, _ := inbox.LoadMessage(ctx, m.Meta)
		if strings.Contains(string(raw), "bob@example.net") {
			dsn = string(raw)
		}
	}
	if !strings.Contains(dsn, "Action: failed") || !strings.Contains(dsn, "Status: 5.6.3") {
		t.Fatalf("no 5.6.3 failure DSN:\n%s", dsn)
	}
	if mail := <-sawMail; mail {
		t.Fatal("MAIL sent to a server without 8BITMIME")
	}
	select {
	case s := <-got:
		t.Fatalf("8-bit message reached the relay: %q", s)
	default:
	}
}
