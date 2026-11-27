package mail_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/dkimout"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
)

// sinkServer accepts one SMTP session and writes the message it receives, dot-stuffing undone, to
// a file, so the test process holds none of it. It offers CHUNKING when chunking is set.
func sinkServer(t *testing.T, chunking bool) (addr, path string, done chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	path = filepath.Join(t.TempDir(), "received.eml")
	done = make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- sinkSession(conn, chunking, path)
	}()
	return ln.Addr().String(), path, done
}

func sinkSession(conn net.Conn, chunking bool, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(conn, 4096)
	reply := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
	reply("220 sink")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		verb := strings.ToUpper(strings.Fields(line + " x")[0])
		switch verb {
		case "EHLO":
			caps := "250-sink\r\n250-8BITMIME\r\n"
			if chunking {
				caps += "250-CHUNKING\r\n"
			}
			reply(caps + "250 SIZE 52428800")
		case "MAIL", "RCPT":
			reply("250 ok")
		case "DATA":
			reply("354 go")
			for {
				l, err := r.ReadSlice('\n')
				if err != nil {
					return err
				}
				if string(l) == ".\r\n" {
					break
				}
				if _, err := f.Write(bytes.TrimPrefix(l, []byte("."))); err != nil {
					return err
				}
			}
			reply("250 queued")
		case "BDAT":
			var n int64
			if _, err := fmt.Sscanf(line, "BDAT %d LAST", &n); err != nil {
				return err
			}
			if _, err := io.CopyN(f, r, n); err != nil {
				return err
			}
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			return nil
		default:
			reply("500 what")
		}
	}
}

func peakHeap(fn func()) uint64 {
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	peak := before.HeapInuse
	stop, done := make(chan bool), make(chan bool)
	go func() {
		defer close(done)
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			peak = max(peak, m.HeapInuse)
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	fn()
	close(stop)
	<-done
	return peak - before.HeapInuse
}

// A queued message goes out streamed from its blob, DKIM-signed on the way: a 10 MB message, by
// DATA or BDAT, must not raise the heap by its size (before: loaded, converted to CRLF and signed
// in memory, about four copies, 40 MB per delivery and 16 deliveries at once).
func TestOutboundStreamed(t *testing.T) {
	for _, chunking := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunking=%v", chunking), func(t *testing.T) {
			ctx := context.Background()
			store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			blobs := blob.NewFS(t.TempDir() + "/blobs")
			queue := mail.NewQueue(store, blobs)

			keyPath := filepath.Join(t.TempDir(), "dkim.pem")
			if err := dkimout.GenerateKey(keyPath); err != nil {
				t.Fatal(err)
			}
			signer, err := dkimout.New(dkimout.Config{Selector: "s", Domain: "example.org", KeyPath: keyPath})
			if err != nil {
				t.Fatal(err)
			}
			rec, err := dkimout.PublicKeyDNS(keyPath)
			if err != nil {
				t.Fatal(err)
			}

			// Stored as DATA stores it: LF line ends, a dot-led line, 8-bit text.
			raw := []byte("From: alice@example.org\nTo: bob@example.net\nSubject: big\n\n.leading dot\ncaff\xe8\n" +
				strings.Repeat("lorem ipsum dolor sit amet consectetur adipiscing\n", 200000))
			if _, err := queue.Enqueue(ctx, "alice@example.org", []string{"bob@example.net"}, raw); err != nil {
				t.Fatal(err)
			}
			wire := mail.CRLF(raw)
			wantSum, wantLen := sha256.Sum256(wire), int64(len(wire))
			raw, wire = nil, nil

			addr, path, done := sinkServer(t, chunking)
			remote := relayRemote{cfg: smtp.RemoteConfig{Relay: addr}}
			w := mail.NewWorker(log.New("error"), queue, mail.NewInbox(store, blobs), directory.NewLocal(store), remote, signer, mail.TestQueuePolicy())
			grew := peakHeap(func() { w.ProcessOnce(ctx) })
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			t.Logf("heap grew %d KB", grew>>10)
			if grew > 8<<20 { // about 3 MB is fixed cost (store, connections), whatever the message size
				t.Errorf("heap grew %d MB sending a 10 MB message", grew>>20)
			}

			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			verifs, err := dkim.VerifyWithOptions(f, &dkim.VerifyOptions{LookupTXT: func(string) ([]string, error) { return []string{rec}, nil }})
			if err != nil || len(verifs) != 1 || verifs[0].Err != nil {
				t.Fatalf("DKIM: %v %+v", err, verifs)
			}
			st, _ := f.Stat()
			h := sha256.New()
			if _, err := io.Copy(h, io.NewSectionReader(f, st.Size()-wantLen, wantLen)); err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(mustRead(t, path, 15), []byte("DKIM-Signature:")) || !bytes.Equal(h.Sum(nil), wantSum[:]) {
				t.Fatal("received message is not the signature followed by the CRLF form of the queued one")
			}
		})
	}
}

func mustRead(t *testing.T, path string, n int) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := io.ReadFull(f, b); err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 3461 6.2: a failure notification for a message over mail.MaxDSNReturnBytes returns only its
// header, even with RET=FULL; a smaller one is returned whole.
func TestWorkerDSNReturnLimit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		bodyLen int
		whole   bool
	}{{1000, true}, {mail.MaxDSNReturnBytes, false}} {
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
		raw := []byte("From: alice@localhost\r\nSubject: returned\r\n\r\n" + strings.Repeat(strings.Repeat("y", 98)+"\r\n", tc.bodyLen/100))
		env := mail.EnvelopeDSN{ReturnPath: "alice@localhost", Ret: mail.RetFull,
			Recipients: []mail.RcptDSN{{Address: "remote@example.com", Notify: mail.NotifyFailure}}}
		if _, err := queue.EnqueueDSN(ctx, env, raw); err != nil {
			t.Fatal(err)
		}
		remote := stubRemote{err: &smtp.ResponseError{Code: 550, Line: "5.1.1 user unknown"}}
		mail.NewWorker(log.New("error"), queue, inbox, dir, remote, nil, mail.TestQueuePolicy()).ProcessOnce(ctx)
		msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
		if err != nil || len(msgs) != 1 {
			t.Fatalf("inbox %d messages, %v", len(msgs), err)
		}
		dsn, err := inbox.LoadRaw(ctx, msgs[0].Meta)
		if err != nil {
			t.Fatal(err)
		}
		s := string(dsn)
		whole := strings.Contains(s, "Content-Type: message/rfc822") && strings.Contains(s, "yyyy")
		headers := strings.Contains(s, "Content-Type: text/rfc822-headers") && strings.Contains(s, "Subject: returned") && !strings.Contains(s, "yyyy")
		if tc.whole && !whole || !tc.whole && !headers {
			t.Fatalf("body %d: notification of %d octets, whole %v, headers only %v", tc.bodyLen, len(dsn), whole, headers)
		}
	}
}
