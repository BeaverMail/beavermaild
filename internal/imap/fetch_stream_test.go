package imap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
)

// fetchOutput runs fn against a session whose connection is captured, and returns what it wrote.
func fetchOutput(t *testing.T, inbox *mail.Inbox, fn func(s *session) error) string {
	t.Helper()
	server, client := net.Pipe()
	s := &session{conn: server, inbox: inbox}
	got := make(chan string, 1)
	go func() { b, _ := io.ReadAll(client); got <- string(b) }()
	if err := fn(s); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	return <-got
}

// Whole-message FETCH items are streamed from the stored file: the response must be byte for byte the
// one built from the message in memory, partials included, and must not need a rawLoads slot (that is
// what keeps a large download out of memory).
func TestFetchWholeMessageStreamed(t *testing.T) {
	ctx := context.Background()
	blobs := blob.NewFS(t.TempDir())
	raw := []byte("From: a@example.org\r\nSubject: big\r\n\r\n" + strings.Repeat("0123456789\r\n", 5000))
	hash, err := blobs.Put(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	inbox := mail.NewInbox(nil, blobs)
	msg := mail.Message{UID: 9, Meta: storage.EmailMeta{BlobHash: hash, Size: uint32(len(raw))}}

	// Hold every slot: a streamed FETCH must still complete.
	for range rawLoadLimit {
		rawLoads <- struct{}{}
	}
	defer func() {
		for range rawLoadLimit {
			<-rawLoads
		}
	}()

	for _, arg := range []string{"1 BODY.PEEK[]", "1 RFC822", "1 (UID BODY.PEEK[]<100.50>)", "1 BODY[]<0.10>", "1 BODY.PEEK[]<999999.5>"} {
		_, items, ok := parseFetchArg(arg)
		if !ok {
			t.Fatalf("parse %q", arg)
		}
		streamed := fetchOutput(t, inbox, func(s *session) error { return s.writeFetch(ctx, 1, msg, items, false) })
		inMemory := fetchOutput(t, inbox, func(s *session) error {
			var parts []string
			if items.uid {
				parts = append(parts, "UID 9")
			}
			return s.writeFetchWithLiterals(1, parts, items.bodySections, raw)
		})
		if streamed != inMemory {
			t.Fatalf("%s: streamed differs\n got %.200q\nwant %.200q", arg, streamed, inMemory)
		}
	}
}

// Anything that parses the message waits for a rawLoads slot, so memory stays bounded.
func TestFetchParsedItemsWaitForSlot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	for range rawLoadLimit {
		rawLoads <- struct{}{}
	}
	defer func() {
		for range rawLoadLimit {
			<-rawLoads
		}
	}()
	cancel()
	if _, err := acquireRawLoad(ctx); err == nil {
		t.Fatal("got a slot while all were taken")
	}
}

// A client that stops reading is cut off after the write timeout instead of blocking its session.
func TestWriteDeadlineConnStalledClient(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer client.Close()
	c := &writeDeadlineConn{Conn: server, d: 50 * time.Millisecond}
	if _, err := c.Write([]byte("* 1 FETCH (BODY[] {5}\r\nhello)\r\n")); err == nil {
		t.Fatal("write to a client that never reads: want a timeout")
	}
}

// URLFETCH and CATENATE load whole messages: each URL waits for a rawLoads slot, so many URLs or
// many clients cannot pile up messages in memory.
func TestURLLoadsWaitForSlot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	for range rawLoadLimit {
		rawLoads <- struct{}{}
	}
	defer func() {
		for range rawLoadLimit {
			<-rawLoads
		}
	}()
	cancel()
	s := &session{}
	var b bytes.Buffer
	if err := s.urlFetchItem(ctx, &b, urlFetchItem{url: "imap://alice@example.org/INBOX/;UID=1"}); err == nil || b.Len() != 0 {
		t.Fatalf("URLFETCH item ran without a slot: err=%v out=%q", err, b.String())
	}
	if _, err := s.catenateURL(ctx, "/INBOX/;UID=1"); err == nil || errors.Is(err, errBadURL) {
		t.Fatalf("CATENATE URL ran without a slot: %v", err)
	}
}
