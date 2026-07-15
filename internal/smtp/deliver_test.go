package smtp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/mtasts"
)

func TestDeliverMXPermanentStops(t *testing.T) {
	t.Parallel()
	first := startMockMX(t, mxScript{
		onRCPT: "550 5.1.1 unknown\r\n",
	})
	second := startMockMX(t, mxScript{
		onRCPT: "250 OK\r\n",
	})
	t.Cleanup(func() { first.close(); second.close() })

	err := deliverMX(context.Background(), []string{first.addr, second.addr}, "a@b.c", "x@y.z", []byte("hi\r\n"), ClientOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	var re *ResponseError
	if !errors.As(err, &re) || re.Code != 550 {
		t.Fatalf("got %v", err)
	}
	if second.accepted() {
		t.Fatal("second mx should not be tried on 550")
	}
}

func TestDeliverMX421TriesNext(t *testing.T) {
	t.Parallel()
	first := startMockMX(t, mxScript{
		onRCPT: "421 closing\r\n",
	})
	second := startMockMX(t, mxScript{})
	t.Cleanup(func() { first.close(); second.close() })

	err := deliverMX(context.Background(), []string{first.addr, second.addr}, "a@b.c", "x@y.z", []byte("hi\r\n"), ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !second.accepted() {
		t.Fatal("second mx should deliver")
	}
}

func TestDeliverMXDialFailTriesNext(t *testing.T) {
	t.Parallel()
	second := startMockMX(t, mxScript{})
	t.Cleanup(second.close)

	err := deliverMX(context.Background(), []string{"127.0.0.1:1", second.addr}, "a@b.c", "x@y.z", []byte("hi\r\n"), ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !second.accepted() {
		t.Fatal("second mx should deliver after dial fail")
	}
}

func TestFilterMXForMTASTS(t *testing.T) {
	t.Parallel()
	policy := &mtasts.Policy{
		Mode: mtasts.ModeEnforce,
		MX:   []string{"mx.ok.test"},
	}
	hosts, err := filterMXForMTASTS([]string{"mx.ok.test:25", "mx.bad.test:25"}, policy)
	if err != nil || len(hosts) != 1 || hosts[0] != "mx.ok.test:25" {
		t.Fatalf("hosts %v err %v", hosts, err)
	}
	_, err = filterMXForMTASTS([]string{"mx.bad.test:25"}, policy)
	if err == nil {
		t.Fatal("expected no matching mx error")
	}
}

func TestDeliverMXMTASTSEnforceRequiresSTARTTLS(t *testing.T) {
	t.Parallel()
	mx := startMockMX(t, mxScript{})
	t.Cleanup(mx.close)

	host, _, _ := net.SplitHostPort(mx.addr)
	policy := &mtasts.Policy{
		Mode: mtasts.ModeEnforce,
		MX:   []string{strings.ToLower(host)},
	}
	err := deliverMX(context.Background(), []string{mx.addr}, "a@b.c", "x@example.com", []byte("hi\r\n"), mxOptionsForPolicy(ClientOptions{}, policy))
	if err == nil {
		t.Fatal("expected error")
	}
	var de *DeliveryError
	if !errors.As(err, &de) || !de.Permanent {
		t.Fatalf("got %v", err)
	}
}

type mxScript struct {
	onRCPT            string
	advertiseSTARTTLS bool
}

type mockMX struct {
	addr string
	ln   net.Listener
	done chan struct{}
	hit  bool
}

func startMockMX(t *testing.T, script mxScript) *mockMX {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &mockMX{addr: ln.Addr().String(), ln: ln, done: make(chan struct{})}
	if script.onRCPT == "" {
		script.onRCPT = "250 OK\r\n"
	}
	go func() {
		defer close(m.done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		m.hit = true
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		writeSMTP(conn, "220 mx.test ESMTP\r\n")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "EHLO"):
				if script.advertiseSTARTTLS {
					writeSMTP(conn, "250-mx.test\r\n250-STARTTLS\r\n250 OK\r\n")
				} else {
					writeSMTP(conn, "250-mx.test\r\n250 OK\r\n")
				}
			case strings.HasPrefix(line, "STARTTLS"):
				writeSMTP(conn, "220 ready\r\n")
			case strings.HasPrefix(line, "MAIL"):
				writeSMTP(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "RCPT"):
				writeSMTP(conn, script.onRCPT)
				if strings.HasPrefix(script.onRCPT, "550") || strings.HasPrefix(script.onRCPT, "421") {
					return
				}
			case line == "DATA":
				inData = true
				writeSMTP(conn, "354 go\r\n")
			default:
				if inData {
					if line == "." {
						inData = false
						writeSMTP(conn, "250 queued\r\n")
					}
					continue
				}
				if strings.HasPrefix(line, "QUIT") {
					writeSMTP(conn, "221 bye\r\n")
					return
				}
			}
		}
	}()
	return m
}

func (m *mockMX) close() { _ = m.ln.Close(); <-m.done }
func (m *mockMX) accepted() bool {
	select {
	case <-m.done:
		return m.hit
	default:
		return m.hit
	}
}

func writeSMTP(conn net.Conn, s string) { _, _ = fmt.Fprint(conn, s) }
