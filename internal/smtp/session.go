// SMTP session state machine for one client connection.
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/tlsload"
)

type session struct {
	log   *slog.Logger
	conn  net.Conn
	r     *bufio.Reader
	dir   *directory.Local
	inbox *mail.Inbox
	tls   *tlsload.Certs

	secure      bool
	tlsRequired bool

	mailFrom string
	rcpt     []rcptTarget
}

type rcptTarget struct {
	address   string
	accountID uint32
}

func newSession(log *slog.Logger, conn net.Conn, dir *directory.Local, inbox *mail.Inbox, certs *tlsload.Certs, secure, tlsRequired bool) *session {
	return &session{
		log:         log,
		conn:        conn,
		r:           bufio.NewReader(conn),
		dir:         dir,
		inbox:       inbox,
		tls:         certs,
		secure:      secure,
		tlsRequired: tlsRequired,
	}
}

func (s *session) run(ctx context.Context) error {
	if err := s.writef("220 localhost ESMTP BeaverMail"); err != nil {
		return err
	}
	for {
		line, err := s.readLine()
		if err != nil {
			return err
		}
		if line == "" {
			continue
		}
		cmd, arg := parseCommand(line)
		switch cmd {
		case "EHLO":
			if err := s.writeEHLO(true); err != nil {
				return err
			}
		case "HELO":
			if err := s.writeEHLO(false); err != nil {
				return err
			}
		case "STARTTLS":
			if err := s.cmdStartTLS(); err != nil {
				return err
			}
		case "MAIL":
			addr, ok := parsePath(arg)
			if !ok {
				if err := s.writef("501 syntax: MAIL FROM:<address>"); err != nil {
					return err
				}
				continue
			}
			s.reset()
			s.mailFrom = addr
			if err := s.writef("250 OK"); err != nil {
				return err
			}
		case "RCPT":
			addr, ok := parsePath(arg)
			if !ok {
				if err := s.writef("501 syntax: RCPT TO:<address>"); err != nil {
					return err
				}
				continue
			}
			if s.mailFrom == "" {
				if err := s.writef("503 need MAIL first"); err != nil {
					return err
				}
				continue
			}
			domName, err := DomainFromAddress(addr)
			if err != nil {
				if err := s.writef("501 syntax: RCPT TO:<address>"); err != nil {
					return err
				}
				continue
			}
			if _, err := s.dir.LookupDomain(ctx, domName); err != nil {
				if errors.Is(err, directory.ErrNotFound) {
					if err := s.writef("550 unknown domain"); err != nil {
						return err
					}
					continue
				}
				return err
			}
			acc, _, err := s.dir.ResolveEmail(ctx, addr)
			if err != nil {
				if errors.Is(err, directory.ErrNotFound) {
					if err := s.writef("550 no such user"); err != nil {
						return err
					}
					continue
				}
				return err
			}
			if !acc.Active {
				if err := s.writef("550 inactive"); err != nil {
					return err
				}
				continue
			}
			s.rcpt = append(s.rcpt, rcptTarget{address: strings.ToLower(addr), accountID: acc.ID})
			if err := s.writef("250 OK"); err != nil {
				return err
			}
		case "DATA":
			if len(s.rcpt) == 0 {
				if err := s.writef("503 need RCPT first"); err != nil {
					return err
				}
				continue
			}
			if err := s.writef("354 start mail input; end with <CRLF>.<CRLF>"); err != nil {
				return err
			}
			raw, err := readDATA(s.r)
			if err != nil {
				return err
			}
			for _, t := range s.rcpt {
				if _, err := s.inbox.Deliver(ctx, t.accountID, raw); err != nil {
					s.log.Warn("deliver failed", "rcpt", t.address, slog.Any("err", err))
					if err := s.writef("451 delivery failed"); err != nil {
						return err
					}
					goto afterData
				}
			}
			if err := s.writef("250 OK"); err != nil {
				return err
			}
		afterData:
			s.reset()
		case "RSET":
			s.reset()
			if err := s.writef("250 OK"); err != nil {
				return err
			}
		case "NOOP":
			if err := s.writef("250 OK"); err != nil {
				return err
			}
		case "QUIT":
			_ = s.writef("221 bye")
			return nil
		default:
			if err := s.writef("502 command not implemented"); err != nil {
				return err
			}
		}
	}
}

func (s *session) writeEHLO(extended bool) error {
	if !extended {
		return s.writef("250 localhost")
	}
	if err := s.writef("250-localhost"); err != nil {
		return err
	}
	if s.tls != nil && !s.secure {
		if err := s.writef("250-STARTTLS"); err != nil {
			return err
		}
	}
	return s.writef("250 OK")
}

func (s *session) cmdStartTLS() error {
	if s.secure {
		return s.writef("503 TLS already active")
	}
	if s.tls == nil {
		return s.writef("502 TLS not available")
	}
	if err := s.writef("220 Ready to start TLS"); err != nil {
		return err
	}
	tlsConn := s.tls.WrapServer(s.conn)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	s.conn = tlsConn
	s.r = bufio.NewReader(tlsConn)
	s.secure = true
	return nil
}

func (s *session) reset() {
	s.mailFrom = ""
	s.rcpt = s.rcpt[:0]
}

func (s *session) writef(format string, args ...any) error {
	_, err := fmt.Fprintf(s.conn, format+"\r\n", args...)
	return err
}

func (s *session) readLine() (string, error) {
	line, err := s.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) > 512 {
		return "", fmt.Errorf("smtp: line too long")
	}
	return line, nil
}

func parseCommand(line string) (cmd, arg string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return strings.ToUpper(line[:i]), strings.TrimSpace(line[i+1:])
	}
	return strings.ToUpper(line), ""
}

func parsePath(arg string) (string, bool) {
	arg = strings.TrimSpace(strings.ToUpper(arg))
	if !strings.HasPrefix(arg, "FROM:") && !strings.HasPrefix(arg, "TO:") {
		// arg is already stripped of FROM:/TO: in caller - MAIL/RCPT pass full "FROM:<>"
	}
	arg = strings.TrimSpace(arg)
	if len(arg) >= 5 && strings.EqualFold(arg[:5], "FROM:") {
		arg = strings.TrimSpace(arg[5:])
	} else if len(arg) >= 3 && strings.EqualFold(arg[:3], "TO:") {
		arg = strings.TrimSpace(arg[3:])
	}
	if len(arg) < 3 || arg[0] != '<' || arg[len(arg)-1] != '>' {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(arg[1 : len(arg)-1])), true
}

// readDATA reads RFC 5321 dot-stuffed message data.
func readDATA(r *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "." {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}
