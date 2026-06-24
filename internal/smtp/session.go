// SMTP session state machine for one client connection.
package smtp

import (
	"bufio"
	"context"
	"encoding/base64"
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
	queue *mail.Queue
	tls   *tlsload.Certs

	secure      bool
	tlsRequired bool
	submission  bool
	dataLimits  DataLimits

	principal directory.Principal

	mailFrom string
	mailRet  mail.RetMode
	mailEnvid string
	rcpt     []rcptTarget

	bdatBuf  []byte
	bdatUsed bool
}

type rcptTarget struct {
	address   string
	accountID uint32 // 0 = outbound queue recipient
	notify    mail.NotifyFlags
	orcpt     string
}

func newSession(log *slog.Logger, conn net.Conn, dir *directory.Local, inbox *mail.Inbox, queue *mail.Queue, certs *tlsload.Certs, secure, tlsRequired, submission bool, limits DataLimits) *session {
	return &session{
		log:         log,
		conn:        conn,
		r:           bufio.NewReader(conn),
		dir:         dir,
		inbox:       inbox,
		queue:       queue,
		tls:         certs,
		secure:      secure,
		tlsRequired: tlsRequired,
		submission:  submission,
		dataLimits:  limits.withDefaults(),
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
		case "AUTH":
			if err := s.cmdAuth(ctx, arg); err != nil {
				return err
			}
		case "MAIL":
			addr, declaredSize, mailParams, ok := parseMailArg(arg)
			if !ok {
				if err := s.writef("501 5.5.4 Syntax: MAIL FROM:<address>"); err != nil {
					return err
				}
				continue
			}
			if declaredSize > s.dataLimits.MaxMessageBytes {
				if err := s.writef("552 5.3.4 Message size exceeds fixed maximum message size"); err != nil {
					return err
				}
				continue
			}
			if s.submission && s.principal.AccountID == 0 {
				if err := s.writef("530 5.7.0 Authentication required"); err != nil {
					return err
				}
				continue
			}
			if s.submission {
				resolved, ok := resolveSubmissionMailFrom(s.principal, addr)
				if !ok {
					if err := s.writef("553 5.7.1 Sender address rejected"); err != nil {
						return err
					}
					continue
				}
				addr = resolved
			}
			s.reset()
			s.mailFrom = addr
			s.mailRet = mailParams.Ret
			s.mailEnvid = mailParams.Envid
			if err := s.writef(smtpOK); err != nil {
				return err
			}
		case "RCPT":
			addr, rcptParams, ok := parseRcptArg(arg)
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
					if !s.submission {
						if err := s.writef("554 5.7.1 Relay access denied"); err != nil {
							return err
						}
						continue
					}
					if s.queue == nil {
						if err := s.writef("550 unknown domain"); err != nil {
							return err
						}
						continue
					}
					s.rcpt = append(s.rcpt, rcptTarget{
						address: strings.ToLower(addr),
						notify:  rcptParams.Notify,
						orcpt:   rcptParams.Orcpt,
					})
					if err := s.writef(smtpOK); err != nil {
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
			s.rcpt = append(s.rcpt, rcptTarget{
				address:   strings.ToLower(addr),
				accountID: acc.ID,
				notify:    rcptParams.Notify,
				orcpt:     rcptParams.Orcpt,
			})
			if err := s.writef(smtpOK); err != nil {
				return err
			}
		case "DATA":
			if s.bdatUsed {
				if err := s.writef("503 5.5.1 BDAT transfer in progress"); err != nil {
					return err
				}
				continue
			}
			if len(s.rcpt) == 0 {
				if err := s.writef("503 need RCPT first"); err != nil {
					return err
				}
				continue
			}
			if err := s.writef(smtpDataStart); err != nil {
				return err
			}
			raw, err := readDATA(s.r, s.dataLimits)
			if err != nil {
				drainDATA(s.r)
				if werr := s.writef(dataErrorResponse(err)); werr != nil {
					return werr
				}
				s.reset()
				continue
			}
			if err := s.finishDelivery(ctx, raw); err != nil {
				return err
			}
		case "BDAT":
			if err := s.cmdBDAT(ctx, arg); err != nil {
				return err
			}
		case "HELP":
			if err := s.cmdHelp(arg); err != nil {
				return err
			}
		case "VRFY":
			if err := s.cmdVrfy(arg); err != nil {
				return err
			}
		case "EXPN":
			if err := s.cmdExpn(arg); err != nil {
				return err
			}
		case "ETRN", "ATRN", "BURL":
			if err := s.writef("502 5.5.1 Command not implemented"); err != nil {
				return err
			}
		case "RSET":
			s.reset()
			if err := s.writef(smtpOK); err != nil {
				return err
			}
		case "NOOP":
			if err := s.writef(smtpOK); err != nil {
				return err
			}
		case "QUIT":
			_ = s.writef("221 2.0.0 Bye")
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
	lines := []string{
		"250-localhost",
		"250-ENHANCEDSTATUSCODES",
		"250-8BITMIME",
		"250-BINARYMIME",
		"250-SMTPUTF8",
		"250-CHUNKING",
		"250-DSN",
		"250-REQUIRETLS",
		"250-PIPELINING",
		fmt.Sprintf("250-SIZE %d", s.dataLimits.MaxMessageBytes),
	}
	if s.tls != nil && !s.secure {
		lines = append(lines, "250-STARTTLS")
	}
	if s.submission && s.secure {
		lines = append(lines, "250-AUTH PLAIN LOGIN")
	}
	for _, line := range lines {
		if err := s.writef(line); err != nil {
			return err
		}
	}
	return s.writef("250 2.0.0 Ok")
}

const (
	smtpOK        = "250 2.0.0 Ok"
	smtpDataStart = "354 2.0.0 Start mail input; end with <CRLF>.<CRLF>"
)

// cmdAuth handles AUTH on submission listeners after TLS is active.
func (s *session) cmdAuth(ctx context.Context, arg string) error {
	if !s.submission {
		return s.writef("502 5.5.1 Command not implemented")
	}
	if !s.secure {
		return s.writef("538 5.7.11 Encryption required for authentication")
	}
	mech, rest := splitAuthArg(arg)
	switch {
	case strings.EqualFold(mech, "PLAIN"):
		return s.authPlain(ctx, rest)
	case strings.EqualFold(mech, "LOGIN"):
		return s.authLogin(ctx, rest)
	default:
		return s.writef("504 5.5.4 Unrecognized authentication type")
	}
}

func (s *session) authPlain(ctx context.Context, credLine string) error {
	credLine = strings.TrimSpace(credLine)
	if credLine == "" {
		if err := s.writef("334 "); err != nil {
			return err
		}
		line, err := s.readLine()
		if err != nil {
			return err
		}
		credLine = line
	}
	user, pass, ok := decodeAuthPlain(credLine)
	if !ok {
		return s.writef("535 5.7.8 Authentication credentials invalid")
	}
	return s.finishAuth(ctx, user, pass)
}

func (s *session) authLogin(ctx context.Context, credLine string) error {
	if strings.TrimSpace(credLine) != "" {
		return s.writef("535 5.7.8 Authentication credentials invalid")
	}
	if err := s.writef("334 " + base64.StdEncoding.EncodeToString([]byte("Username:"))); err != nil {
		return err
	}
	userLine, err := s.readLine()
	if err != nil {
		return err
	}
	user := decodeSMTPBase64(userLine)
	if user == "" {
		return s.writef("535 5.7.8 Authentication credentials invalid")
	}
	if err := s.writef("334 " + base64.StdEncoding.EncodeToString([]byte("Password:"))); err != nil {
		return err
	}
	passLine, err := s.readLine()
	if err != nil {
		return err
	}
	return s.finishAuth(ctx, user, decodeSMTPBase64(passLine))
}

func (s *session) finishAuth(ctx context.Context, user, pass string) error {
	p, err := s.dir.Authenticate(ctx, user, pass)
	if err != nil {
		if errors.Is(err, directory.ErrInvalidCredentials) || errors.Is(err, directory.ErrInactive) {
			return s.writef("535 5.7.8 Authentication credentials invalid")
		}
		return err
	}
	s.principal = p
	s.reset()
	return s.writef("235 2.7.0 Authentication successful")
}

// senderAllowed reports whether mailFrom matches the authenticated account (aliases later).
func senderAllowed(p directory.Principal, mailFrom string) bool {
	return strings.EqualFold(mailFrom, p.Email())
}

// resolveSubmissionMailFrom accepts the client envelope sender or substitutes placeholders (e.g. Claws unknown@localhost).
func resolveSubmissionMailFrom(p directory.Principal, mailFrom string) (string, bool) {
	if senderAllowed(p, mailFrom) {
		return strings.ToLower(mailFrom), true
	}
	if placeholderSender(mailFrom) {
		return strings.ToLower(p.Email()), true
	}
	return "", false
}

// placeholderSender reports MUAs that send a dummy envelope from instead of the account address.
func placeholderSender(mailFrom string) bool {
	mailFrom = strings.ToLower(strings.TrimSpace(mailFrom))
	if mailFrom == "" {
		return true
	}
	local, _, ok := strings.Cut(mailFrom, "@")
	return ok && local == "unknown"
}

func splitAuthArg(arg string) (mech, rest string) {
	arg = strings.TrimSpace(arg)
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		return strings.ToUpper(arg), ""
	}
	return strings.ToUpper(strings.TrimSpace(arg[:i])), strings.TrimSpace(arg[i+1:])
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
	s.mailRet = mail.RetNone
	s.mailEnvid = ""
	s.rcpt = s.rcpt[:0]
	s.bdatBuf = s.bdatBuf[:0]
	s.bdatUsed = false
}

// finishDelivery stores the message for local recipients and enqueues remote ones.
func (s *session) finishDelivery(ctx context.Context, raw []byte) error {
	var remotes []string
	for _, t := range s.rcpt {
		if t.accountID == 0 {
			remotes = append(remotes, t.address)
			continue
		}
		if _, err := s.inbox.Deliver(ctx, t.accountID, raw); err != nil {
			s.log.Warn("deliver failed", "rcpt", t.address, slog.Any("err", err))
			if err := s.writef("451 delivery failed"); err != nil {
				return err
			}
			s.reset()
			return nil
		}
	}
	if len(remotes) > 0 {
		if s.queue == nil {
			if err := s.writef("451 outbound delivery unavailable"); err != nil {
				return err
			}
			s.reset()
			return nil
		}
		if _, err := s.queue.EnqueueDSN(ctx, s.buildEnvelopeDSN(remotes), raw); err != nil {
			s.log.Warn("enqueue failed", slog.Any("err", err))
			if err := s.writef("451 delivery failed"); err != nil {
				return err
			}
			s.reset()
			return nil
		}
	}
	if err := s.writef(smtpOK); err != nil {
		return err
	}
	s.reset()
	return nil
}

// cmdBDAT receives one binary chunk and delivers the message on the final LAST chunk.
func (s *session) cmdBDAT(ctx context.Context, arg string) error {
	if s.mailFrom == "" || len(s.rcpt) == 0 {
		return s.writef("503 5.5.1 Bad sequence of commands")
	}
	size, last, ok := parseBDAT(arg)
	if !ok {
		return s.writef("501 5.5.4 Syntax: BDAT <size> [LAST]")
	}
	if size > s.dataLimits.MaxMessageBytes {
		return s.writef("552 5.3.4 Message size exceeds fixed maximum message size")
	}
	if len(s.bdatBuf)+size > s.dataLimits.MaxMessageBytes {
		return s.writef("552 5.3.4 Message size exceeds fixed maximum message size")
	}
	if err := s.writef("250 2.0.0 Ok"); err != nil {
		return err
	}
	chunk, err := readBDATChunk(s.r, size)
	if err != nil {
		s.reset()
		return err
	}
	s.bdatUsed = true
	s.bdatBuf = append(s.bdatBuf, chunk...)
	if !last {
		return nil
	}
	if err := s.finishDelivery(ctx, s.bdatBuf); err != nil {
		return err
	}
	return nil
}

// buildEnvelopeDSN collects MAIL/RCPT DSN parameters for queued remote recipients.
func (s *session) buildEnvelopeDSN(remotes []string) mail.EnvelopeDSN {
	env := mail.EnvelopeDSN{
		ReturnPath: s.mailFrom,
		Ret:        s.mailRet,
		Envid:      s.mailEnvid,
	}
	remoteSet := make(map[string]rcptTarget, len(remotes))
	for _, t := range s.rcpt {
		if t.accountID == 0 {
			remoteSet[t.address] = t
		}
	}
	for _, addr := range remotes {
		t, ok := remoteSet[strings.ToLower(addr)]
		notify := mail.NotifyDefault
		orcpt := ""
		if ok {
			notify = t.notify
			orcpt = t.orcpt
		}
		env.Recipients = append(env.Recipients, mail.RcptDSN{
			Address: addr,
			Notify:  notify,
			Orcpt:   orcpt,
		})
	}
	return env
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
