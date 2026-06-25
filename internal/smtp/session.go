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
	vrfyEnabled bool
	submission  bool
	pipelining  bool
	dataLimits  DataLimits

	principal directory.Principal

	mailFrom  string
	mailRet   mail.RetMode
	mailEnvid string
	mailBody  string
	mailUTF8  bool
	rcpt      []rcptTarget

	bdatBuf  []byte
	bdatUsed bool
}

type rcptTarget struct {
	address   string
	accountID uint32 // 0 = outbound queue recipient
	notify    mail.NotifyFlags
	orcpt     string
}

type smtpCommand struct {
	cmd string
	arg string
}

func newSession(log *slog.Logger, conn net.Conn, dir *directory.Local, inbox *mail.Inbox, queue *mail.Queue, certs *tlsload.Certs, secure, tlsRequired, vrfyEnabled, submission bool, limits DataLimits) *session {
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
		vrfyEnabled: vrfyEnabled,
		submission:  submission,
		dataLimits:  limits.withDefaults(),
	}
}

func (s *session) run(ctx context.Context) error {
	if err := s.writef("220 localhost ESMTP BeaverMail"); err != nil {
		return err
	}
	for {
		cmds, err := s.readCommandBatch()
		if err != nil {
			return err
		}
		mailBlocked := false
		for _, c := range cmds {
			stop, blockMail, err := s.dispatch(ctx, c.cmd, c.arg, mailBlocked)
			if blockMail {
				mailBlocked = true
			}
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
	}
}

func (s *session) readCommandBatch() ([]smtpCommand, error) {
	var batch []smtpCommand
	for {
		line, err := s.readLine()
		if err != nil {
			return batch, err
		}
		if line == "" {
			continue
		}
		cmd, arg := parseCommand(line)
		batch = append(batch, smtpCommand{cmd: cmd, arg: arg})
		if !s.pipelining || !pipelineContinues(cmd) {
			break
		}
		if s.r.Buffered() == 0 {
			break
		}
	}
	return batch, nil
}

func pipelineContinues(cmd string) bool {
	switch cmd {
	case "MAIL", "RCPT", "RSET", "NOOP", "HELP", "VRFY", "EXPN", "ETRN", "ATRN", "BURL":
		return true
	default:
		return false
	}
}

func (s *session) dispatch(ctx context.Context, cmd, arg string, mailBlocked bool) (stop, blockMail bool, err error) {
	switch cmd {
	case "EHLO":
		s.pipelining = true
		return false, false, s.writeEHLO(true)
	case "HELO":
		s.pipelining = false
		return false, false, s.writeEHLO(false)
	case "STARTTLS":
		return false, false, s.cmdStartTLS()
	case "AUTH":
		return false, false, s.cmdAuth(ctx, arg)
	case "MAIL":
		block, err := s.handleMail(ctx, arg)
		return false, block, err
	case "RCPT":
		return false, false, s.handleRcpt(ctx, arg, mailBlocked)
	case "DATA":
		if mailBlocked {
			return false, false, s.writef(replyBadSequence)
		}
		return false, false, s.handleDATA(ctx)
	case "BDAT":
		if mailBlocked {
			return false, false, s.writef(replyBadSequence)
		}
		return false, false, s.cmdBDAT(ctx, arg)
	case "HELP":
		return false, false, s.cmdHelp(arg)
	case "VRFY":
		return false, false, s.cmdVrfy(ctx, arg)
	case "EXPN":
		return false, false, s.cmdExpn(arg)
	case "ETRN", "ATRN", "BURL":
		return false, false, s.writef(replyNotImplemented)
	case "RSET":
		s.reset()
		return false, false, s.writef(replyOK)
	case "NOOP":
		return false, false, s.writef(replyOK)
	case "QUIT":
		_ = s.writef(replyBye)
		return true, false, nil
	default:
		return false, false, s.writef(replyNotImplemented)
	}
}

func (s *session) handleMail(ctx context.Context, arg string) (blockMail bool, err error) {
	_ = ctx
	if s.submission && !s.secure {
		return true, s.writef(replyTLSRequired)
	}
	addr, declaredSize, mailParams, ok := parseMailArg(arg)
	if !ok {
		return true, s.writef(replySyntaxMail)
	}
	if mailParams.Unsupported != "" {
		return true, s.writef(mailParams.Unsupported)
	}
	body := strings.ToUpper(strings.TrimSpace(mailParams.Body))
	switch body {
	case "", "7BIT", "8BITMIME":
	default:
		if body == "BINARYMIME" {
			return true, s.writef(replyBinaryNotSupported)
		}
		return true, s.writef(replySyntaxMail)
	}
	if !validEnvelopeAddress(addr) {
		return true, s.writef(replySyntaxMail)
	}
	if addressNeedsUTF8(addr) && !mailParams.SMTPUTF8 {
		return true, s.writef(replyUTF8Required)
	}
	if declaredSize > s.dataLimits.MaxMessageBytes {
		return true, s.writef(replyMessageTooLarge)
	}
	if s.submission && s.principal.AccountID == 0 {
		return true, s.writef(replyAuthRequired)
	}
	if s.submission {
		resolved, ok := resolveSubmissionMailFrom(s.principal, addr)
		if !ok {
			return true, s.writef(replySenderRejected)
		}
		addr = resolved
	}
	s.reset()
	s.mailFrom = addr
	s.mailRet = mailParams.Ret
	s.mailEnvid = mailParams.Envid
	if body == "" {
		s.mailBody = "7BIT"
	} else {
		s.mailBody = body
	}
	s.mailUTF8 = mailParams.SMTPUTF8 || addressNeedsUTF8(addr)
	return false, s.writef(replyOK)
}

func (s *session) handleRcpt(ctx context.Context, arg string, mailBlocked bool) error {
	if mailBlocked {
		return s.writef(replyBadSequence)
	}
	addr, rcptParams, ok := parseRcptArg(arg)
	if !ok {
		return s.writef(replySyntaxRcpt)
	}
	if rcptParams.Unsupported != "" {
		return s.writef(rcptParams.Unsupported)
	}
	if s.mailFrom == "" {
		return s.writef(replyBadSequence)
	}
	if !validEnvelopeAddress(addr) {
		return s.writef(replySyntaxRcpt)
	}
	if addressNeedsUTF8(addr) && !s.mailUTF8 {
		return s.writef(replyUTF8Required)
	}
	domName, err := DomainFromAddress(addr)
	if err != nil {
		return s.writef(replySyntaxRcpt)
	}
	if _, err := s.dir.LookupDomain(ctx, domName); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			if !s.submission {
				return s.writef(replyRelayDenied)
			}
			if s.queue == nil {
				return s.writef(replyDomainUnknown)
			}
			s.rcpt = append(s.rcpt, rcptTarget{
				address: normalizeEnvelopeAddress(addr),
				notify:  rcptParams.Notify,
				orcpt:   rcptParams.Orcpt,
			})
			return s.writef(replyOK)
		}
		return err
	}
	acc, _, err := s.dir.ResolveEmail(ctx, addr)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return s.writef(replyUserUnknown)
		}
		return err
	}
	if !acc.Active {
		return s.writef(replyUserInactive)
	}
	s.rcpt = append(s.rcpt, rcptTarget{
		address:   normalizeEnvelopeAddress(addr),
		accountID: acc.ID,
		notify:    rcptParams.Notify,
		orcpt:     rcptParams.Orcpt,
	})
	return s.writef(replyOK)
}

func (s *session) handleDATA(ctx context.Context) error {
	if s.bdatUsed {
		return s.writef(replyBDATInProgress)
	}
	if len(s.rcpt) == 0 {
		return s.writef(replyBadSequence)
	}
	if err := s.writef(replyDataStart); err != nil {
		return err
	}
	raw, err := readDATA(s.r, s.dataLimits)
	if err != nil {
		drainDATA(s.r)
		if werr := s.writef(dataErrorResponse(err)); werr != nil {
			return werr
		}
		s.reset()
		return nil
	}
	return s.finishDelivery(ctx, raw)
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
		"250-FUTURERELEASE",
		"250-DELIVER BY",
		"250-MT-PRIORITY",
		"250-NO-SOLICITING",
		fmt.Sprintf("250-SIZE %d", s.dataLimits.MaxMessageBytes),
	}
	if s.vrfyEnabled {
		lines = append(lines, "250-VRFY", "250-EXPN")
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

// cmdAuth handles AUTH on submission listeners after TLS is active.
func (s *session) cmdAuth(ctx context.Context, arg string) error {
	if !s.submission {
		return s.writef(replyNotImplemented)
	}
	if !s.secure {
		return s.writef(replyTLSRequiredAuth)
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
	return s.writef(replyAuthOK)
}

// senderAllowed reports whether mailFrom matches the authenticated account (aliases later).
func senderAllowed(p directory.Principal, mailFrom string) bool {
	return strings.EqualFold(mailFrom, p.Email())
}

// resolveSubmissionMailFrom accepts the client envelope sender or substitutes placeholders (e.g. Claws unknown@localhost).
func resolveSubmissionMailFrom(p directory.Principal, mailFrom string) (string, bool) {
	if senderAllowed(p, mailFrom) {
		return normalizeEnvelopeAddress(mailFrom), true
	}
	if placeholderSender(mailFrom) {
		return normalizeEnvelopeAddress(p.Email()), true
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
		return s.writef(replyTLSAlreadyActive)
	}
	if s.tls == nil {
		return s.writef(replyTLSUnavailable)
	}
	if err := s.writef(replyTLSReady); err != nil {
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
	s.mailBody = ""
	s.mailUTF8 = false
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
			if err := s.writef(replyLocalError); err != nil {
				return err
			}
			s.reset()
			return nil
		}
	}
	if len(remotes) > 0 {
		if s.queue == nil {
			if err := s.writef(replyOutboundUnavailable); err != nil {
				return err
			}
			s.reset()
			return nil
		}
		if _, err := s.queue.EnqueueDSN(ctx, s.buildEnvelopeDSN(remotes), raw); err != nil {
			s.log.Warn("enqueue failed", slog.Any("err", err))
			if err := s.writef(replyLocalError); err != nil {
				return err
			}
			s.reset()
			return nil
		}
	}
	if err := s.writef(replyOK); err != nil {
		return err
	}
	s.reset()
	return nil
}

// cmdBDAT receives one binary chunk and delivers the message on the final LAST chunk.
func (s *session) cmdBDAT(ctx context.Context, arg string) error {
	if s.mailFrom == "" || len(s.rcpt) == 0 {
		return s.writef(replyBadSequence)
	}
	size, last, ok := parseBDAT(arg)
	if !ok {
		return s.writef(replySyntaxBDAT)
	}
	if size > s.dataLimits.MaxMessageBytes {
		return s.writef(replyMessageTooLarge)
	}
	if len(s.bdatBuf)+size > s.dataLimits.MaxMessageBytes {
		return s.writef(replyMessageTooLarge)
	}
	if err := s.writef(replyOK); err != nil {
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
		Body:       s.mailBody,
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
