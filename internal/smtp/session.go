// SMTP session state machine for one client connection.
package smtp

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/mailauth"
	"github.com/BeaverMail/beavermaild/internal/security"
	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
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

	filter          MessageFilter
	filterTmpDir    string
	filterTimeoutMs int
	filterSeq       int
	filterTxnID     string
	mailAuth        *mailauth.Verifier
	heloDomain      string
	authState       mailauth.SessionState
	authDone        bool // FinishEom ran for this transaction (Authentication-Results can be added)
	iprevPTR        string
	iprevResult     string
	iprevDone       bool
	clientASN       uint32
	clientCountry   string
	asnDone         bool
	asnLookup       *ASNLookup

	principal   directory.Principal
	authGate    security.AuthGate
	sendGate    security.SendGate
	greylist    *Greylist
	readTimeout time.Duration
	hostname    string       // banner and EHLO name
	curCmd      string       // command being answered, for reply logging (MAIL/RCPT keep their argument)
	stopping    *atomic.Bool // server shutdown flag (nil when not served by a Server)

	mailFrom  string // "" is the null reverse-path (bounces); inTxn tells whether MAIL was accepted
	inTxn     bool
	txnRcpts  int // RCPT commands accepted in this transaction
	mailRet   mail.RetMode
	mailEnvid string
	mailBody  string
	mailUTF8  bool
	rcpt      []rcptTarget

	// Session-wide abuse counters (RFC 5321 7.8).
	goodRcpts, badRcpts, unknownCmds int
	// postmasters caches ResolvePostmaster per tenant: it scans every account, and a client could
	// otherwise repeat RCPT TO:<postmaster@...> up to MaxRecipients times per transaction.
	postmasters map[uint32][]storage.Account

	bdatBuf  []byte
	bdatUsed bool
}

type rcptTarget struct {
	address   string
	accountID uint32 // 0 = outbound queue recipient (unless report is set)
	notify    mail.NotifyFlags
	orcpt     string
	report    string // dmarc|tls: goes to the domain report store, never an INBOX
}

type smtpCommand struct {
	cmd string
	arg string
}

func newSession(log *slog.Logger, conn net.Conn, dir *directory.Local, inbox *mail.Inbox, queue *mail.Queue, certs *tlsload.Certs, secure, tlsRequired, vrfyEnabled, submission bool, limits DataLimits, filter MessageFilter, filterTmpDir string, filterTimeoutMs int, mailAuth *mailauth.Verifier, gate security.AuthGate, sendGate security.SendGate, greylist *Greylist, asnLookup *ASNLookup, readTimeout time.Duration) *session {
	if filter == nil {
		filter = NopFilter{}
	}
	if gate == nil {
		gate = security.NopGate{}
	}
	if sendGate == nil {
		sendGate = security.NopSendGate{}
	}
	if filterTimeoutMs <= 0 {
		filterTimeoutMs = 10000
	}
	return &session{
		log:             log,
		conn:            conn,
		r:               bufio.NewReader(conn),
		dir:             dir,
		inbox:           inbox,
		queue:           queue,
		tls:             certs,
		secure:          secure,
		tlsRequired:     tlsRequired,
		vrfyEnabled:     vrfyEnabled,
		submission:      submission,
		dataLimits:      limits.withDefaults(),
		filter:          filter,
		filterTmpDir:    filterTmpDir,
		filterTimeoutMs: filterTimeoutMs,
		mailAuth:        mailAuth,
		authGate:        gate,
		sendGate:        sendGate,
		greylist:        greylist,
		asnLookup:       asnLookup,
		readTimeout:     readTimeout,
		hostname:        "localhost",
	}
}

func (s *session) run(ctx context.Context) error {
	s.log.Debug("smtp connect", "ip", s.clientIP(), "submission", s.submission)
	if err := s.writef("220 %s ESMTP BeaverMail", s.hostname); err != nil {
		return err
	}
	s.ensureIPRev(ctx)
	s.ensureASN(ctx)
	if out, err := s.runFilter(ctx, FilterPhaseConnect, nil, ""); err != nil {
		return err
	} else if out.Action != FilterActionAccept {
		reply, _ := s.replyFilterAction(out.Action)
		if reply == "" {
			reply = replyConnectionRejected
		}
		_ = s.writef(reply)
		return nil
	}
	for {
		cmds, err := s.readCommandBatch()
		if err != nil {
			return err
		}
		mailBlocked := false
		for _, c := range cmds {
			// Never keep other arguments: AUTH carries credentials.
			s.curCmd = c.cmd
			if c.cmd == "MAIL" || c.cmd == "RCPT" {
				s.curCmd = c.cmd + " " + c.arg
			}
			stop, blockMail, err := s.dispatch(ctx, c.cmd, c.arg, mailBlocked)
			if blockMail {
				mailBlocked = true
			}
			if errors.Is(err, errCloseSession) {
				return nil
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
		if errors.Is(err, errLineTooLong) {
			batch = append(batch, smtpCommand{cmd: cmdLineTooLong})
			break
		}
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
	case "EHLO", "HELO":
		// RFC 5321 4.1.4: a bad EHLO gets 501 and leaves the state alone; a good one resets like RSET.
		domain, _, _ := strings.Cut(strings.TrimSpace(arg), " ")
		if domain == "" {
			return false, false, s.writef(replySyntaxHelo)
		}
		s.reset()
		s.heloDomain = domain
		s.pipelining = cmd == "EHLO"
		s.checkSPFEhlo(ctx)
		if err := s.filterHelo(ctx); err != nil {
			return false, false, err
		}
		return false, false, s.writeEHLO(cmd == "EHLO")
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
	case "ETRN", "ATRN", "BURL", "TURN", "SEND", "SOML", "SAML":
		return false, false, s.writef(replyNotImplemented)
	case cmdLineTooLong:
		return false, false, s.writef(replyLineTooLong)
	case "RSET":
		s.reset()
		return false, false, s.writef(replyOK)
	case "NOOP":
		return false, false, s.writef(replyOK)
	case "QUIT":
		_ = s.writef(replyBye)
		return true, false, nil
	default:
		// RFC 5321 4.2.4: 500 for an unknown command, 502 only for known but unimplemented ones.
		if s.unknownCmds++; s.unknownCmds >= MaxUnknownCommands {
			return true, false, s.writef(replyTooManyUnknown)
		}
		return false, false, s.writef(replyUnrecognized)
	}
}

func (s *session) handleMail(ctx context.Context, arg string) (blockMail bool, err error) {
	_ = ctx
	if s.submission && !s.secure {
		return true, s.writef(replyTLSRequired)
	}
	// RFC 5321 4.1.4: EHLO/HELO opens the session, and MAIL MUST NOT be sent inside an open transaction.
	if s.heloDomain == "" {
		return true, s.writef(replyNoHelo)
	}
	if s.inTxn {
		return true, s.writef(replyNestedMail)
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
	// RFC 5321 4.1.1.2: Reverse-path = Path / "<>"; the null path carries bounces, DSNs and MDNs.
	if addr != "" && !validEnvelopeAddress(addr) {
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
	// A null path impersonates no one and must stay null (RFC 5321 4.5.5, 6.1).
	if s.submission && addr != "" {
		resolved, ok := resolveSubmissionMailFrom(s.principal, addr)
		if !ok {
			return true, s.writef(replySenderRejected)
		}
		addr = resolved
	}
	s.reset()
	s.inTxn = true
	s.mailFrom = addr
	s.mailRet = mailParams.Ret
	s.mailEnvid = mailParams.Envid
	if body == "" {
		s.mailBody = "7BIT"
	} else {
		s.mailBody = body
	}
	s.mailUTF8 = mailParams.SMTPUTF8 || addressNeedsUTF8(addr)
	s.checkSPFMailFrom(ctx)
	if out, err := s.runFilter(ctx, FilterPhaseMail, nil, ""); err != nil {
		return true, err
	} else if out.Action != FilterActionAccept {
		reply, _ := s.replyFilterAction(out.Action)
		if reply == "" {
			reply = replyFilterReject
		}
		return true, s.writef(reply)
	}
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
	if !s.inTxn {
		return s.writef(replyBadSequence)
	}
	if s.txnRcpts >= MaxRecipients {
		return s.writef(replyTooManyRcpts) // RFC 5321 4.5.3.1.10
	}
	// RFC 5321 4.5.1: "RCPT TO:<Postmaster>" with no domain MUST be accepted.
	if strings.EqualFold(addr, directory.PostmasterLocalPart) && !s.submission {
		return s.acceptPostmaster(ctx, rcptParams)
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
	dom, err := s.dir.LookupDomain(ctx, domName)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			if !s.submission {
				return s.writef(replyRelayDenied)
			}
			if s.queue == nil {
				return s.writef(replyDomainUnknown)
			}
			if ok, err := s.allowGreylist(ctx, addr); err != nil {
				return err
			} else if !ok {
				return s.writef("452 4.2.2 Try again later")
			}
			return s.addRcpt(ctx, normalizeEnvelopeAddress(addr), rcptTarget{
				address: normalizeEnvelopeAddress(addr),
				notify:  rcptParams.Notify,
				orcpt:   rcptParams.Orcpt,
			})
		}
		return err
	}
	target := rcptTarget{
		address: normalizeEnvelopeAddress(addr),
		notify:  rcptParams.Notify,
		orcpt:   rcptParams.Orcpt,
		report:  reportKindForAddress(addr),
	}
	targets := []rcptTarget{target}
	// Report addresses skip account lookup so a catch-all cannot swallow them.
	if target.report == "" {
		accounts, err := s.resolveLocalRcpt(ctx, addr, domName)
		if errors.Is(err, directory.ErrNotFound) && strings.EqualFold(localPart(addr), directory.PostmasterLocalPart) {
			accounts, err = s.resolvePostmaster(ctx, dom.TenantID)
		}
		if errors.Is(err, directory.ErrNotFound) {
			return s.unknownRcpt()
		}
		if err != nil {
			return err
		}
		targets = targets[:0]
		for _, acc := range accounts {
			if acc.Active {
				t := target
				t.accountID = acc.ID
				targets = append(targets, t)
			}
		}
		if len(targets) == 0 {
			return s.writef(replyUserInactive)
		}
	}
	if ok, err := s.allowGreylist(ctx, addr); err != nil {
		return err
	} else if !ok {
		return s.writef("452 4.2.2 Try again later")
	}
	return s.addRcpt(ctx, normalizeEnvelopeAddress(addr), targets...)
}

// acceptPostmaster takes the bare "Postmaster" recipient for the instance admins (RFC 5321 4.5.1).
func (s *session) acceptPostmaster(ctx context.Context, params RcptParams) error {
	accounts, err := s.resolvePostmaster(ctx, 0)
	if errors.Is(err, directory.ErrNotFound) {
		return s.writef(replyUserUnknown)
	}
	if err != nil {
		return err
	}
	addr := directory.PostmasterLocalPart
	if ok, err := s.allowGreylist(ctx, addr); err != nil {
		return err
	} else if !ok {
		return s.writef("452 4.2.2 Try again later")
	}
	targets := make([]rcptTarget, 0, len(accounts))
	for _, acc := range accounts {
		targets = append(targets, rcptTarget{address: addr, notify: params.Notify, orcpt: params.Orcpt, accountID: acc.ID})
	}
	return s.addRcpt(ctx, addr, targets...)
}

// resolvePostmaster is directory.ResolvePostmaster, looked up once per tenant and session.
func (s *session) resolvePostmaster(ctx context.Context, tenantID uint32) ([]storage.Account, error) {
	if accounts, ok := s.postmasters[tenantID]; ok {
		return accounts, nil
	}
	accounts, err := s.dir.ResolvePostmaster(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if s.postmasters == nil {
		s.postmasters = map[uint32][]storage.Account{}
	}
	s.postmasters[tenantID] = accounts
	return accounts, nil
}

// addRcpt adds the recipient's targets to the transaction unless the rcpt-phase filter refuses it: a
// refused recipient must not get the message anyway.
func (s *session) addRcpt(ctx context.Context, addr string, targets ...rcptTarget) error {
	n := len(s.rcpt)
	s.rcpt = append(s.rcpt, targets...)
	if out, err := s.runFilter(ctx, FilterPhaseRcpt, []string{addr}, ""); err != nil {
		s.rcpt = s.rcpt[:n]
		return err
	} else if out.Action != FilterActionAccept {
		s.rcpt = s.rcpt[:n]
		reply, _ := s.replyFilterAction(out.Action)
		if reply == "" {
			reply = replyFilterReject
		}
		return s.writef(reply)
	}
	s.txnRcpts++
	s.goodRcpts++
	return s.writef(replyOK)
}

// unknownRcpt answers an unknown recipient; a session that mostly probes unknown addresses is closed
// (RFC 5321 7.8, address harvesting).
func (s *session) unknownRcpt() error {
	s.badRcpts++
	if s.badRcpts >= MaxBadRecipients && s.badRcpts > s.goodRcpts {
		_ = s.writef(replyTooManyBadRcpts)
		return errCloseSession
	}
	return s.writef(replyUserUnknown)
}

// errCloseSession ends the session after a final reply has been written.
var errCloseSession = errors.New("smtp: session closed by server")

// localPart returns the part of addr before the last "@".
func localPart(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return addr[:i]
	}
	return addr
}

// allowGreylist applies persistent greylisting only to unauthenticated inbound mail.
func (s *session) allowGreylist(ctx context.Context, rcpt string) (bool, error) {
	if s.greylist == nil || s.submission || s.principal.AccountID != 0 {
		return true, nil
	}
	return s.greylist.Allow(ctx, s.clientIP(), s.mailFrom, rcpt)
}

func (s *session) handleDATA(ctx context.Context) error {
	if s.bdatUsed {
		return s.writef(replyBDATInProgress)
	}
	if len(s.rcpt) == 0 {
		return s.writef(replyBadSequence)
	}
	if out, err := s.runFilter(ctx, FilterPhaseData, s.rcptAddresses(), ""); err != nil {
		return err
	} else if out.Action != FilterActionAccept {
		reply, _ := s.replyFilterAction(out.Action)
		if reply == "" {
			reply = replyFilterReject
		}
		return s.writef(reply)
	}
	if err := s.writef(replyDataStart); err != nil {
		return err
	}
	raw, err := readDATA(s.r, s.dataLimits, s.bumpReadDeadline)
	// SMTP smuggling: past a bare CR/LF, or a line too long to check, the end of data is unknowable,
	// and resuming after the next "." could run attacker text as commands. Answer and hang up, as
	// Postfix does; the same when the drain of any other failed DATA meets broken framing.
	if errors.Is(err, ErrBareLF) || errors.Is(err, ErrLineTooLong) {
		_ = s.writef(dataErrorResponse(err))
		return errCloseSession
	}
	if err != nil {
		if !drainDATA(s.r, s.dataLimits, s.bumpReadDeadline) {
			_ = s.writef(dataErrorResponse(err))
			return errCloseSession
		}
		if werr := s.writef(dataErrorResponse(err)); werr != nil {
			return werr
		}
		s.reset()
		return nil
	}
	return s.deliverAfterFilter(ctx, raw)
}

// filterHelo runs the helo-phase plugin filter before the EHLO/HELO response.
func (s *session) filterHelo(ctx context.Context) error {
	out, err := s.runFilter(ctx, FilterPhaseHelo, nil, "")
	if err != nil {
		return err
	}
	if out.Action == FilterActionAccept {
		return nil
	}
	reply, _ := s.replyFilterAction(out.Action)
	if reply == "" {
		reply = replyFilterReject
	}
	return s.writef(reply)
}

func (s *session) writeEHLO(extended bool) error {
	if !extended {
		return s.writef("250 %s", s.hostname)
	}
	lines := []string{
		"250-" + s.hostname,
		"250-ENHANCEDSTATUSCODES",
		"250-8BITMIME",
		"250-SMTPUTF8",
		"250-CHUNKING",
		"250-DSN",
		"250-PIPELINING",
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
	// One write for the whole multi-line reply (as Postfix/Exim do): naive clients read the
	// socket once after EHLO and otherwise take a leftover "250-..." line as the AUTH reply.
	// RFC 5321 4.1.1.1 / RFC 2034 3: the last line is an ehlo-keyword too, with no enhanced status code.
	lines[len(lines)-1] = "250 " + strings.TrimPrefix(lines[len(lines)-1], "250-")
	reply := strings.Join(lines, "\r\n") + "\r\n"
	if replyHook != nil {
		replyHook(s.curCmd, reply)
	}
	_, err := io.WriteString(s.conn, reply)
	return err
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
	ip := security.ClientIP(s.conn)
	if !s.authGate.AllowAuth(ip, user) {
		return s.writef("454 4.7.0 Too many authentication attempts, try again later")
	}
	p, err := s.dir.Authenticate(ctx, user, pass)
	if err != nil {
		if errors.Is(err, directory.ErrInvalidCredentials) || errors.Is(err, directory.ErrInactive) {
			// Only a wrong password counts toward the IP limit: a suspended client retrying with the right one
			// (often via a shared webmail IP) must not lock out everyone else.
			if errors.Is(err, directory.ErrInvalidCredentials) {
				s.authGate.RecordAuthFailure(ip, user)
			}
			return s.writef("535 5.7.8 Authentication credentials invalid")
		}
		return err
	}
	s.authGate.RecordAuthSuccess(ip, user)
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
	// RFC 3207 4.2: forget everything learned before TLS; the client must send EHLO again.
	s.reset()
	s.heloDomain = ""
	s.pipelining = false
	s.authState = mailauth.SessionState{}
	return nil
}

func (s *session) reset() {
	s.inTxn = false
	s.txnRcpts = 0
	s.mailFrom = ""
	s.mailRet = mail.RetNone
	s.mailEnvid = ""
	s.mailBody = ""
	s.mailUTF8 = false
	s.rcpt = s.rcpt[:0]
	s.bdatBuf = s.bdatBuf[:0]
	s.bdatUsed = false
	s.filterTxnID = ""
	s.authState = mailauth.SessionState{SPFEhlo: s.authState.SPFEhlo}
	s.authDone = false
}

// resolveLocalRcpt maps a hosted address to its accounts: the mailbox itself, else the alias
// targets, else the domain catch-all. ErrNotFound when none applies.
func (s *session) resolveLocalRcpt(ctx context.Context, addr, domName string) ([]storage.Account, error) {
	acc, _, err := s.dir.ResolveEmail(ctx, addr)
	if err == nil {
		return []storage.Account{acc}, nil
	}
	if !errors.Is(err, directory.ErrNotFound) {
		return nil, err
	}
	accounts, err := s.dir.ResolveAlias(ctx, addr)
	if err == nil && len(accounts) > 0 {
		return accounts, nil
	}
	if err != nil && !errors.Is(err, directory.ErrNotFound) {
		return nil, err
	}
	acc, _, err = s.dir.ResolveCatchAll(ctx, domName)
	if err != nil {
		return nil, err
	}
	return []storage.Account{acc}, nil
}

// finishDelivery stores the message for local recipients and enqueues remote ones.
func (s *session) finishDelivery(ctx context.Context, raw []byte) error {
	if s.submission && s.principal.AccountID != 0 {
		email := s.principal.Email()
		if !s.sendGate.AllowSend(email) {
			if err := s.writef(replySendRateLimited); err != nil {
				return err
			}
			s.reset()
			return nil
		}
	}
	var remotes []string
	// Final delivery (RFC 5321 §4.4): local copies carry the envelope sender as Return-Path,
	// replacing any the message brought along; relayed copies get none (the last hop adds it).
	local := prependHeader(stripHeaderFields(raw, "Return-Path", nil), "Return-Path", "<"+s.mailFrom+">")
	delivered := make(map[uint32]bool) // one copy per mailbox even when aliases or catch-all overlap
	for _, t := range s.rcpt {
		if t.report != "" {
			if err := s.storeReport(ctx, t, raw); err != nil {
				s.log.Warn("store report failed", "rcpt", t.address, slog.Any("err", err))
				if err := s.writef(replyLocalError); err != nil {
					return err
				}
				s.reset()
				return nil
			}
			continue
		}
		if t.accountID == 0 {
			remotes = append(remotes, t.address)
			continue
		}
		if delivered[t.accountID] {
			continue
		}
		delivered[t.accountID] = true
		if _, err := s.inbox.Deliver(ctx, t.accountID, local); err != nil {
			if errors.Is(err, mail.ErrOverQuota) {
				if err := s.writef(replyMailboxFull); err != nil {
					return err
				}
				s.reset()
				return nil
			}
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
	if s.submission && s.principal.AccountID != 0 {
		s.sendGate.RecordSend(s.principal.Email())
	}
	s.log.Info("smtp accepted", "ip", s.clientIP(), "from", s.mailFrom, "rcpts", s.rcptAddresses(), "size", len(raw), "submission", s.submission)
	if err := s.writef(replyOK); err != nil {
		return err
	}
	s.reset()
	return nil
}

// cmdBDAT receives one binary chunk and delivers the message on the final LAST chunk.
func (s *session) cmdBDAT(ctx context.Context, arg string) error {
	size, last, ok := parseBDAT(arg)
	if !ok {
		// Chunk length unknown: the stream cannot be resynchronized, so end the session.
		_ = s.writef(replySyntaxBDAT)
		return fmt.Errorf("smtp: bdat syntax %q", arg)
	}
	if size > s.dataLimits.MaxMessageBytes || len(s.bdatBuf)+size > s.dataLimits.MaxMessageBytes {
		// Refuse to read an oversized chunk; the bytes in flight leave the stream unusable.
		_ = s.writef(replyMessageTooLarge)
		s.reset()
		return fmt.Errorf("smtp: bdat chunk %d bytes over limit", size)
	}
	// RFC 3030: the chunk follows the command line immediately and the reply comes only after it.
	chunk, err := readBDATChunk(s.r, size, s.bumpReadDeadline)
	if err != nil {
		s.reset()
		return err
	}
	if !s.inTxn || len(s.rcpt) == 0 {
		return s.writef(replyBadSequence) // chunk already consumed, session stays in sync
	}
	s.bdatUsed = true
	s.bdatBuf = append(s.bdatBuf, chunk...)
	if !last {
		return s.writef("250 2.0.0 %d octets received", size)
	}
	return s.deliverAfterFilter(ctx, s.bdatBuf)
}

// buildEnvelopeDSN collects MAIL/RCPT DSN parameters for queued remote recipients.
func (s *session) buildEnvelopeDSN(remotes []string) mail.EnvelopeDSN {
	env := mail.EnvelopeDSN{
		ReturnPath: s.mailFrom,
		Ret:        s.mailRet,
		Envid:      s.mailEnvid,
		Body:       s.mailBody,
	}
	if s.principal.AccountID != 0 {
		env.SignAs = s.principal.Email()
	}
	remoteSet := make(map[string]rcptTarget, len(remotes))
	for _, t := range s.rcpt {
		if t.accountID == 0 {
			remoteSet[t.address] = t
		}
	}
	for _, addr := range remotes {
		t, ok := remoteSet[addr]
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

func (s *session) bumpReadDeadline() {
	if s.readTimeout > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	}
}

// replyHook sees every reply with the command it answers ("" before the first one); tests set it to
// check replies against the RFC grammar.
var replyHook func(cmd, reply string)

func (s *session) writef(format string, args ...any) error {
	line := fmt.Sprintf(format+"\r\n", args...)
	if replyHook != nil {
		replyHook(s.curCmd, line)
	}
	// Rejections are otherwise invisible to the operator (greylist, unknown user, filter, auth).
	if line[0] == '4' || line[0] == '5' {
		s.log.Info("smtp reply", "ip", s.clientIP(), "cmd", s.curCmd, "from", s.mailFrom, "reply", strings.TrimRight(line, "\r\n"), "submission", s.submission)
	}
	_, err := io.WriteString(s.conn, line)
	return err
}

func (s *session) readLine() (string, error) {
	// Only the wait for a command is cut short on shutdown; DATA/BDAT keep their deadline.
	stopping := s.stopping != nil && s.stopping.Load()
	if stopping {
		_ = s.conn.SetReadDeadline(time.Now())
	} else {
		s.bumpReadDeadline()
	}
	line, tooLong, err := readLineBounded(s.r, maxCommandLine)
	if err != nil {
		if stopping || (s.stopping != nil && s.stopping.Load()) {
			_ = s.writef("421 4.3.2 %s Service shutting down", s.hostname)
			return "", fmt.Errorf("smtp: server shutting down")
		}
		return "", err
	}
	if tooLong {
		return "", errLineTooLong
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// maxCommandLine bounds a command or SASL line with its CRLF. RFC 5321 4.5.3.1 asks for as few limits as
// possible (4.5.3.1.4's 512 is a floor) and RFC 4954 4 lets AUTH lines reach 12288 octets.
const maxCommandLine = 12288 + 2

// errLineTooLong reports a line over maxCommandLine; the session answers 500 and goes on.
var errLineTooLong = errors.New("smtp: line too long")

// cmdLineTooLong is the pseudo-command for an overlong line (a space never occurs in a parsed verb).
const cmdLineTooLong = "LINE TOO LONG"

func parseCommand(line string) (cmd, arg string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return strings.ToUpper(line[:i]), strings.TrimSpace(line[i+1:])
	}
	return strings.ToUpper(line), ""
}
