// SMTP session state machine for one client connection.
package smtp

import (
	"bufio"
	"bytes"
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
	"github.com/BeaverMail/beavermaild/internal/sasl"
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
	held      *bytes.Buffer // replies RFC 2920 3.2 (2) lets go out together; nil when not holding
	txnRcpts  int           // RCPT commands accepted in this transaction
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

func newSession(log *slog.Logger, conn net.Conn, dir *directory.Local, inbox *mail.Inbox, queue *mail.Queue, certs *tlsload.Certs, secure, vrfyEnabled, submission bool, limits DataLimits, filter MessageFilter, filterTmpDir string, filterTimeoutMs int, mailAuth *mailauth.Verifier, gate security.AuthGate, sendGate security.SendGate, greylist *Greylist, asnLookup *ASNLookup, readTimeout time.Duration) *session {
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
		for i, c := range cmds {
			// Never keep other arguments: AUTH carries credentials.
			s.curCmd = c.cmd
			if c.cmd == "MAIL" || c.cmd == "RCPT" {
				s.curCmd = c.cmd + " " + c.arg
			}
			// RFC 2920 3.2 (2): replies to RSET, MAIL and RCPT inside a group go out together; any
			// other command, and the end of the group, sends them first (5)-(7).
			if groupedReply(c.cmd) && i < len(cmds)-1 {
				s.holdReplies()
			} else if err := s.flushReplies(); err != nil {
				return err
			}
			stop, blockMail, err := s.dispatch(ctx, c.cmd, c.arg, mailBlocked)
			if blockMail {
				mailBlocked = true
			}
			if err != nil || stop {
				_ = s.flushReplies() // what was answered still reaches the client
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
		if err := s.flushReplies(); err != nil {
			return err
		}
	}
}

// groupedReply reports the commands whose replies RFC 2920 3.2 (2) lets a server hold and send
// together with the rest of the group.
func groupedReply(cmd string) bool { return cmd == "RSET" || cmd == "MAIL" || cmd == "RCPT" }

// holdReplies makes writef collect replies instead of writing them, until flushReplies.
func (s *session) holdReplies() {
	if s.held == nil {
		s.held = new(bytes.Buffer)
	}
}

// flushReplies writes the held replies in one write and stops holding.
func (s *session) flushReplies() error {
	if s.held == nil {
		return nil
	}
	held := s.held
	s.held = nil
	if held.Len() == 0 {
		return nil
	}
	_, err := s.conn.Write(held.Bytes())
	return err
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
	// A BDAT chunk leaves the stream before any check can answer: every reply, a refusal
	// included, comes after the data (RFC 3030 2). Left unread it would be parsed as commands
	// (SMTP smuggling through BDAT).
	var chunk bdatChunk
	if cmd == "BDAT" {
		if chunk, err = s.consumeBDAT(arg); err != nil {
			return false, false, err
		}
	}
	// Submission without TLS is of no use (AUTH needs it): like a server that requires TLS, answer
	// every command but NOOP, EHLO, STARTTLS and QUIT with 530 (RFC 3207 4). AUTH keeps the more
	// specific 538 5.7.11 of RFC 4954 6.
	if s.submission && !s.secure && s.tls != nil {
		switch cmd {
		case "NOOP", "EHLO", "STARTTLS", "QUIT", "AUTH":
		default:
			return false, cmd == "MAIL", s.writef(replyTLSRequired)
		}
	}
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
		if strings.TrimSpace(arg) != "" {
			return false, false, s.writef("501 5.5.4 Syntax: STARTTLS takes no parameters") // RFC 3207 4
		}
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
		return false, false, s.cmdBDAT(ctx, chunk)
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
	return false, s.writef(replyMailOK)
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
	return s.writef(replyRcptOK)
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

// cmdAuth handles AUTH on submission listeners after TLS is active (RFC 4954 4).
func (s *session) cmdAuth(ctx context.Context, arg string) error {
	if !s.submission {
		return s.writef(replyNotImplemented)
	}
	if !s.secure {
		return s.writef(replyTLSRequiredAuth)
	}
	// One successful AUTH per session, and none inside a mail transaction (both MUST, 503).
	if s.principal.AccountID != 0 || s.inTxn {
		return s.writef(replyBadSequence)
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

// SASL exchange replies (RFC 4954 4).
const (
	replyAuthCancelled = "501 5.0.0 Authentication cancelled"
	replyAuthBase64    = "501 5.5.2 Cannot decode response"
	replyAuthLineLong  = "500 5.5.6 Authentication exchange line is too long"
	replyAuthBadCreds  = "535 5.7.8 Authentication credentials invalid"
)

// authResponse sends challenge and reads the client's answer. It returns the decoded bytes, or
// the reply that ends the exchange: "*" cancels (501), anything not BASE64 is refused (501), and a
// line past the authentication buffer fails the command (500 5.5.6), not the session.
func (s *session) authResponse(challenge string) (data []byte, reply string, err error) {
	if err := s.writef("334 " + challenge); err != nil {
		return nil, "", err
	}
	line, err := s.readLine()
	if errors.Is(err, errLineTooLong) {
		return nil, replyAuthLineLong, nil
	} else if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(line) == sasl.Cancel {
		return nil, replyAuthCancelled, nil
	}
	if data, err = sasl.DecodeResponse(line); err != nil {
		return nil, replyAuthBase64, nil
	}
	return data, "", nil
}

func (s *session) authPlain(ctx context.Context, initial string) error {
	var data []byte
	if initial = strings.TrimSpace(initial); initial != "" {
		var err error
		if data, err = sasl.DecodeResponse(initial); err != nil {
			return s.writef(replyAuthBase64)
		}
	} else {
		var reply string
		var err error
		if data, reply, err = s.authResponse(""); err != nil || reply != "" {
			if err != nil {
				return err
			}
			return s.writef(reply)
		}
	}
	authzid, user, pass, err := sasl.ParsePlain(data)
	if err != nil {
		return s.writef(replyAuthBadCreds)
	}
	if !sasl.AuthorizedAs(authzid, user) {
		return s.writef(replyAuthBadCreds) // RFC 4616 2: no rule lets one user act as another
	}
	return s.finishAuth(ctx, user, pass)
}

// authLogin is the LOGIN mechanism (draft-murchison-sasl-login): the server asks first, so an
// initial response is refused with 501 (RFC 4954 4).
func (s *session) authLogin(ctx context.Context, initial string) error {
	if strings.TrimSpace(initial) != "" {
		return s.writef("501 5.5.2 LOGIN takes no initial response")
	}
	user, reply, err := s.authResponse(base64.StdEncoding.EncodeToString([]byte("Username:")))
	if err != nil || reply != "" {
		if err != nil {
			return err
		}
		return s.writef(reply)
	}
	if len(user) == 0 {
		return s.writef(replyAuthBadCreds)
	}
	pass, reply, err := s.authResponse(base64.StdEncoding.EncodeToString([]byte("Password:")))
	if err != nil || reply != "" {
		if err != nil {
			return err
		}
		return s.writef(reply)
	}
	return s.finishAuth(ctx, string(user), string(pass))
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
			return s.writef(replyAuthBadCreds)
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
	s.notifyLocalSuccess(ctx, raw)
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

// notifyLocalSuccess issues a "delivered" DSN for each local recipient that asked for one with
// NOTIFY=SUCCESS (RFC 3461 5.2.3 (a)). The messages are already stored: a failure here is logged.
// The DSN goes out with a null sender and NOTIFY=NEVER (RFC 3461 6.1).
func (s *session) notifyLocalSuccess(ctx context.Context, raw []byte) {
	if s.mailFrom == "" {
		return
	}
	for _, t := range s.rcpt {
		if t.accountID == 0 || t.report != "" || !mail.NotifyWanted(t.notify, mail.DSNActionDelivered) {
			continue
		}
		dsn := mail.BuildDSN(mail.DSNBuildOpts{
			ReturnPath: s.mailFrom, FinalRcpt: t.address, Orcpt: t.orcpt, Envid: s.mailEnvid, Ret: s.mailRet,
			Action: mail.DSNActionDelivered, Status: "2.0.0", OriginalRaw: raw, Hostname: s.hostname,
		})
		var err error
		if acc, _, rerr := s.dir.ResolveEmail(ctx, s.mailFrom); rerr == nil && acc.Active {
			_, err = s.inbox.Deliver(ctx, acc.ID, dsn)
		} else if s.queue != nil {
			_, err = s.queue.EnqueueDSN(ctx, mail.EnvelopeDSN{Recipients: []mail.RcptDSN{{Address: s.mailFrom, Notify: mail.NotifyNever}}}, dsn)
		} else {
			err = errors.New("no outbound queue")
		}
		if err != nil {
			s.log.Warn("success dsn failed", "rcpt", t.address, "return_path", s.mailFrom, slog.Any("err", err))
		}
	}
}

// cmdBDAT receives one binary chunk and delivers the message on the final LAST chunk.
// bdatChunk is a BDAT command with its data already off the stream.
type bdatChunk struct {
	data   []byte
	last   bool
	tooBig bool // over MaxMessageBytes: read and dropped
}

// consumeBDAT parses a BDAT command and reads its chunk: kept in memory when it fits the message
// limit, discarded otherwise. A size that cannot be parsed leaves no way to find the next command,
// so the session ends.
func (s *session) consumeBDAT(arg string) (bdatChunk, error) {
	size, last, ok := parseBDAT(arg)
	if !ok {
		_ = s.writef(replySyntaxBDAT)
		return bdatChunk{}, fmt.Errorf("smtp: bdat syntax %q", arg)
	}
	c := bdatChunk{last: last}
	if size > s.dataLimits.MaxMessageBytes || len(s.bdatBuf)+size > s.dataLimits.MaxMessageBytes {
		c.tooBig = true
		if err := discardBDATChunk(s.r, int64(size), s.bumpReadDeadline); err != nil {
			s.reset()
			return bdatChunk{}, err
		}
		return c, nil
	}
	var err error
	if c.data, err = readBDATChunk(s.r, size, s.bumpReadDeadline); err != nil {
		s.reset()
		return bdatChunk{}, err
	}
	return c, nil
}

func (s *session) cmdBDAT(ctx context.Context, c bdatChunk) error {
	if !s.inTxn || len(s.rcpt) == 0 {
		return s.writef(replyBadSequence)
	}
	if c.tooBig {
		s.reset() // the message is lost; RSET state, the session goes on (RFC 3030 2)
		return s.writef(replyMessageTooLarge)
	}
	s.bdatUsed = true
	s.bdatBuf = append(s.bdatBuf, c.data...)
	if !c.last {
		return s.writef("250 2.0.0 %d octets received", len(c.data))
	}
	// BDAT is length-framed, so a bare CR cannot end the data; stored, it would still end a header
	// line for some readers. Same rule as Exim: a continuation in the header, a line end in the body.
	return s.deliverAfterFilter(ctx, mail.BareCR(s.bdatBuf))
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
	if s.held != nil {
		s.held.WriteString(line)
		return nil
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
