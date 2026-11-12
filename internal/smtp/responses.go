// SMTP server reply lines with RFC 3463 enhanced status codes.
package smtp

const (
	replyOK                  = "250 2.0.0 Ok"
	replyMailOK              = "250 2.1.0 Sender ok"    // RFC 2920 3.2 (10): the text names the command
	replyRcptOK              = "250 2.1.5 Recipient ok" // (RFC 3463 X.1.0, X.1.5)
	replyDataStart           = "354 2.0.0 Start mail input; end with <CRLF>.<CRLF>"
	replyBye                 = "221 2.0.0 Bye"
	replyTLSReady            = "220 2.0.0 Ready to start TLS"
	replyAuthOK              = "235 2.7.0 Authentication successful"
	replySyntaxMail          = "501 5.5.4 Syntax: MAIL FROM:<address>"
	replySyntaxRcpt          = "501 5.5.4 Syntax: RCPT TO:<address>"
	replySyntaxBDAT          = "501 5.5.4 Syntax: BDAT <size> [LAST]"
	replySyntaxVRFY          = "501 5.5.4 Syntax: VRFY <address>"
	replyBadSequence         = "503 5.5.1 Bad sequence of commands"
	replyBDATInProgress      = "503 5.5.1 BDAT transfer in progress"
	replyTLSAlreadyActive    = "503 5.5.1 TLS already active"
	replyNotImplemented      = "502 5.5.1 Command not implemented"
	replyTLSUnavailable      = "502 5.5.1 TLS not available"
	replyAuthRequired        = "530 5.7.0 Authentication required"
	replyTLSRequired         = "530 5.7.0 Must issue a STARTTLS command first"
	replyTLSRequiredAuth     = "538 5.7.11 Encryption required for authentication"
	replySenderRejected      = "553 5.7.1 Sender address rejected"
	replyRelayDenied         = "554 5.7.1 Relay access denied"
	replyUserUnknown         = "550 5.1.1 User unknown"
	replyDomainUnknown       = "550 5.1.2 Mailbox unavailable"
	replyUserInactive        = "550 5.1.1 User inactive"
	replyMessageTooLarge     = "552 5.3.4 Message size exceeds fixed maximum message size"
	replyBinaryNotSupported  = "555 5.6.1 BINARYMIME not supported"
	replyUTF8Required        = "553 5.6.7 Non-ASCII addresses require SMTPUTF8"
	replyParamNotSupported   = "555 5.5.4 Extension parameter not supported"
	replyParamUnknown        = "555 5.5.4 Unrecognized MAIL/RCPT parameter"
	replySyntaxHelo          = "501 5.5.4 Syntax: EHLO hostname"
	replyNoHelo              = "503 5.5.1 Send EHLO or HELO first"
	replyNestedMail          = "503 5.5.1 Sender already given"
	replyUnrecognized        = "500 5.5.2 Command unrecognized"
	replyLineTooLong         = "500 5.5.2 Line too long"
	replyBareCRLF            = "554 5.6.0 Bare CR or LF in message data, closing connection"
	replyTooManyRcpts        = "452 4.5.3 Too many recipients"
	replyTooManyBadRcpts     = "421 4.7.0 Too many invalid recipients, closing connection"
	replyTooManyUnknown      = "421 4.7.0 Too many unrecognized commands, closing connection"
	replyLocalError          = "451 4.3.0 Local error in processing"
	replyOutboundUnavailable = "451 4.3.0 Outbound delivery unavailable"
	replySendRateLimited     = "452 4.7.0 Message rate limit exceeded, try again later"
	replyFilterReject        = "550 5.7.1 Message rejected"
	replyFilterTempfail      = "451 4.7.0 Message temporarily rejected"
	replyConnectionRejected  = "554 5.7.1 Connection refused"
	replyMailboxFull         = "552 5.2.2 Mailbox full"
)

// Abuse limits (RFC 5321 7.8). Postfix and Exim use the same orders of magnitude.
const (
	// MaxRecipients caps RCPT per transaction; more get 452 4.5.3 (RFC 5321 4.5.3.1.10 floor is 100).
	MaxRecipients = 1000
	// MaxBadRecipients unknown recipients in a session, when they outnumber the good ones, end it (harvesting).
	MaxBadRecipients = 10
	// MaxUnknownCommands unrecognized commands in a session end it.
	MaxUnknownCommands = 10
)
