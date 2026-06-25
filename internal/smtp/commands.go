// SMTP auxiliary commands (HELP, VRFY, EXPN).
package smtp

// cmdHelp returns a short list of supported SMTP commands.
func (s *session) cmdHelp(arg string) error {
	_ = arg
	lines := []string{
		"214-2.0.0 Commands:",
		"214- EHLO HELO MAIL RCPT DATA RSET NOOP QUIT",
		"214- STARTTLS AUTH BDAT HELP VRFY EXPN",
		"214 2.0.0 End",
	}
	for _, line := range lines {
		if err := s.writef(line); err != nil {
			return err
		}
	}
	return nil
}

// cmdVrfy is disabled by default (RFC 5321 security guidance).
func (s *session) cmdVrfy(arg string) error {
	if arg == "" {
		return s.writef(replySyntaxVRFY)
	}
	return s.writef("252 2.5.1 VRFY is disabled")
}

// cmdExpn is disabled (no mailing-list expansion in Beaver).
func (s *session) cmdExpn(arg string) error {
	_ = arg
	return s.writef("252 2.5.1 EXPN is disabled")
}
