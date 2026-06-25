// SMTP auxiliary commands (HELP, VRFY, EXPN).
package smtp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/BeaverMail/beaver/internal/directory"
)

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

// cmdVrfy verifies a local mailbox when vrfy_enabled is true; default is 252 disabled.
func (s *session) cmdVrfy(ctx context.Context, arg string) error {
	if arg == "" {
		return s.writef(replySyntaxVRFY)
	}
	if !s.vrfyEnabled {
		return s.writef("252 2.5.1 VRFY is disabled")
	}
	addr := strings.TrimSpace(arg)
	if len(addr) >= 2 && addr[0] == '<' && addr[len(addr)-1] == '>' {
		addr = strings.TrimSpace(addr[1 : len(addr)-1])
	}
	if !validEnvelopeAddress(addr) {
		return s.writef(replySyntaxVRFY)
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
	return s.writef(fmt.Sprintf("250 2.1.5 <%s>", normalizeEnvelopeAddress(addr)))
}

// cmdExpn is disabled (no mailing-list expansion in Beaver).
func (s *session) cmdExpn(arg string) error {
	_ = arg
	return s.writef("252 2.5.1 EXPN is disabled")
}
