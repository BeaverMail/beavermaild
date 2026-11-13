package app

import (
	"context"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/config"
	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
)

// remoteDeliverer adapts smtp.DeliverRemote for the mail queue worker.
type remoteDeliverer struct {
	base smtp.RemoteConfig
	dir  *directory.Local
}

// remoteConfigFrom builds the outbound delivery settings. Build it once: it owns the MTA-STS policy
// cache and its file.
func remoteConfigFrom(c *config.Config) smtp.RemoteConfig {
	tlsSkip := c.SMTPOutboundTLSInsecureSkip()
	helo := c.SMTPHostname()
	return smtp.RemoteConfig{
		Relay: c.SMTPRelay(),
		RelayOptions: smtp.ClientOptions{
			STARTTLS:              c.SMTPRelayStartTLS(),
			TLSInsecureSkipVerify: tlsSkip,
			User:                  c.SMTPRelayUser(),
			Password:              c.SMTPRelayPassword(),
			HeloName:              helo,
			AllowPlainAuth:        smtp.IsLoopbackAddr(c.SMTPRelay()),
		},
		MXOptions: smtp.ClientOptions{HeloName: helo, RejectPrivate: !c.SMTPOutboundAllowPrivate()},
		MTASTS:    c.NewMTASTSResolver(),
		TLSPolicy: c.SMTP.TLSPolicy,
	}
}

func (d remoteDeliverer) DeliverRemote(ctx context.Context, mailFrom, rcptTo string, data []byte, dsn *mail.RelayDSN) (string, error) {
	cfg := d.base
	cfg.RelayOptions.DSN, cfg.MXOptions.DSN = dsn, dsn
	if d.dir != nil {
		if at := strings.LastIndex(mailFrom, "@"); at > 0 && at < len(mailFrom)-1 {
			if dom, err := d.dir.LookupDomain(ctx, mailFrom[at+1:]); err == nil && strings.TrimSpace(dom.RelayHost) != "" {
				cfg.Relay = strings.TrimSpace(dom.RelayHost)
				cfg.RelayOptions.User = dom.RelayUser
				cfg.RelayOptions.Password = dom.RelayPassword
				cfg.RelayOptions.STARTTLS = dom.RelayStartTLS
				cfg.RelayOptions.AllowPlainAuth = smtp.IsLoopbackAddr(cfg.Relay)
			}
		}
	}
	return smtp.DeliverRemote(ctx, cfg, mailFrom, rcptTo, data)
}
