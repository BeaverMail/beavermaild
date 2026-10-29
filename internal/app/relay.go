package app

import (
	"context"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/config"
	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/smtp"
)

// remoteDeliverer adapts smtp.DeliverRemote for the mail queue worker.
type remoteDeliverer struct {
	base smtp.RemoteConfig
	dir  *directory.Local
}

func newRemoteDeliverer(c *config.Config, dir *directory.Local) remoteDeliverer {
	return remoteDeliverer{base: remoteConfigFrom(c), dir: dir}
}

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
		},
		MXOptions: smtp.ClientOptions{TLSInsecureSkipVerify: tlsSkip, HeloName: helo},
		MTASTS:    c.NewMTASTSResolver(),
	}
}

func (d remoteDeliverer) DeliverRemote(ctx context.Context, mailFrom, rcptTo string, data []byte) (string, error) {
	cfg := d.base
	if d.dir != nil {
		if at := strings.LastIndex(mailFrom, "@"); at > 0 && at < len(mailFrom)-1 {
			if dom, err := d.dir.LookupDomain(ctx, mailFrom[at+1:]); err == nil && strings.TrimSpace(dom.RelayHost) != "" {
				cfg.Relay = strings.TrimSpace(dom.RelayHost)
				cfg.RelayOptions.User = dom.RelayUser
				cfg.RelayOptions.Password = dom.RelayPassword
				cfg.RelayOptions.STARTTLS = dom.RelayStartTLS
			}
		}
	}
	return smtp.DeliverRemote(ctx, cfg, mailFrom, rcptTo, data)
}
