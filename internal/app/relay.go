package app

import (
	"context"

	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/smtp"
)

// remoteDeliverer adapts smtp.DeliverRemote for the mail queue worker.
type remoteDeliverer struct {
	cfg smtp.RemoteConfig
}

func newRemoteDeliverer(c *config.Config) remoteDeliverer {
	return remoteDeliverer{cfg: remoteConfigFrom(c)}
}

func remoteConfigFrom(c *config.Config) smtp.RemoteConfig {
	tlsSkip := c.SMTPOutboundTLSInsecureSkip()
	return smtp.RemoteConfig{
		Relay: c.SMTPRelay(),
		RelayOptions: smtp.ClientOptions{
			STARTTLS:              c.SMTPRelayStartTLS(),
			TLSInsecureSkipVerify: tlsSkip,
			User:                  c.SMTPRelayUser(),
			Password:              c.SMTPRelayPassword(),
		},
		MXOptions: smtp.ClientOptions{TLSInsecureSkipVerify: tlsSkip},
		MTASTS:    c.NewMTASTSResolver(),
	}
}

func (d remoteDeliverer) DeliverRemote(ctx context.Context, mailFrom, rcptTo string, data []byte) error {
	return smtp.DeliverRemote(ctx, d.cfg, mailFrom, rcptTo, data)
}
