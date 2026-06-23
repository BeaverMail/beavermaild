package app

import (
	"context"

	"github.com/BeaverMail/beaver/internal/smtp"
)

// remoteDeliverer adapts smtp.DeliverRemote for the mail queue worker.
type remoteDeliverer struct {
	relay string
}

func (d remoteDeliverer) DeliverRemote(ctx context.Context, mailFrom, rcptTo string, data []byte) error {
	return smtp.DeliverRemote(ctx, d.relay, mailFrom, rcptTo, data)
}
