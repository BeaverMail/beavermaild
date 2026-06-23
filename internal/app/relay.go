package app

import (
	"context"

	"github.com/BeaverMail/beaver/internal/smtp"
)

// relaySender adapts smtp.Send for the mail queue worker.
type relaySender struct{}

func (relaySender) Send(ctx context.Context, addr, mailFrom, rcptTo string, data []byte) error {
	return smtp.Send(ctx, addr, mailFrom, rcptTo, data)
}
