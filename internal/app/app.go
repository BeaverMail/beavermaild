// Package app wires config, storage, and process lifecycle for beaver serve.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/imap"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
	"github.com/BeaverMail/beaver/internal/tlsload"
)

// App holds runtime resources opened by beaver serve.
type App struct {
	log   *slog.Logger
	cfg   *config.Config
	store storage.Store
	blobs *blob.FS
	dir   *directory.Local
	inbox *mail.Inbox
	queue *mail.Queue
	smtp  *smtp.Server
	imap  *imap.Server
}

// Open connects storage using cfg and returns an App.
func Open(ctx context.Context, log *slog.Logger, cfg *config.Config) (*App, error) {
	store, err := sqlite.Open(ctx, cfg.StorePath())
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	blobs := blob.NewFS(cfg.BlobDir())
	dir := directory.NewLocal(store)
	inbox := mail.NewInbox(store, blobs)
	queue := mail.NewQueue(store, blobs)

	certs, err := openTLSCerts(cfg)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	tlsOpts := tlsOptions(cfg, certs)

	return &App{
		log:   log,
		cfg:   cfg,
		store: store,
		blobs: blobs,
		dir:   dir,
		inbox: inbox,
		queue: queue,
		smtp: smtp.NewServer(log, cfg.SMTPListen(), dir, inbox, queue, cfg.SMTPSubmissionListen(), cfg.SMTPSubmissionTLSListen(), smtp.Options{
			Certs:       certs,
			TLSRequired: tlsOpts.required,
		}),
		imap: imap.NewServer(log, cfg.IMAPListen(), dir, inbox, imap.Options{
			Certs:       certs,
			TLSListen:   tlsOpts.imapTLSListen,
			TLSRequired: tlsOpts.required,
		}),
	}, nil
}

type tlsRuntime struct {
	required     bool
	imapTLSListen string
}

func tlsOptions(cfg *config.Config, certs *tlsload.Certs) tlsRuntime {
	r := tlsRuntime{required: cfg.TLSRequired()}
	if certs != nil && cfg.IMAPTLSListen() != "" {
		r.imapTLSListen = cfg.IMAPTLSListen()
	}
	return r
}

func openTLSCerts(cfg *config.Config) (*tlsload.Certs, error) {
	if certFile, keyFile, ok := cfg.TLSPair(); ok {
		certs, err := tlsload.Load(certFile, keyFile, cfg.TLS.MinVersion)
		if err != nil {
			return nil, fmt.Errorf("load tls: %w", err)
		}
		return certs, nil
	}
	if hosts := cfg.ACMEHosts(); len(hosts) > 0 {
		certs, err := tlsload.LoadACME(cfg.ACMECacheDir(), hosts, cfg.TLS.MinVersion)
		if err != nil {
			return nil, fmt.Errorf("load acme: %w", err)
		}
		return certs, nil
	}
	return nil, nil
}

// Store returns the KV store.
func (a *App) Store() storage.Store { return a.store }

// Blobs returns the filesystem blob store.
func (a *App) Blobs() *blob.FS { return a.blobs }

// Run blocks until ctx is canceled, then closes resources.
func (a *App) Run(ctx context.Context) error {
	qt, err := a.cfg.QueueTimings()
	if err != nil {
		return fmt.Errorf("queue policy: %w", err)
	}
	policy := mail.QueuePolicy{
		RetryIntervals: qt.RetryIntervals,
		MaxLifetime:    qt.MaxLifetime,
		RunDelay:       qt.RunDelay,
	}

	errCh := make(chan error, 2)
	go func() { errCh <- a.smtp.Serve(ctx) }()
	go func() { errCh <- a.imap.Serve(ctx) }()
	go mail.NewWorker(a.log, a.queue, a.inbox, a.dir, remoteDeliverer{relay: a.cfg.SMTPRelay()}, policy).Run(ctx)

	_, _, tlsOn := a.cfg.TLSPair()
	a.log.Info("beaver ready",
		"data_dir", a.cfg.DataDir,
		"store", a.cfg.StorePath(),
		"blobs", a.cfg.BlobDir(),
		"smtp", a.cfg.SMTPListen(),
		"smtp_submission", a.cfg.SMTPSubmissionListen(),
		"smtp_submission_tls", a.cfg.SMTPSubmissionTLSListen(),
		"tls_acme_hosts", a.cfg.ACMEHosts(),
		"imap", a.cfg.IMAPListen(),
		"imap_tls", a.cfg.IMAPTLSListen(),
		"smtp_relay", a.cfg.SMTPRelay(),
		"tls", tlsOn,
	)

	select {
	case <-ctx.Done():
		a.log.Info("shutting down")
		return a.Close()
	case err := <-errCh:
		if err != nil {
			a.log.Error("server stopped", slog.Any("err", err))
		}
		return a.Close()
	}
}

// Close releases storage handles.
func (a *App) Close() error {
	if a.store != nil {
		return a.store.Close()
	}
	return nil
}
