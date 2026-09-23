// Package app wires config, storage, and process lifecycle for beaver serve.
package app

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/httpapi"
	"github.com/BeaverMail/beaver/internal/imap"
	beaverlog "github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/mailauth"
	"github.com/BeaverMail/beaver/internal/pluginhost"
	"github.com/BeaverMail/beaver/internal/pluginhost/daemon"
	"github.com/BeaverMail/beaver/internal/servicestatus"
	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/openstore"
	"github.com/BeaverMail/beaver/internal/tlsload"
	"github.com/BeaverMail/beaver/internal/webui"
)

// App holds runtime resources opened by beaver serve.
type App struct {
	log     *slog.Logger
	cfg     *config.Config
	store   storage.Store
	blobs   *blob.FS
	dir     *directory.Local
	inbox   *mail.Inbox
	queue   *mail.Queue
	smtp    *smtp.Server
	imap    *imap.Server
	http    *httpapi.Server
	daemon  *daemon.Manager
	status  *servicestatus.Registry
	logFile *beaverlog.RotatingFile
}

// Open connects storage using cfg and returns an App.
func Open(ctx context.Context, log *slog.Logger, cfg *config.Config) (*App, error) {
	store, err := openstore.OpenConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	blobs := blob.NewFS(cfg.BlobDir())
	dir := directory.NewLocal(store)
	inbox := mail.NewInbox(store, blobs)
	inbox.SetQuotaDefaults(mail.QuotaDefaults{
		StorageBytes: cfg.Quota.DefaultStorageBytes,
		Messages:     cfg.Quota.DefaultMessages,
	})
	queue := mail.NewQueue(store, blobs)

	certs, err := openTLSCerts(cfg)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	tlsOpts := tlsOptions(cfg, certs)
	authGate := cfg.NewAuthGate()
	sendGate := cfg.NewSendGate()
	smtpMaxConn, smtpReadTO, err := cfg.SMTPListenerLimits()
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("smtp listener limits: %w", err)
	}
	imapMaxConn, imapReadTO, err := cfg.IMAPListenerLimits()
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("imap listener limits: %w", err)
	}
	var mailAuth *mailauth.Verifier
	if cfg.MailAuth.Enabled {
		mailAuth = mailauth.New(mailauth.Config{
			Enabled:      true,
			DNSTimeout:   cfg.MailAuthDNSTimeout(),
			SPFEnabled:   cfg.MailAuth.SPF.Enabled,
			DKIMEnabled:  cfg.MailAuth.DKIM.Enabled,
			DMARCEnabled: cfg.MailAuth.DMARC.Enabled,
			ARCEnabled:   cfg.MailAuth.ARC.Enabled,
		})
	}
	greylistEnabled, greylistMinDelay, greylistMaxAge := cfg.SMTPGreylist()
	greylist := smtp.NewGreylist(store, smtp.GreylistConfig{
		Enabled:  greylistEnabled,
		MinDelay: greylistMinDelay,
		MaxAge:   greylistMaxAge,
	})
	asnEnabled, asnTimeout, asnCacheTTL, asnCacheMissTTL, asnZoneV4, asnZoneV6, asnCacheMax := cfg.SMTPASNLookup()
	asnLookup := smtp.NewASNLookup(smtp.ASNLookupConfig{
		Enabled:         asnEnabled,
		Timeout:         asnTimeout,
		ZoneIPv4:        asnZoneV4,
		ZoneIPv6:        asnZoneV6,
		CacheTTL:        asnCacheTTL,
		CacheMissTTL:    asnCacheMissTTL,
		CacheMaxEntries: asnCacheMax,
	})

	status := servicestatus.New()
	seedListenerStatus(status, cfg, certs != nil)

	var logFile *beaverlog.RotatingFile
	logPath := cfg.LogFilePath()
	if logPath != "" {
		var openErr error
		logFile, openErr = beaverlog.OpenFile(logPath, beaverlog.FileOptions{
			MaxBytes: cfg.LogFileMaxBytes(),
			Keep:     cfg.LogFileKeep(),
		})
		if openErr != nil {
			_ = store.Close()
			return nil, fmt.Errorf("open log file: %w", openErr)
		}
		log = beaverlog.WithFile(log, logFile)
	}

	var httpSrv *httpapi.Server
	if cfg.HTTPEnabled() {
		var uiFS fs.FS
		if assets, ok := webui.Assets(); ok {
			uiFS = assets
		}
		httpSrv, err = httpapi.New(httpapi.Options{
			Listen:      cfg.HTTPListen(),
			Dir:         dir,
			Log:         log,
			AuthKey:     cfg.Secrets.AuthKey,
			Certs:       certs,
			AuthGate:    authGate,
			Blobs:       blobs,
			Queue:       queue,
			Remote:      ptrRemote(remoteConfigFrom(cfg)),
			Status:      status,
			LogFile:     logPath,
			LogFileKeep: cfg.LogFileKeep(),
			UI:          uiFS,
		})
		if err != nil {
			if logFile != nil {
				_ = logFile.Close()
			}
			_ = store.Close()
			return nil, fmt.Errorf("http api: %w", err)
		}
	}

	return &App{
		log:   log,
		cfg:   cfg,
		store: store,
		blobs: blobs,
		dir:   dir,
		inbox: inbox,
		queue: queue,
		smtp: smtp.NewServer(log, cfg.SMTPListen(), dir, inbox, queue, cfg.SMTPSubmissionListen(), cfg.SMTPSubmissionTLSListen(), smtp.Options{
			Certs:           certs,
			TLSRequired:     tlsOpts.required,
			VRFYEnabled:     cfg.SMTPVRFYEnabled(),
			DataLimits:      smtp.DataLimits{MaxMessageBytes: cfg.SMTPMaxMessageBytes()},
			Filter:          smtp.NopFilter{},
			FilterTmpDir:    filepath.Join(cfg.DataDir, "tmp"),
			FilterTimeoutMs: int(cfg.PluginsSMTPFilterTimeout() / time.Millisecond),
			MailAuth:        mailAuth,
			AuthGate:        authGate,
			Greylist:        greylist,
			ASNLookup:       asnLookup,
			SendGate:        sendGate,
			MaxConnections:  smtpMaxConn,
			ReadTimeout:     smtpReadTO,
			Status:          status,
		}),
		imap: imap.NewServer(log, cfg.IMAPListen(), dir, inbox, imap.Options{
			Certs:          certs,
			TLSListen:      tlsOpts.imapTLSListen,
			TLSRequired:    tlsOpts.required,
			AuthGate:       authGate,
			MaxConnections: imapMaxConn,
			ReadTimeout:    imapReadTO,
			Status:         status,
		}),
		http:    httpSrv,
		status:  status,
		logFile: logFile,
	}, nil
}

func seedListenerStatus(reg *servicestatus.Registry, cfg *config.Config, hasCerts bool) {
	if addr := cfg.SMTPListen(); addr != "" {
		reg.Set(servicestatus.Entry{ID: "smtp_inbound", Name: "SMTP inbound", Listen: addr, State: servicestatus.StateDown})
	}
	if addr := cfg.SMTPSubmissionListen(); addr != "" {
		reg.Set(servicestatus.Entry{ID: "smtp_submission", Name: "SMTP submission", Listen: addr, State: servicestatus.StateDown})
	}
	if addr := cfg.SMTPSubmissionTLSListen(); addr != "" {
		st := servicestatus.StateDown
		errMsg := ""
		if !hasCerts {
			st = servicestatus.StateDisabled
			errMsg = "tls not configured"
		}
		reg.Set(servicestatus.Entry{ID: "smtp_submission_tls", Name: "SMTP submission TLS", Listen: addr, State: st, Error: errMsg})
	}
	if addr := cfg.IMAPListen(); addr != "" {
		reg.Set(servicestatus.Entry{ID: "imap", Name: "IMAP", Listen: addr, State: servicestatus.StateDown})
	}
	if addr := cfg.IMAPTLSListen(); addr != "" {
		st := servicestatus.StateDown
		errMsg := ""
		if !hasCerts {
			st = servicestatus.StateDisabled
			errMsg = "tls not configured"
		}
		reg.Set(servicestatus.Entry{ID: "imap_tls", Name: "IMAP TLS", Listen: addr, State: st, Error: errMsg})
	}
	if cfg.HTTPEnabled() {
		reg.Set(servicestatus.Entry{ID: "http", Name: "HTTP admin", Listen: cfg.HTTPListen(), State: servicestatus.StateDown})
	}
	reg.Set(servicestatus.Entry{ID: "queue_worker", Name: "Queue worker", State: servicestatus.StateDown})
	if len(cfg.ACMEHosts()) > 0 {
		st := servicestatus.StateDown
		errMsg := "certs not loaded"
		if hasCerts {
			st = servicestatus.StateUp
			errMsg = ""
		}
		reg.Set(servicestatus.Entry{ID: "acme", Name: "ACME", State: st, Error: errMsg})
	}
}

type tlsRuntime struct {
	required      bool
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

	errCh := make(chan error, 3)

	dm := daemon.NewManager(a.log, daemon.Config{
		SocketDir:      a.cfg.PluginsSMTPSocketDir(),
		DataDir:        a.cfg.DataDir,
		Timeout:        a.cfg.PluginsSMTPFilterTimeout(),
		FailOpen:       a.cfg.PluginsSMTPTimeoutFailOpen(),
		RestartBackoff: a.cfg.PluginsSMTPRestartBackoff(),
	})
	if reg, err := pluginhost.LoadRegistry(pluginhost.PluginsDirFromConfigPath(a.cfg.ConfigPath())); err != nil {
		return fmt.Errorf("plugins: %w", err)
	} else if err := dm.LoadFromRegistry(reg); err != nil {
		return fmt.Errorf("plugins: %w", err)
	} else if err := dm.Start(ctx); err != nil {
		return fmt.Errorf("plugins: %w", err)
	} else {
		a.daemon = dm
		a.smtp.SetFilter(dm.Filter())
		if a.status != nil {
			st := servicestatus.StateUp
			detail := ""
			if len(reg.DaemonEntries()) == 0 {
				st = servicestatus.StateDisabled
				detail = "no daemon plugins"
			}
			a.status.Set(servicestatus.Entry{ID: "antispam", Name: "Antispam plugins", State: st, Error: detail})
		}
	}

	go func() { errCh <- a.smtp.Serve(ctx) }()
	go func() { errCh <- a.imap.Serve(ctx) }()
	if a.http != nil {
		go func() { errCh <- a.http.Serve(ctx) }()
	}
	signer, err := a.cfg.NewDKIMSigner()
	if err != nil {
		return fmt.Errorf("dkim sign: %w", err)
	}
	if a.status != nil {
		a.status.Set(servicestatus.Entry{ID: "queue_worker", Name: "Queue worker", State: servicestatus.StateUp})
	}
	go mail.NewWorker(a.log, a.queue, a.inbox, a.dir, newRemoteDeliverer(a.cfg), signer, policy).Run(ctx)

	_, _, tlsOn := a.cfg.TLSPair()
	storeInfo := a.cfg.StorePath()
	if a.cfg.StoreDriver() == config.StoreDriverMySQL {
		storeInfo = "mysql"
	}
	a.log.Info("beaver ready",
		"data_dir", a.cfg.DataDir,
		"store_driver", a.cfg.StoreDriver(),
		"store", storeInfo,
		"blobs", a.cfg.BlobDir(),
		"smtp", a.cfg.SMTPListen(),
		"smtp_submission", a.cfg.SMTPSubmissionListen(),
		"smtp_submission_tls", a.cfg.SMTPSubmissionTLSListen(),
		"tls_acme_hosts", a.cfg.ACMEHosts(),
		"imap", a.cfg.IMAPListen(),
		"imap_tls", a.cfg.IMAPTLSListen(),
		"http", a.cfg.HTTPListen(),
		"http_enabled", a.cfg.HTTPEnabled(),
		"web_ui", webui.Enabled(),
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

func ptrRemote(cfg smtp.RemoteConfig) *smtp.RemoteConfig {
	return &cfg
}

// Close releases storage handles and stops plugin daemons.
func (a *App) Close() error {
	if a.daemon != nil {
		_ = a.daemon.Stop()
		a.daemon = nil
	}
	if a.logFile != nil {
		_ = a.logFile.Close()
		a.logFile = nil
	}
	if a.store != nil {
		return a.store.Close()
	}
	return nil
}
