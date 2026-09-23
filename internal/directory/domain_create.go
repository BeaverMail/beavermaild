package directory

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/BeaverMail/beaver/internal/dkimout"
	"github.com/BeaverMail/beaver/internal/storage"
)

// DomainCreateOpts holds optional hosting settings when registering a domain.
type DomainCreateOpts struct {
	CatchAllLocal   string
	MailHostname    string
	SSLMode         string // none|custom|acme
	CertPEM         string // custom SSL
	KeyPEM          string
	DKIMEnabled     bool
	AntiSpam        bool
	SendMaxMessages int
	SendWindow      string
	StorageBytes    uint64
	Messages        uint32
	RelayHost       string
	RelayUser       string
	RelayPassword   string
	RelayStartTLS   bool
}

// DomainStats is list-view aggregates for one domain.
type DomainStats struct {
	AccountCount int
	StorageUsed  uint64
	SSLActive    bool
	DKIMActive   bool
	AntiSpam     bool
}

// CreateDomainWithOpts registers a domain and applies hosting settings/assets.
func (d *Local) CreateDomainWithOpts(ctx context.Context, tenantID uint32, name string, opts DomainCreateOpts) (storage.Domain, error) {
	dom, err := d.CreateDomain(ctx, tenantID, name)
	if err != nil {
		return storage.Domain{}, err
	}
	if err := d.applyDomainOpts(ctx, &dom, opts, false); err != nil {
		_, _ = d.DeleteDomain(ctx, dom.Name, nil)
		if d.dataDir != "" {
			_ = os.RemoveAll(DomainDir(d.dataDir, dom.ID))
		}
		return storage.Domain{}, err
	}
	return dom, nil
}

// UpdateDomainWithOpts updates hosting settings for an existing domain (name/tenant unchanged).
func (d *Local) UpdateDomainWithOpts(ctx context.Context, name string, opts DomainCreateOpts) (storage.Domain, error) {
	dom, err := d.LookupDomain(ctx, name)
	if err != nil {
		return storage.Domain{}, err
	}
	if err := d.applyDomainOpts(ctx, &dom, opts, true); err != nil {
		return storage.Domain{}, err
	}
	return dom, nil
}

func (d *Local) applyDomainOpts(ctx context.Context, dom *storage.Domain, opts DomainCreateOpts, update bool) error {
	mode := strings.ToLower(strings.TrimSpace(opts.SSLMode))
	if mode == "" {
		mode = storage.DomainSSLNone
	}
	switch mode {
	case storage.DomainSSLNone, storage.DomainSSLCustom, storage.DomainSSLACME:
	default:
		return fmt.Errorf("directory: invalid ssl_mode %q", opts.SSLMode)
	}

	prevHost := dom.MailHostname
	mailHost := normalizeDomain(opts.MailHostname)
	if mode != storage.DomainSSLNone && mailHost == "" {
		return fmt.Errorf("directory: mail_hostname required when ssl_mode is %s", mode)
	}
	if update {
		dom.CatchAllLocal = normalizeLocalPart(opts.CatchAllLocal)
	} else if catch := normalizeLocalPart(opts.CatchAllLocal); catch != "" {
		dom.CatchAllLocal = catch
	}
	dom.MailHostname = mailHost
	dom.SSLMode = mode
	dom.AntiSpam = opts.AntiSpam
	dom.SendMaxMessages = opts.SendMaxMessages
	dom.SendWindow = strings.TrimSpace(opts.SendWindow)
	dom.StorageBytes = opts.StorageBytes
	dom.Messages = opts.Messages
	dom.RelayHost = strings.TrimSpace(opts.RelayHost)
	dom.RelayUser = strings.TrimSpace(opts.RelayUser)
	dom.RelayStartTLS = opts.RelayStartTLS
	if !update || opts.RelayPassword != "" || dom.RelayHost == "" {
		dom.RelayPassword = opts.RelayPassword
	}
	dom.DKIMEnabled = opts.DKIMEnabled

	if d.dataDir == "" && (mode == storage.DomainSSLCustom || opts.DKIMEnabled) {
		return fmt.Errorf("directory: data_dir required for TLS/DKIM assets")
	}
	if mode == storage.DomainSSLCustom {
		hasPEM := strings.TrimSpace(opts.CertPEM) != "" && strings.TrimSpace(opts.KeyPEM) != ""
		if hasPEM {
			if err := EnsureDomainDir(d.dataDir, dom.ID); err != nil {
				return err
			}
			if err := WriteDomainFile(DomainTLSCertPath(d.dataDir, dom.ID), []byte(opts.CertPEM)); err != nil {
				return fmt.Errorf("directory: write tls cert: %w", err)
			}
			if err := WriteDomainFile(DomainTLSKeyPath(d.dataDir, dom.ID), []byte(opts.KeyPEM)); err != nil {
				return fmt.Errorf("directory: write tls key: %w", err)
			}
		} else if !update || !DomainTLSFilesPresent(d.dataDir, dom.ID) {
			return fmt.Errorf("directory: cert_pem and key_pem required for custom SSL")
		}
	}
	if opts.DKIMEnabled {
		if dom.DKIMSelector == "" {
			dom.DKIMSelector = "beaver"
		}
		path := DomainDKIMKeyPath(d.dataDir, dom.ID)
		if !DomainDKIMKeyPresent(d.dataDir, dom.ID) {
			if err := EnsureDomainDir(d.dataDir, dom.ID); err != nil {
				return err
			}
			if err := dkimout.GenerateKey(path); err != nil {
				return fmt.Errorf("directory: dkim key: %w", err)
			}
		}
	} else if !update {
		dom.DKIMSelector = ""
	}

	batch := storage.NewBatch().WithAccount(systemAccountID)
	if err := d.putDomain(batch, *dom); err != nil {
		return err
	}
	if update && prevHost != "" && prevHost != mailHost {
		_ = batch.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, []byte("mhost/"+prevHost)))
	}
	if mailHost != "" {
		if err := d.putLookup(batch, "mhost", mailHost, dom.ID); err != nil {
			return err
		}
	} else if update && prevHost != "" {
		_ = batch.Delete(storage.SubspaceLookup, storage.BatchSuffix(0, 0, []byte("mhost/"+prevHost)))
	}
	return d.store.Commit(ctx, batch)
}

// LookupDomainByMailHost finds a domain by TLS/mail hostname.
func (d *Local) LookupDomainByMailHost(ctx context.Context, host string) (storage.Domain, error) {
	host = normalizeDomain(host)
	if host == "" {
		return storage.Domain{}, fmt.Errorf("directory: empty mail hostname")
	}
	id, err := d.lookupID(ctx, "mhost", host)
	if err != nil {
		return storage.Domain{}, err
	}
	return d.getDomain(ctx, id)
}

// BuildDomainStats returns list aggregates for one domain.
func (d *Local) BuildDomainStats(dom storage.Domain, accountCount int, storageUsed uint64) DomainStats {
	st := DomainStats{
		AccountCount: accountCount,
		StorageUsed:  storageUsed,
		AntiSpam:     dom.AntiSpam,
	}
	switch dom.SSLMode {
	case storage.DomainSSLCustom:
		st.SSLActive = d.dataDir != "" && DomainTLSFilesPresent(d.dataDir, dom.ID)
	case storage.DomainSSLACME:
		st.SSLActive = strings.TrimSpace(dom.MailHostname) != ""
	}
	st.DKIMActive = dom.DKIMEnabled && dom.DKIMSelector != "" && d.dataDir != "" && DomainDKIMKeyPresent(d.dataDir, dom.ID)
	return st
}

// DKIMDNSRecord returns the TXT name/value for publishing when DKIM is enabled.
func (d *Local) DKIMDNSRecord(dom storage.Domain) (name, value string, err error) {
	if !dom.DKIMEnabled || dom.DKIMSelector == "" || d.dataDir == "" {
		return "", "", nil
	}
	pub, err := dkimout.PublicKeyDNS(DomainDKIMKeyPath(d.dataDir, dom.ID))
	if err != nil {
		return "", "", err
	}
	return dom.DKIMSelector + "._domainkey." + dom.Name, pub, nil
}

// ResolveCatchAll maps unknown RCPT on a known domain to the catch-all mailbox.
func (d *Local) ResolveCatchAll(ctx context.Context, domainName string) (storage.Account, storage.Domain, error) {
	dom, err := d.LookupDomain(ctx, domainName)
	if err != nil {
		return storage.Account{}, storage.Domain{}, err
	}
	if dom.CatchAllLocal == "" {
		return storage.Account{}, storage.Domain{}, ErrNotFound
	}
	return d.lookupAccount(ctx, dom.CatchAllLocal+"@"+dom.Name)
}

// DomainQuotaForAccount returns hosting quota overrides for the account's domain.
// ok is false when the domain uses process-wide defaults (both fields zero).
func (d *Local) DomainQuotaForAccount(ctx context.Context, accountID uint32) (storageBytes uint64, messages uint32, ok bool) {
	acc, err := d.getAccount(ctx, accountID)
	if err != nil {
		return 0, 0, false
	}
	dom, err := d.getDomain(ctx, acc.DomainID)
	if err != nil {
		return 0, 0, false
	}
	if dom.StorageBytes == 0 && dom.Messages == 0 {
		return 0, 0, false
	}
	return dom.StorageBytes, dom.Messages, true
}
