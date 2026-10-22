// First-install setup and directory write handlers for /api/v1.
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	beaverlog "github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/servicestatus"
	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/storage"
)

// handleSetupStatus reports whether the greenfield wizard is still available.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	needed, err := s.dir.NeedsSetup(r.Context())
	if err != nil {
		s.log.Error("http setup status", "err", err)
		writeError(w, http.StatusInternalServerError, "setup status failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needed": needed})
}

type setupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// handleSetupBootstrap creates the first admin when the directory is empty.
func (s *Server) handleSetupBootstrap(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.authGate.AllowAuth(ip, "") {
		writeError(w, http.StatusTooManyRequests, "too many auth attempts")
		return
	}
	var req setupRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || strings.TrimSpace(req.Password) == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}
	_, err := s.dir.BootstrapAdmin(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, directory.ErrSetupComplete) {
			writeError(w, http.StatusConflict, "setup already complete")
			return
		}
		s.authGate.RecordAuthFailure(ip, req.Email)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := s.dir.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		s.log.Error("http setup authenticate", "err", err)
		writeError(w, http.StatusInternalServerError, "setup session failed")
		return
	}
	s.authGate.RecordAuthSuccess(ip, req.Email)
	s.writeSession(w, p)
}

type createDomainRequest struct {
	Name            string `json:"name"`
	TenantID        uint32 `json:"tenant_id"`
	CatchAll        string `json:"catch_all"`
	MailHostname    string `json:"mail_hostname"`
	SSLMode         string `json:"ssl_mode"`
	CertPEM         string `json:"cert_pem"`
	KeyPEM          string `json:"key_pem"`
	DKIMEnabled     bool   `json:"dkim_enabled"`
	AntiSpam        bool   `json:"antispam"`
	SendMaxMessages int    `json:"send_max_messages"`
	SendWindow      string `json:"send_window"`
	StorageBytes    uint64 `json:"storage_bytes"`
	MessagesQuota   uint32 `json:"messages_quota"`
	RelayHost       string `json:"relay_host"`
	RelayUser       string `json:"relay_user"`
	RelayPassword   string `json:"relay_password"`
	RelayStartTLS   bool   `json:"relay_starttls"`
}

// handleCreateDomain creates a domain in the caller's tenant scope with optional hosting settings.
func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req createDomainRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if strings.TrimSpace(req.MailHostname) == "" {
		writeError(w, http.StatusBadRequest, "mail_hostname required")
		return
	}
	tenantID := req.TenantID
	switch p.Role {
	case directory.RoleAdmin:
		if tenantID == 0 {
			tenantID = directory.DefaultTenantID
		}
	case directory.RoleTenantAdmin:
		tenantID = p.TenantID
	default:
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !canManageDomain(p, tenantID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	opts := directory.DomainCreateOpts{
		CatchAllLocal:   req.CatchAll,
		MailHostname:    req.MailHostname,
		SSLMode:         req.SSLMode,
		CertPEM:         req.CertPEM,
		KeyPEM:          req.KeyPEM,
		DKIMEnabled:     req.DKIMEnabled,
		AntiSpam:        req.AntiSpam,
		SendMaxMessages: req.SendMaxMessages,
		SendWindow:      req.SendWindow,
		StorageBytes:    req.StorageBytes,
		Messages:        req.MessagesQuota,
		RelayHost:       req.RelayHost,
		RelayUser:       req.RelayUser,
		RelayPassword:   req.RelayPassword,
		RelayStartTLS:   req.RelayStartTLS,
	}
	dom, err := s.dir.CreateDomainWithOpts(r.Context(), tenantID, req.Name, opts)
	if err != nil {
		if errors.Is(err, directory.ErrExists) {
			writeError(w, http.StatusConflict, "domain already exists")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.syncDomainRuntime(dom)
	writeJSON(w, http.StatusCreated, s.domainToDTO(r.Context(), dom))
}

type patchDomainRequest struct {
	CatchAll        string `json:"catch_all"`
	MailHostname    string `json:"mail_hostname"`
	SSLMode         string `json:"ssl_mode"`
	CertPEM         string `json:"cert_pem"`
	KeyPEM          string `json:"key_pem"`
	DKIMEnabled     bool   `json:"dkim_enabled"`
	AntiSpam        bool   `json:"antispam"`
	SendMaxMessages int    `json:"send_max_messages"`
	SendWindow      string `json:"send_window"`
	StorageBytes    uint64 `json:"storage_bytes"`
	MessagesQuota   uint32 `json:"messages_quota"`
	RelayHost       string `json:"relay_host"`
	RelayUser       string `json:"relay_user"`
	RelayPassword   string `json:"relay_password"`
	RelayStartTLS   bool   `json:"relay_starttls"`
}

// handleGetDomain returns one domain with hosting stats when in scope.
func (s *Server) handleGetDomain(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	domainName := r.PathValue("domain")
	dom, err := s.dir.LookupDomain(r.Context(), domainName)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup domain failed")
		return
	}
	if !canListAllDomains(p) && !canSeeDomainTenant(p, dom.TenantID) &&
		!(p.Role == directory.RoleUser && strings.EqualFold(p.DomainName, dom.Name)) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, s.domainToDTO(r.Context(), dom))
}

// handlePatchDomain updates hosting settings for an existing domain.
func (s *Server) handlePatchDomain(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	domainName := r.PathValue("domain")
	dom, err := s.dir.LookupDomain(r.Context(), domainName)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup domain failed")
		return
	}
	if !canManageDomain(p, dom.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req patchDomainRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.MailHostname) == "" {
		writeError(w, http.StatusBadRequest, "mail_hostname required")
		return
	}
	opts := directory.DomainCreateOpts{
		CatchAllLocal:   req.CatchAll,
		MailHostname:    req.MailHostname,
		SSLMode:         req.SSLMode,
		CertPEM:         req.CertPEM,
		KeyPEM:          req.KeyPEM,
		DKIMEnabled:     req.DKIMEnabled,
		AntiSpam:        req.AntiSpam,
		SendMaxMessages: req.SendMaxMessages,
		SendWindow:      req.SendWindow,
		StorageBytes:    req.StorageBytes,
		Messages:        req.MessagesQuota,
		RelayHost:       req.RelayHost,
		RelayUser:       req.RelayUser,
		RelayPassword:   req.RelayPassword,
		RelayStartTLS:   req.RelayStartTLS,
	}
	updated, err := s.dir.UpdateDomainWithOpts(r.Context(), domainName, opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.syncDomainRuntime(updated)
	writeJSON(w, http.StatusOK, s.domainToDTO(r.Context(), updated))
}

func (s *Server) syncDomainRuntime(dom storage.Domain) {
	if s.dkim != nil {
		if dom.DKIMEnabled && dom.DKIMSelector != "" && s.dir.DataDir() != "" {
			_ = s.dkim.LoadDomain(dom.Name, dom.DKIMSelector, directory.DomainDKIMKeyPath(s.dir.DataDir(), dom.ID))
		} else {
			s.dkim.Set(dom.Name, nil)
		}
	}
	if s.domainTLS != nil {
		_ = s.domainTLS.Reload(context.Background())
	}
}

type confirmDomainRequest struct {
	Confirm string `json:"confirm"`
}

// handleDeleteDomain removes a domain after confirm matches the path name.
func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.blobs == nil {
		writeError(w, http.StatusServiceUnavailable, "blob store unavailable")
		return
	}
	domainName := r.PathValue("domain")
	var req confirmDomainRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(req.Confirm), domainName) {
		writeError(w, http.StatusBadRequest, "confirm must match domain name")
		return
	}
	dom, err := s.dir.LookupDomain(r.Context(), domainName)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup domain failed")
		return
	}
	if !canManageDomain(p, dom.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	res, err := s.dir.DeleteDomain(r.Context(), domainName, s.blobs)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		s.log.Error("http delete domain", "err", err)
		writeError(w, http.StatusInternalServerError, "delete domain failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":             res.Domain.Name,
		"accounts_deleted": res.AccountsDeleted,
	})
}

type createAccountRequest struct {
	LocalPart string `json:"local_part"`
	Password  string `json:"password"`
	Role      string `json:"role"`
}

// handleCreateAccount registers an account on a domain.
func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	domainName := r.PathValue("domain")
	dom, err := s.dir.LookupDomain(r.Context(), domainName)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup domain failed")
		return
	}
	if !canManageAccount(p, dom.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req createAccountRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	role := directory.NormalizeRole(req.Role)
	if role == "" || req.Role == "" {
		role = directory.RoleUser
	}
	if !canAssignRole(p, role) {
		writeError(w, http.StatusForbidden, "cannot assign role")
		return
	}
	acc, err := s.dir.CreateAccountRole(r.Context(), dom.ID, req.LocalPart, req.Password, role)
	if err != nil {
		if errors.Is(err, directory.ErrExists) {
			writeError(w, http.StatusConflict, "account already exists")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	email := acc.LocalPart + "@" + dom.Name
	writeJSON(w, http.StatusCreated, accountListDTO{
		ID:        acc.ID,
		LocalPart: acc.LocalPart,
		Email:     email,
		Role:      directory.NormalizeRole(acc.Role),
		TenantID:  acc.TenantID,
		Active:    acc.Active,
	})
}

// handleDeleteAccount removes one account (not the caller's own).
func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.blobs == nil {
		writeError(w, http.StatusServiceUnavailable, "blob store unavailable")
		return
	}
	email := strings.TrimSpace(r.PathValue("email"))
	if strings.EqualFold(email, p.Email()) {
		writeError(w, http.StatusForbidden, "cannot delete own account")
		return
	}
	acc, dom, err := s.dir.ResolveEmail(r.Context(), email)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "account not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "resolve email failed")
		return
	}
	if !canManageAccount(p, acc.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	res, err := s.dir.DeleteAccount(r.Context(), email, s.blobs)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "account not found")
			return
		}
		s.log.Error("http delete account", "err", err)
		writeError(w, http.StatusInternalServerError, "delete account failed")
		return
	}
	_ = dom
	writeJSON(w, http.StatusOK, map[string]any{
		"email":            res.Email,
		"messages_removed": res.MessagesRemoved,
		"blobs_removed":    res.BlobsRemoved,
	})
}

type patchAccountRequest struct {
	Role     *string `json:"role"`
	Password *string `json:"password"`
	Active   *bool   `json:"active"`
	// Mailbox quota overrides (0 = unlimited).
	StorageLimit  *uint64 `json:"storage_limit"`
	MessagesLimit *uint32 `json:"messages_limit"`
}

// handlePatchAccount updates role, password, active flag, and/or mailbox quota limits.
func (s *Server) handlePatchAccount(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	email := strings.TrimSpace(r.PathValue("email"))
	acc, dom, err := s.dir.ResolveEmail(r.Context(), email)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "account not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "resolve email failed")
		return
	}
	if !canManageAccount(p, acc.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req patchAccountRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	setQuota := req.StorageLimit != nil || req.MessagesLimit != nil
	if req.Role == nil && req.Password == nil && req.Active == nil && !setQuota {
		writeError(w, http.StatusBadRequest, "no fields to update")
		return
	}
	if setQuota && s.inbox == nil {
		writeError(w, http.StatusServiceUnavailable, "quota store unavailable")
		return
	}
	self := strings.EqualFold(email, p.Email())
	if self && req.Password != nil {
		writeError(w, http.StatusForbidden, "cannot reset own password via admin api")
		return
	}
	if self && req.Active != nil && !*req.Active {
		writeError(w, http.StatusForbidden, "cannot deactivate own account")
		return
	}
	if req.Role != nil {
		if !canAssignRole(p, *req.Role) {
			writeError(w, http.StatusForbidden, "cannot assign role")
			return
		}
		if err := s.dir.SetAccountRole(r.Context(), acc.ID, *req.Role); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Password != nil {
		if err := s.dir.SetPassword(r.Context(), acc.ID, *req.Password); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Active != nil {
		if err := s.dir.SetActive(r.Context(), acc.ID, *req.Active); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if setQuota {
		if err := s.inbox.SetQuotaLimits(r.Context(), acc.ID, req.StorageLimit, req.MessagesLimit); err != nil {
			s.log.Error("http set quota", "err", err)
			writeError(w, http.StatusInternalServerError, "set quota failed")
			return
		}
	}
	acc, _, err = s.dir.ResolveEmail(r.Context(), email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reload account failed")
		return
	}
	dto := accountListDTO{
		ID:        acc.ID,
		LocalPart: acc.LocalPart,
		Email:     acc.LocalPart + "@" + dom.Name,
		Role:      directory.NormalizeRole(acc.Role),
		TenantID:  acc.TenantID,
		Active:    acc.Active,
	}
	if s.inbox != nil {
		if st, err := s.inbox.QuotaStatus(r.Context(), acc.ID); err == nil {
			dto.StorageUsed, dto.StorageLimit = st.StorageUsed, st.StorageLimit
			dto.MessagesUsed, dto.MessagesLimit = st.MessagesUsed, st.MessagesLimit
		}
	}
	writeJSON(w, http.StatusOK, dto)
}

type createTenantRequest struct {
	Name string `json:"name"`
}

// handleCreateTenant creates a tenant (instance admin only).
func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !canCreateOrDeleteTenant(p) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req createTenantRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	tenant, err := s.dir.CreateTenant(r.Context(), req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, tenantDTO{ID: tenant.ID, Name: tenant.Name})
}

type patchTenantRequest struct {
	Name string `json:"name"`
}

// handlePatchTenant renames a tenant.
func (s *Server) handlePatchTenant(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id, err := parsePathUint32(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	if !canRenameTenant(p, id) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req patchTenantRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.dir.SetTenantName(r.Context(), id, req.Name); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tenant, err := s.dir.GetTenant(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reload tenant failed")
		return
	}
	writeJSON(w, http.StatusOK, tenantDTO{ID: tenant.ID, Name: tenant.Name})
}

type confirmTenantRequest struct {
	Confirm string `json:"confirm"`
}

// handleDeleteTenant cascades domains then removes the tenant (not default).
func (s *Server) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !canCreateOrDeleteTenant(p) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if s.blobs == nil {
		writeError(w, http.StatusServiceUnavailable, "blob store unavailable")
		return
	}
	id, err := parsePathUint32(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	var req confirmTenantRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	tenant, err := s.dir.GetTenant(r.Context(), id)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup tenant failed")
		return
	}
	if strings.TrimSpace(req.Confirm) != tenant.Name {
		writeError(w, http.StatusBadRequest, "confirm must match tenant name")
		return
	}
	res, err := s.dir.DeleteTenant(r.Context(), id, s.blobs)
	if err != nil {
		if errors.Is(err, directory.ErrForbiddenDefault) {
			writeError(w, http.StatusBadRequest, "cannot delete default tenant")
			return
		}
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		s.log.Error("http delete tenant", "err", err)
		writeError(w, http.StatusInternalServerError, "delete tenant failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":               res.Tenant.ID,
		"name":             res.Tenant.Name,
		"domains_deleted":  res.DomainsDeleted,
		"accounts_deleted": res.AccountsDeleted,
	})
}

func parsePathUint32(s string) (uint32, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

type queueRcptDTO struct {
	Address       string `json:"address"`
	Retry         uint32 `json:"retry"`
	Status        string `json:"status"`
	NextDueMS     int64  `json:"next_due_ms"`
	LastAttemptMS int64  `json:"last_attempt_ms"`
	LastDiag      string `json:"last_diag,omitempty"` // last error, or the accepting server's reply once delivered
}

type queueEntryDTO struct {
	ID         uint32         `json:"id"`
	ReturnPath string         `json:"return_path"`
	Size       uint64         `json:"size"`
	Created    uint64         `json:"created"`
	Pending    int            `json:"pending"`
	Held       bool           `json:"held"`
	Recipients []queueRcptDTO `json:"recipients"`
	// CompletedMS is when no recipient was left pending (0 while still pending).
	CompletedMS int64 `json:"completed_ms,omitempty"`
}

// handleListQueue returns outbound queue entries (instance admin only).
// Query ?all=1 includes entries with no pending recipients (default: pending only).
func (s *Server) handleListQueue(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if p.Role != directory.RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if s.queue == nil {
		writeError(w, http.StatusServiceUnavailable, "queue unavailable")
		return
	}
	all := r.URL.Query().Get("all") == "1" || strings.EqualFold(r.URL.Query().Get("all"), "true")
	var (
		entries []mail.QueueEntry
		err     error
	)
	if all {
		entries, err = s.queue.ListAll(r.Context())
	} else {
		entries, err = s.queue.ListPending(r.Context())
	}
	if err != nil {
		s.log.Error("http list queue", "err", err)
		writeError(w, http.StatusInternalServerError, "list queue failed")
		return
	}
	out := make([]queueEntryDTO, 0, len(entries))
	for _, e := range entries {
		rcpts := make([]queueRcptDTO, len(e.Msg.Recipients))
		pending := 0
		for i, rcpt := range e.Msg.Recipients {
			st := mail.RecipientStatus(rcpt)
			if st == "pending" {
				pending++
			}
			rcpts[i] = queueRcptDTO{
				Address:       rcpt.Address,
				Retry:         rcpt.Retry,
				Status:        st,
				NextDueMS:     rcpt.NextDue,
				LastAttemptMS: rcpt.LastAttempt,
				LastDiag:      rcpt.LastDiag,
			}
		}
		out = append(out, queueEntryDTO{
			ID:          e.ID,
			ReturnPath:  e.Msg.ReturnPath,
			Size:        e.Msg.Size,
			Created:     e.Msg.Created,
			Pending:     pending,
			Held:        mail.IsHeld(e.Msg),
			Recipients:  rcpts,
			CompletedMS: e.Msg.Done,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

func (s *Server) requireQueueAdmin(w http.ResponseWriter, r *http.Request) (ok bool) {
	p, authed := principal(r.Context())
	if !authed {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	if p.Role != directory.RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden")
		return false
	}
	if s.queue == nil {
		writeError(w, http.StatusServiceUnavailable, "queue unavailable")
		return false
	}
	return true
}

func (s *Server) parseQueueID(w http.ResponseWriter, r *http.Request) (uint32, bool) {
	id, err := parsePathUint32(r.PathValue("id"))
	if err != nil || id == 0 {
		writeError(w, http.StatusBadRequest, "invalid queue id")
		return 0, false
	}
	return id, true
}

func (s *Server) handleQueueRetry(w http.ResponseWriter, r *http.Request) {
	if !s.requireQueueAdmin(w, r) {
		return
	}
	id, ok := s.parseQueueID(w, r)
	if !ok {
		return
	}
	address := strings.TrimSpace(r.URL.Query().Get("address"))
	if err := s.queue.RetryNow(r.Context(), id, address); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "queue entry not found")
			return
		}
		s.log.Error("http queue retry", "err", err)
		writeError(w, http.StatusInternalServerError, "queue retry failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleQueueHold(w http.ResponseWriter, r *http.Request) {
	if !s.requireQueueAdmin(w, r) {
		return
	}
	id, ok := s.parseQueueID(w, r)
	if !ok {
		return
	}
	if err := s.queue.Hold(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "queue entry not found")
			return
		}
		s.log.Error("http queue hold", "err", err)
		writeError(w, http.StatusInternalServerError, "queue hold failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleQueueUnhold(w http.ResponseWriter, r *http.Request) {
	if !s.requireQueueAdmin(w, r) {
		return
	}
	id, ok := s.parseQueueID(w, r)
	if !ok {
		return
	}
	if err := s.queue.Unhold(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "queue entry not found")
			return
		}
		s.log.Error("http queue unhold", "err", err)
		writeError(w, http.StatusInternalServerError, "queue unhold failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleQueueCancel(w http.ResponseWriter, r *http.Request) {
	if !s.requireQueueAdmin(w, r) {
		return
	}
	id, ok := s.parseQueueID(w, r)
	if !ok {
		return
	}
	if err := s.queue.Cancel(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "queue entry not found")
			return
		}
		s.log.Error("http queue cancel", "err", err)
		writeError(w, http.StatusInternalServerError, "queue cancel failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type deliveryTestRequest struct {
	To   string `json:"to"`
	Mode string `json:"mode"`
}

// handleServicesStatus returns listener/component status for ops (admin only).
func (s *Server) handleServicesStatus(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if p.Role != directory.RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	entries := []servicestatus.Entry{}
	if s.status != nil {
		entries = s.status.List()
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": entries})
}

// handleLogs returns recent rotating JSON log records (admin only).
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if p.Role != directory.RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if s.logFile == "" {
		writeError(w, http.StatusServiceUnavailable, "log file unavailable")
		return
	}
	q := beaverlog.Query{Limit: 200}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		q.Limit = n
	}
	if v := r.URL.Query().Get("level"); v != "" {
		lvl, ok := beaverlog.ParseLevelName(v)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid level")
			return
		}
		q.MinLevel = lvl
		q.LevelSet = true
	}
	q.Q = r.URL.Query().Get("q")
	if v := r.URL.Query().Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			t, err = time.Parse(time.RFC3339, v)
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid before")
			return
		}
		q.Before = t
	}
	entries, err := beaverlog.ReadHistory(s.logFile, s.logFileKeep, q)
	if err != nil {
		s.log.Error("http logs file", "err", err)
		writeError(w, http.StatusInternalServerError, "read logs failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// handleDeliveryStatus reports outbound probe options (no secrets).
func (s *Server) handleDeliveryStatus(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if p.Role != directory.RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	relay := ""
	if s.remote != nil {
		relay = strings.TrimSpace(s.remote.Relay)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"relay_configured": relay != "",
		"relay":            relay,
	})
}

// handleDeliveryTest probes outbound MX or relay connectivity without sending mail.
func (s *Server) handleDeliveryTest(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if p.Role != directory.RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if s.remote == nil {
		writeError(w, http.StatusServiceUnavailable, "delivery probe unavailable")
		return
	}
	var req deliveryTestRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res := smtp.ProbeRemote(ctx, *s.remote, smtp.ProbeRequest{To: req.To, Mode: req.Mode})
	writeJSON(w, http.StatusOK, res)
}
