// /api/v1 handlers: health, auth, me, tenants, domains, accounts, setup.
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/storage"
)

// routes registers /api/v1 endpoints on the server mux.
func (s *Server) routes() {
	s.mux.HandleFunc("GET "+apiPrefix+"/health", s.handleHealth)
	s.mux.HandleFunc("GET "+apiPrefix+"/setup", s.handleSetupStatus)
	s.mux.HandleFunc("POST "+apiPrefix+"/setup", s.requireSameOrigin(s.handleSetupBootstrap))
	s.mux.HandleFunc("POST "+apiPrefix+"/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST "+apiPrefix+"/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET "+apiPrefix+"/me", s.requireAuth(s.handleMe))
	s.mux.HandleFunc("GET "+apiPrefix+"/tenants", s.requireAuth(s.handleListTenants))
	s.mux.HandleFunc("POST "+apiPrefix+"/tenants", s.requireAuth(s.requireSameOrigin(s.handleCreateTenant)))
	s.mux.HandleFunc("PATCH "+apiPrefix+"/tenants/{id}", s.requireAuth(s.requireSameOrigin(s.handlePatchTenant)))
	s.mux.HandleFunc("DELETE "+apiPrefix+"/tenants/{id}", s.requireAuth(s.requireSameOrigin(s.handleDeleteTenant)))
	s.mux.HandleFunc("GET "+apiPrefix+"/domains", s.requireAuth(s.handleListDomains))
	s.mux.HandleFunc("POST "+apiPrefix+"/domains", s.requireAuth(s.requireSameOrigin(s.handleCreateDomain)))
	s.mux.HandleFunc("GET "+apiPrefix+"/domains/{domain}", s.requireAuth(s.handleGetDomain))
	s.mux.HandleFunc("GET "+apiPrefix+"/domains/{domain}/dns-recommended", s.requireAuth(s.handleDomainDNSRecommended))
	s.mux.HandleFunc("GET "+apiPrefix+"/domains/{domain}/reports", s.requireAuth(s.handleDomainReports))
	s.mux.HandleFunc("PATCH "+apiPrefix+"/domains/{domain}", s.requireAuth(s.requireSameOrigin(s.handlePatchDomain)))
	s.mux.HandleFunc("DELETE "+apiPrefix+"/domains/{domain}", s.requireAuth(s.requireSameOrigin(s.handleDeleteDomain)))
	s.mux.HandleFunc("GET "+apiPrefix+"/domains/{domain}/accounts", s.requireAuth(s.handleListAccounts))
	s.mux.HandleFunc("POST "+apiPrefix+"/domains/{domain}/accounts", s.requireAuth(s.requireSameOrigin(s.handleCreateAccount)))
	s.mux.HandleFunc("DELETE "+apiPrefix+"/accounts/{email}", s.requireAuth(s.requireSameOrigin(s.handleDeleteAccount)))
	s.mux.HandleFunc("PATCH "+apiPrefix+"/accounts/{email}", s.requireAuth(s.requireSameOrigin(s.handlePatchAccount)))
	s.mux.HandleFunc("GET "+apiPrefix+"/queue", s.requireAuth(s.handleListQueue))
	s.mux.HandleFunc("POST "+apiPrefix+"/queue/{id}/retry", s.requireAuth(s.requireSameOrigin(s.handleQueueRetry)))
	s.mux.HandleFunc("POST "+apiPrefix+"/queue/{id}/hold", s.requireAuth(s.requireSameOrigin(s.handleQueueHold)))
	s.mux.HandleFunc("POST "+apiPrefix+"/queue/{id}/unhold", s.requireAuth(s.requireSameOrigin(s.handleQueueUnhold)))
	s.mux.HandleFunc("DELETE "+apiPrefix+"/queue/{id}", s.requireAuth(s.requireSameOrigin(s.handleQueueCancel)))
	s.mux.HandleFunc("POST "+apiPrefix+"/delivery/test", s.requireAuth(s.requireSameOrigin(s.handleDeliveryTest)))
	s.mux.HandleFunc("GET "+apiPrefix+"/delivery", s.requireAuth(s.handleDeliveryStatus))
	s.mux.HandleFunc("GET "+apiPrefix+"/status", s.requireAuth(s.handleServicesStatus))
	s.mux.HandleFunc("GET "+apiPrefix+"/logs", s.requireAuth(s.handleLogs))
	if s.ui != nil {
		s.mux.Handle("/", newSPAHandler(s.ui))
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type accountDTO struct {
	Email    string `json:"email"`
	Role     string `json:"role"`
	TenantID uint32 `json:"tenant_id"`
}

type loginResponse struct {
	Token   string     `json:"token"`
	Account accountDTO `json:"account"`
}

// handleLogin authenticates directory credentials and issues a session.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.authGate.AllowAuth(ip, "") {
		writeError(w, http.StatusTooManyRequests, "too many auth attempts")
		return
	}
	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}
	p, err := s.dir.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		s.authGate.RecordAuthFailure(ip, req.Email)
		if errors.Is(err, directory.ErrInvalidCredentials) || errors.Is(err, directory.ErrInactive) || errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		s.log.Error("http login", "err", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	s.authGate.RecordAuthSuccess(ip, req.Email)
	s.writeSession(w, p)
}

// handleLogout clears the session cookie (Bearer clients drop the token locally).
func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleMe returns the authenticated principal.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, accountDTO{
		Email:    p.Email(),
		Role:     p.Role,
		TenantID: p.TenantID,
	})
}

type tenantDTO struct {
	ID   uint32 `json:"id"`
	Name string `json:"name"`
}

// handleListTenants returns tenants visible to the caller (admin/provisioner: all; tenant_admin: own).
func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch p.Role {
	case directory.RoleAdmin, directory.RoleProvisioner:
		tenants, err := s.dir.ListTenants(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list tenants failed")
			return
		}
		out := make([]tenantDTO, 0, len(tenants))
		for _, t := range tenants {
			out = append(out, tenantDTO{ID: t.ID, Name: t.Name})
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
	case directory.RoleTenantAdmin:
		t, err := s.dir.GetTenant(r.Context(), p.TenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "get tenant failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenants": []tenantDTO{{ID: t.ID, Name: t.Name}}})
	default:
		writeError(w, http.StatusForbidden, "forbidden")
	}
}

type domainDTO struct {
	ID            uint32 `json:"id"`
	Name          string `json:"name"`
	TenantID      uint32 `json:"tenant_id"`
	CatchAll      string `json:"catch_all,omitempty"`
	MailHostname  string `json:"mail_hostname,omitempty"`
	SSLMode       string `json:"ssl_mode,omitempty"`
	DKIMEnabled   bool   `json:"dkim_enabled,omitempty"`
	DKIMSelector  string `json:"dkim_selector,omitempty"`
	DKIMDNSName   string `json:"dkim_dns_name,omitempty"`
	DKIMDNSValue  string `json:"dkim_dns_value,omitempty"`
	AntiSpam      bool   `json:"antispam,omitempty"`
	SendMax       int    `json:"send_max_messages,omitempty"`
	SendWindow    string `json:"send_window,omitempty"`
	StorageBytes  uint64 `json:"storage_bytes,omitempty"`
	MessagesQuota uint32 `json:"messages_quota,omitempty"`
	RelayHost     string `json:"relay_host,omitempty"`
	RelayUser     string `json:"relay_user,omitempty"`
	RelayStartTLS bool   `json:"relay_starttls,omitempty"`
	AccountCount  int    `json:"account_count"`
	StorageUsed   uint64 `json:"storage_used"`
	SSLActive     bool   `json:"ssl_active"`
	DKIMActive    bool   `json:"dkim_active"`
	AntiSpamOn    bool   `json:"antispam_active"`
}

func (s *Server) domainToDTO(ctx context.Context, d storage.Domain) domainDTO {
	dto := domainDTO{
		ID:            d.ID,
		Name:          d.Name,
		TenantID:      d.TenantID,
		CatchAll:      d.CatchAllLocal,
		MailHostname:  d.MailHostname,
		SSLMode:       d.SSLMode,
		DKIMEnabled:   d.DKIMEnabled,
		DKIMSelector:  d.DKIMSelector,
		AntiSpam:      d.AntiSpam,
		SendMax:       d.SendMaxMessages,
		SendWindow:    d.SendWindow,
		StorageBytes:  d.StorageBytes,
		MessagesQuota: d.Messages,
		RelayHost:     d.RelayHost,
		RelayUser:     d.RelayUser,
		RelayStartTLS: d.RelayStartTLS,
	}
	accounts, _, err := s.dir.ListAccounts(ctx, d.Name)
	n := 0
	var used uint64
	if err == nil {
		n = len(accounts)
		if s.inbox != nil {
			for _, a := range accounts {
				st, err := s.inbox.QuotaStatus(ctx, a.ID)
				if err == nil {
					used += st.StorageUsed
				}
			}
		}
	}
	st := s.dir.BuildDomainStats(d, n, used)
	dto.AccountCount = st.AccountCount
	dto.StorageUsed = st.StorageUsed
	dto.SSLActive = st.SSLActive
	dto.DKIMActive = st.DKIMActive
	dto.AntiSpamOn = st.AntiSpam
	if name, val, err := s.dir.DKIMDNSRecord(d); err == nil {
		dto.DKIMDNSName = name
		dto.DKIMDNSValue = val
	}
	return dto
}

// handleListDomains returns domains in the caller's scope.
func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	domains, err := s.dir.ListDomains(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list domains failed")
		return
	}
	out := make([]domainDTO, 0, len(domains))
	for _, d := range domains {
		if canListAllDomains(p) || canSeeDomainTenant(p, d.TenantID) {
			out = append(out, s.domainToDTO(r.Context(), d))
			continue
		}
		if p.Role == directory.RoleUser && strings.EqualFold(p.DomainName, d.Name) {
			out = append(out, s.domainToDTO(r.Context(), d))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": out})
}

type accountListDTO struct {
	ID        uint32 `json:"id"`
	LocalPart string `json:"local_part"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	TenantID  uint32 `json:"tenant_id"`
	Active    bool   `json:"active"`
	// Mailbox usage and limits (0 limit = unlimited); omitted when the inbox is not wired.
	StorageUsed   uint64 `json:"storage_used"`
	StorageLimit  uint64 `json:"storage_limit"`
	MessagesUsed  uint32 `json:"messages_used"`
	MessagesLimit uint32 `json:"messages_limit"`
}

// handleListAccounts lists accounts on a domain when the caller is in scope.
func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	domainName := r.PathValue("domain")
	accounts, dom, err := s.dir.ListAccounts(r.Context(), domainName)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "list accounts failed")
		return
	}
	if !canListAccounts(p, dom.TenantID, dom.Name) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	out := make([]accountListDTO, 0, len(accounts))
	for _, a := range accounts {
		role := directory.NormalizeRole(a.Role)
		email := a.LocalPart + "@" + dom.Name
		if p.Role == directory.RoleUser && !strings.EqualFold(email, p.Email()) {
			continue
		}
		dto := accountListDTO{
			ID:        a.ID,
			LocalPart: a.LocalPart,
			Email:     email,
			Role:      role,
			TenantID:  a.TenantID,
			Active:    a.Active,
		}
		if s.inbox != nil {
			if st, err := s.inbox.QuotaStatus(r.Context(), a.ID); err == nil {
				dto.StorageUsed, dto.StorageLimit = st.StorageUsed, st.StorageLimit
				dto.MessagesUsed, dto.MessagesLimit = st.MessagesUsed, st.MessagesLimit
			}
		}
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

// writeSession mints a token, sets the cookie, and returns the login response body.
func (s *Server) writeSession(w http.ResponseWriter, p directory.Principal) {
	token, exp, err := s.mintToken(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token failed")
		return
	}
	s.setSessionCookie(w, token, exp)
	writeJSON(w, http.StatusOK, loginResponse{
		Token: token,
		Account: accountDTO{
			Email:    p.Email(),
			Role:     p.Role,
			TenantID: p.TenantID,
		},
	})
}
