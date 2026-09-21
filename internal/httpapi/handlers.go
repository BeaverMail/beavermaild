// /api/v1 handlers: health, auth, me, tenants, domains, accounts, setup.
package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/BeaverMail/beaver/internal/directory"
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
	s.mux.HandleFunc("DELETE "+apiPrefix+"/domains/{domain}", s.requireAuth(s.requireSameOrigin(s.handleDeleteDomain)))
	s.mux.HandleFunc("GET "+apiPrefix+"/domains/{domain}/accounts", s.requireAuth(s.handleListAccounts))
	s.mux.HandleFunc("POST "+apiPrefix+"/domains/{domain}/accounts", s.requireAuth(s.requireSameOrigin(s.handleCreateAccount)))
	s.mux.HandleFunc("DELETE "+apiPrefix+"/accounts/{email}", s.requireAuth(s.requireSameOrigin(s.handleDeleteAccount)))
	s.mux.HandleFunc("PATCH "+apiPrefix+"/accounts/{email}", s.requireAuth(s.requireSameOrigin(s.handlePatchAccount)))
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

// handleListTenants returns tenants visible to the caller (admin: all; tenant_admin: own).
func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch p.Role {
	case directory.RoleAdmin:
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
	ID       uint32 `json:"id"`
	Name     string `json:"name"`
	TenantID uint32 `json:"tenant_id"`
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
			out = append(out, domainDTO{ID: d.ID, Name: d.Name, TenantID: d.TenantID})
			continue
		}
		if p.Role == directory.RoleUser && strings.EqualFold(p.DomainName, d.Name) {
			out = append(out, domainDTO{ID: d.ID, Name: d.Name, TenantID: d.TenantID})
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
		out = append(out, accountListDTO{
			ID:        a.ID,
			LocalPart: a.LocalPart,
			Email:     email,
			Role:      role,
			TenantID:  a.TenantID,
			Active:    a.Active,
		})
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
