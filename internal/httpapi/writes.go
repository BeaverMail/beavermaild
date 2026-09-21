// First-install setup and directory write handlers for /api/v1.
package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/BeaverMail/beaver/internal/directory"
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
	Name     string `json:"name"`
	TenantID uint32 `json:"tenant_id"`
}

// handleCreateDomain creates or returns a domain in the caller's tenant scope.
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
	dom, created, err := s.dir.EnsureDomain(r.Context(), tenantID, req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, domainDTO{ID: dom.ID, Name: dom.Name, TenantID: dom.TenantID})
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
}

// handlePatchAccount updates role, password, and/or active flag.
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
	if req.Role == nil && req.Password == nil && req.Active == nil {
		writeError(w, http.StatusBadRequest, "no fields to update")
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
	acc, _, err = s.dir.ResolveEmail(r.Context(), email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reload account failed")
		return
	}
	writeJSON(w, http.StatusOK, accountListDTO{
		ID:        acc.ID,
		LocalPart: acc.LocalPart,
		Email:     acc.LocalPart + "@" + dom.Name,
		Role:      directory.NormalizeRole(acc.Role),
		TenantID:  acc.TenantID,
		Active:    acc.Active,
	})
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
