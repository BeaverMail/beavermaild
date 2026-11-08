// /api/v1 alias handlers: local aliases delivering to mailboxes of the same tenant.
package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/directory"
)

type aliasDTO struct {
	Email     string   `json:"email"`
	LocalPart string   `json:"local_part"`
	Targets   []string `json:"targets"`
}

func toAliasDTO(a directory.AliasView) aliasDTO {
	return aliasDTO{Email: a.Email, LocalPart: a.LocalPart, Targets: a.Targets}
}

type aliasRequest struct {
	LocalPart string   `json:"local_part"`
	Targets   []string `json:"targets"`
}

// aliasDomainInScope loads domainName and checks the caller may manage its accounts.
func (s *Server) aliasDomainInScope(w http.ResponseWriter, r *http.Request, domainName string) bool {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	dom, err := s.dir.LookupDomain(r.Context(), domainName)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return false
		}
		writeError(w, http.StatusInternalServerError, "lookup domain failed")
		return false
	}
	if !canManageAccount(p, dom.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

// aliasEmailDomain returns the domain part of an alias address from the path.
func aliasEmailDomain(email string) string {
	_, dom, _ := strings.Cut(strings.TrimSpace(email), "@")
	return dom
}

func (s *Server) handleListAliases(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	if !s.aliasDomainInScope(w, r, domainName) {
		return
	}
	aliases, _, err := s.dir.ListAliases(r.Context(), domainName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list aliases failed")
		return
	}
	out := make([]aliasDTO, len(aliases))
	for i, a := range aliases {
		out[i] = toAliasDTO(a)
	}
	writeJSON(w, http.StatusOK, map[string]any{"aliases": out})
}

func (s *Server) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	if !s.aliasDomainInScope(w, r, domainName) {
		return
	}
	var req aliasRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	a, err := s.dir.CreateAlias(r.Context(), domainName, req.LocalPart, req.Targets)
	if err != nil {
		if errors.Is(err, directory.ErrExists) {
			writeError(w, http.StatusConflict, "address already used by a mailbox or alias")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toAliasDTO(a))
}

func (s *Server) handlePatchAlias(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	if !s.aliasDomainInScope(w, r, aliasEmailDomain(email)) {
		return
	}
	var req struct {
		Targets []string `json:"targets"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	a, err := s.dir.SetAliasTargets(r.Context(), email, req.Targets)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "alias not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toAliasDTO(a))
}

func (s *Server) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	if !s.aliasDomainInScope(w, r, aliasEmailDomain(email)) {
		return
	}
	if err := s.dir.DeleteAlias(r.Context(), email); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "alias not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete alias failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": email})
}
