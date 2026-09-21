// Session tokens (HMAC cookie / Bearer) and role gates for /api/v1.
package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
)

type ctxKey int

const principalKey ctxKey = 1

// sessionClaims is the signed session payload.
type sessionClaims struct {
	AccountID uint32 `json:"aid"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	TenantID  uint32 `json:"tid"`
	Exp       int64  `json:"exp"`
}

// decodeAuthKey accepts hex (beaver init) or raw secret bytes.
func decodeAuthKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("httpapi: empty auth key")
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) >= 16 {
		return b, nil
	}
	return []byte(s), nil
}

// mintToken signs a session for principal.
func (s *Server) mintToken(p directory.Principal) (string, time.Time, error) {
	exp := time.Now().Add(sessionTTL)
	claims := sessionClaims{
		AccountID: p.AccountID,
		Email:     p.Email(),
		Role:      directory.NormalizeRole(p.Role),
		TenantID:  p.TenantID,
		Exp:       exp.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.authKey)
	_, _ = mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "v1." + body + "." + sig, exp, nil
}

// parseToken verifies HMAC and expiry.
func (s *Server) parseToken(token string) (sessionClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return sessionClaims{}, errors.New("invalid token")
	}
	mac := hmac.New(sha256.New, s.authKey)
	_, _ = mac.Write([]byte(parts[1]))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(want, got) {
		return sessionClaims{}, errors.New("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return sessionClaims{}, errors.New("invalid token payload")
	}
	var claims sessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return sessionClaims{}, errors.New("invalid token claims")
	}
	if claims.Exp < time.Now().Unix() {
		return sessionClaims{}, errors.New("token expired")
	}
	claims.Role = directory.NormalizeRole(claims.Role)
	return claims, nil
}

// principalFromRequest reads Bearer or session cookie.
func (s *Server) principalFromRequest(r *http.Request) (directory.Principal, error) {
	token := bearerToken(r)
	if token == "" {
		if c, err := r.Cookie(sessionCookie); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		return directory.Principal{}, errors.New("unauthorized")
	}
	claims, err := s.parseToken(token)
	if err != nil {
		return directory.Principal{}, err
	}
	local, domain, ok := strings.Cut(claims.Email, "@")
	if !ok {
		return directory.Principal{}, errors.New("invalid token email")
	}
	return directory.Principal{
		AccountID:  claims.AccountID,
		TenantID:   claims.TenantID,
		LocalPart:  local,
		DomainName: domain,
		Role:       claims.Role,
	}, nil
}

// bearerToken extracts the Authorization Bearer value.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, prefix))
}

// requireAuth wraps handlers that need a valid session.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.principalFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, p)
		next(w, r.WithContext(ctx))
	}
}

// principal returns the authenticated principal from context.
func principal(ctx context.Context) (directory.Principal, bool) {
	p, ok := ctx.Value(principalKey).(directory.Principal)
	return p, ok
}

// clientIP returns the remote host for auth rate limiting (no X-Forwarded-For yet).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// setSessionCookie writes the HttpOnly session cookie.
func (s *Server) setSessionCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.useTLS,
	})
}

// clearSessionCookie expires the session cookie.
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.useTLS,
	})
}

// canListAllDomains reports instance-wide domain visibility.
func canListAllDomains(p directory.Principal) bool {
	return p.Role == directory.RoleAdmin
}

// canSeeDomainTenant reports whether p may see domains for tenantID.
func canSeeDomainTenant(p directory.Principal, tenantID uint32) bool {
	switch p.Role {
	case directory.RoleAdmin:
		return true
	case directory.RoleTenantAdmin:
		return p.TenantID == tenantID
	case directory.RoleUser:
		return false
	default:
		return false
	}
}

// canListAccounts reports whether p may list accounts on domain tenant/name.
func canListAccounts(p directory.Principal, tenantID uint32, domainName string) bool {
	switch p.Role {
	case directory.RoleAdmin:
		return true
	case directory.RoleTenantAdmin:
		return p.TenantID == tenantID
	case directory.RoleUser:
		return strings.EqualFold(p.DomainName, domainName)
	default:
		return false
	}
}

// canManageDomain reports whether p may create/delete domains in tenantID.
func canManageDomain(p directory.Principal, tenantID uint32) bool {
	switch p.Role {
	case directory.RoleAdmin:
		return true
	case directory.RoleTenantAdmin:
		return p.TenantID == tenantID
	default:
		return false
	}
}

// canManageAccount reports whether p may mutate accounts on a domain tenant.
func canManageAccount(p directory.Principal, tenantID uint32) bool {
	return canManageDomain(p, tenantID)
}

// canCreateOrDeleteTenant reports instance-admin-only tenant lifecycle.
func canCreateOrDeleteTenant(p directory.Principal) bool {
	return p.Role == directory.RoleAdmin
}

// canRenameTenant reports whether p may rename tenantID.
func canRenameTenant(p directory.Principal, tenantID uint32) bool {
	switch p.Role {
	case directory.RoleAdmin:
		return true
	case directory.RoleTenantAdmin:
		return p.TenantID == tenantID
	default:
		return false
	}
}

// canAssignRole reports whether p may set targetRole on an account.
func canAssignRole(p directory.Principal, targetRole string) bool {
	targetRole = directory.NormalizeRole(targetRole)
	switch p.Role {
	case directory.RoleAdmin:
		return directory.ValidateRole(targetRole) == nil
	case directory.RoleTenantAdmin:
		return targetRole == directory.RoleUser || targetRole == directory.RoleTenantAdmin
	default:
		return false
	}
}

// requireSameOrigin rejects cookie-authenticated mutations from cross-site origins.
// Bearer clients (scripts / tests) are exempt. Login is not wrapped with this helper.
func (s *Server) requireSameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bearerToken(r) != "" {
			next(w, r)
			return
		}
		if !sameOriginOK(r) {
			writeError(w, http.StatusForbidden, "csrf origin check failed")
			return
		}
		next(w, r)
	}
}

// sameOriginOK accepts Sec-Fetch-Site same-origin/none, or Origin matching Host
// (including Vite loopback proxy: Origin :5173 → Host :8080).
func sameOriginOK(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "same-origin", "none":
		return true
	case "cross-site", "same-site":
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return isLoopbackHost(u.Hostname()) && isLoopbackHost(hostOnly(r.Host))
}

func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
