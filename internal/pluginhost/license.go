// Plugin license environment and status display (verification code lives in plugin/license).
package pluginhost

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/config"
	"github.com/BeaverMail/beavermaild/plugin"
	"github.com/BeaverMail/beavermaild/plugin/license"
)

// LicenseEnv is the environment every plugin process gets so a paid plugin can find its license.
// A data dir without a usable install id only leaves BEAVER_INSTALL_ID out: install-scoped
// licenses then fail with a readable message, domain-scoped ones still work.
func LicenseEnv(cfg *config.Config) []string {
	env := []string{license.EnvLicensesDir + "=" + cfg.LicensesDir()}
	if id, err := cfg.InstallID(); err == nil && id != "" {
		env = append(env, license.EnvInstallID+"="+id)
	}
	return env
}

// LicenseStatus describes e's license for beaver plugins list: -, free, missing, expired, invalid or valid.
func LicenseStatus(e Entry, licensesDir, installID string) string {
	switch e.License {
	case plugin.LicenseFree:
		return "free"
	case plugin.LicensePaid:
	default:
		return "-" // not declared: the plugin may use its own license scheme
	}
	key, err := base64.StdEncoding.DecodeString(e.LicenseKey)
	if err != nil {
		return "invalid (descriptor license_key is not base64)"
	}
	prod := license.Product{Plugin: e.Name, PublicKey: key, Released: e.Released}
	lic, err := prod.LoadFrom(licensesDir, installID)
	switch {
	case errors.Is(err, license.ErrMissing):
		return "missing (" + prod.Path(licensesDir) + ")"
	case errors.Is(err, license.ErrNotCovered):
		return "expired (updates until " + lic.UpdatesUntil + ", this version released " + e.Released + ")"
	case err != nil:
		return "invalid (" + err.Error() + ")"
	}
	s := "valid"
	if lic.Model == license.ModelPerpetual {
		s += ", updates until " + lic.UpdatesUntil
	}
	if len(lic.Domains) > 0 {
		s += " domains=" + strings.Join(lic.Domains, ",")
	}
	return s
}
