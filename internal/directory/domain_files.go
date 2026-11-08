// Per-domain asset paths (TLS PEM, DKIM keys) under data_dir/domains/<id>/.
package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// DomainDir returns data_dir/domains/<id>.
func DomainDir(dataDir string, domainID uint32) string {
	return filepath.Join(dataDir, "domains", strconv.FormatUint(uint64(domainID), 10))
}

// DomainTLSCertPath is the custom certificate PEM path.
func DomainTLSCertPath(dataDir string, domainID uint32) string {
	return filepath.Join(DomainDir(dataDir, domainID), "tls.crt")
}

// DomainTLSKeyPath is the custom private key PEM path.
func DomainTLSKeyPath(dataDir string, domainID uint32) string {
	return filepath.Join(DomainDir(dataDir, domainID), "tls.key")
}

// DomainDKIMKeyPath is the outbound DKIM private key PEM path.
func DomainDKIMKeyPath(dataDir string, domainID uint32) string {
	return filepath.Join(DomainDir(dataDir, domainID), "dkim.pem")
}

// WriteDomainFile creates the domain dir and writes path with mode 0600.
func WriteDomainFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// DomainTLSFilesPresent reports whether custom cert+key exist.
func DomainTLSFilesPresent(dataDir string, domainID uint32) bool {
	cert := DomainTLSCertPath(dataDir, domainID)
	key := DomainTLSKeyPath(dataDir, domainID)
	if _, err := os.Stat(cert); err != nil {
		return false
	}
	if _, err := os.Stat(key); err != nil {
		return false
	}
	return true
}

// DomainDKIMKeyPresent reports whether the DKIM private key file exists.
func DomainDKIMKeyPresent(dataDir string, domainID uint32) bool {
	_, err := os.Stat(DomainDKIMKeyPath(dataDir, domainID))
	return err == nil
}

// EnsureDomainDir creates data_dir/domains/<id>.
func EnsureDomainDir(dataDir string, domainID uint32) error {
	if err := os.MkdirAll(DomainDir(dataDir, domainID), 0o700); err != nil {
		return fmt.Errorf("directory: domain dir: %w", err)
	}
	return nil
}
