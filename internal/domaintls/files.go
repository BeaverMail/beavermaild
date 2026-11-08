package domaintls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// fileRecheck bounds how often the global PEM files are stat'ed for changes.
const fileRecheck = time.Minute

func errNotACME(host string) error {
	return fmt.Errorf("domaintls: host %q not acme", host)
}

// fileCert is a PEM pair reloaded when either file's mtime changes (e.g. renewed by Caddy or certbot).
type fileCert struct {
	certFile, keyFile string

	mu              sync.Mutex
	cert            *tls.Certificate
	certMod, keyMod time.Time
	checked         time.Time
}

func loadFileCert(certFile, keyFile string) (*fileCert, error) {
	f := &fileCert{certFile: certFile, keyFile: keyFile}
	if err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fileCert) load() error {
	cm, err := modTime(f.certFile)
	if err != nil {
		return err
	}
	km, err := modTime(f.keyFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(f.certFile, f.keyFile)
	if err != nil {
		return fmt.Errorf("domaintls: load key pair: %w", err)
	}
	f.cert, f.certMod, f.keyMod, f.checked = &cert, cm, km, time.Now()
	return nil
}

// get returns the current cert, reloading it if the files changed; a failed reload keeps the old one.
func (f *fileCert) get(log *slog.Logger) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.checked) < fileRecheck {
		return f.cert, nil
	}
	f.checked = time.Now()
	cm, err1 := modTime(f.certFile)
	km, err2 := modTime(f.keyFile)
	if err1 == nil && err2 == nil && (!cm.Equal(f.certMod) || !km.Equal(f.keyMod)) {
		old := f.cert
		if err := f.load(); err != nil {
			f.cert = old
			log.Warn("tls reload", "cert_file", f.certFile, "err", err)
		} else {
			log.Info("tls reloaded", "cert_file", f.certFile)
		}
	}
	return f.cert, nil
}

func modTime(path string) (time.Time, error) {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return st.ModTime(), nil
}

// loadOrCreateSelfSigned keeps one self-signed cert under dir so STARTTLS works without any configured cert.
func loadOrCreateSelfSigned(dir string) (*tls.Certificate, error) {
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		return &cert, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	names := []string{"localhost"}
	if host != "" && host != "localhost" {
		names = append([]string{host}, names...)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
