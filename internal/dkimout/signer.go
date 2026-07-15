// Outbound DKIM signing for queued remote delivery (RFC 6376).
package dkimout

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// Signer adds a DKIM-Signature when configured selector and key are present.
type Signer struct {
	selector string
	domain   string // fixed SDID; empty uses return-path domain
	signer   crypto.Signer
}

// Config holds DKIM signing parameters.
type Config struct {
	Selector string
	Domain   string
	KeyPath  string
}

// New loads a private key PEM (RSA or PKCS#8) and returns a Signer.
func New(cfg Config) (*Signer, error) {
	if strings.TrimSpace(cfg.Selector) == "" || strings.TrimSpace(cfg.KeyPath) == "" {
		return nil, fmt.Errorf("dkimout: selector and key path required")
	}
	key, err := loadPrivateKey(cfg.KeyPath)
	if err != nil {
		return nil, err
	}
	return &Signer{
		selector: strings.TrimSpace(cfg.Selector),
		domain:   strings.TrimSpace(strings.ToLower(cfg.Domain)),
		signer:   key,
	}, nil
}

// Sign returns raw unchanged when signing is skipped; otherwise appends DKIM-Signature.
func (s *Signer) Sign(returnPath string, raw []byte) ([]byte, error) {
	if s == nil || len(raw) == 0 {
		return raw, nil
	}
	returnPath = strings.TrimSpace(returnPath)
	if returnPath == "" {
		return raw, nil
	}
	if hasSelectorSignature(raw, s.selector) {
		return raw, nil
	}
	domain := s.domain
	if domain == "" {
		var err error
		domain, err = domainFromAddress(returnPath)
		if err != nil {
			return nil, err
		}
	}
	var out bytes.Buffer
	err := dkim.Sign(&out, bytes.NewReader(raw), &dkim.SignOptions{
		Domain:   domain,
		Selector: s.selector,
		Signer:   s.signer,
		Hash:     crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("dkimout: sign: %w", err)
	}
	return out.Bytes(), nil
}

func loadPrivateKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dkimout: read key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("dkimout: invalid PEM in %s", path)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("dkimout: parse RSA key: %w", err)
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("dkimout: parse PKCS8 key: %w", err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("dkimout: key is not a signer")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("dkimout: unsupported PEM type %q", block.Type)
	}
}

func domainFromAddress(addr string) (string, error) {
	addr = strings.TrimSpace(strings.ToLower(addr))
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return "", fmt.Errorf("dkimout: invalid address %q", addr)
	}
	return addr[at+1:], nil
}

// hasSelectorSignature reports whether raw already contains s=<selector> in a DKIM-Signature header.
func hasSelectorSignature(raw []byte, selector string) bool {
	selector = strings.ToLower(strings.TrimSpace(selector))
	if selector == "" {
		return false
	}
	lower := bytes.ToLower(raw)
	if !bytes.Contains(lower, []byte("dkim-signature:")) {
		return false
	}
	return bytes.Contains(lower, []byte("s="+selector))
}

// GenerateTestKey writes a 2048-bit RSA private key PEM to path (tests only).
func GenerateTestKey(path string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	b := x509.MarshalPKCS1PrivateKey(key)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b})
}
