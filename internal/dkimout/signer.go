// Outbound DKIM signing for queued remote delivery (RFC 6376).
package dkimout

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	netmail "net/mail"
	"net/textproto"
	"os"
	"strings"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/BeaverMail/beavermaild/internal/dnsname"
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
	// RFC 8301 3.2: signers MUST use RSA keys of at least 1024 bits (verifiers reject shorter ones).
	if k, ok := key.(*rsa.PrivateKey); ok && k.N.BitLen() < 1024 {
		return nil, fmt.Errorf("dkimout: RSA key of %d bits in %s, at least 1024 required (2048 recommended)", k.N.BitLen(), cfg.KeyPath)
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
		// RFC 6376 5.4.1: "relaxed" survives the refolding intermediaries do to person-to-person mail.
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             headerKeys(raw),
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
	return dnsname.ToASCII(addr[at+1:]), nil
}

// coreFields are the header fields signed when present (RFC 6376 5.4.1, plus the MIME fields that
// decide how the body renders); trace and client fields (Received, X-*) are left out.
var coreFields = []string{
	"From", "Reply-To", "Subject", "Date", "To", "Cc", "Message-ID", "In-Reply-To", "References",
	"Resent-Date", "Resent-From", "Resent-To", "Resent-Cc",
	"List-Id", "List-Help", "List-Unsubscribe", "List-Subscribe", "List-Post", "List-Owner", "List-Archive",
	"MIME-Version", "Content-Type", "Content-Transfer-Encoding",
}

// oversigned fields appear once in a valid message: they are listed once more than present, so a
// copy added in transit breaks the signature (RFC 6376 8.15, "h=from:from").
var oversigned = map[string]bool{"From": true, "Reply-To": true, "Subject": true, "Date": true, "To": true, "Cc": true, "Message-ID": true}

// headerKeys is the h= list for raw: each present core field as many times as it occurs, plus one for
// the oversigned ones. From is always listed (RFC 6376 5.4). nil (sign every field, the library
// default) only for a header block net/mail cannot read.
func headerKeys(raw []byte) []string {
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	var keys []string
	for _, name := range coreFields {
		n := len(msg.Header[textproto.CanonicalMIMEHeaderKey(name)])
		if oversigned[name] && (n > 0 || name == "From") {
			n++
		}
		for range n {
			keys = append(keys, name)
		}
	}
	return keys
}

// GenerateKey writes a 2048-bit RSA private key PEM to path.
func GenerateKey(path string) error {
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

// GenerateTestKey is an alias used by tests.
func GenerateTestKey(path string) error { return GenerateKey(path) }

// PublicKeyDNS returns a DKIM TXT value (v=DKIM1; k=rsa; p=...) for the private key at path.
func PublicKeyDNS(path string) (string, error) {
	key, err := loadPrivateKey(path)
	if err != nil {
		return "", err
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return "", err
		}
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubDER), nil
	case ed25519.PrivateKey:
		// RFC 8463 4: p= is the raw 32-octet public key, not a SubjectPublicKeyInfo.
		return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)), nil
	default:
		return "", fmt.Errorf("dkimout: unsupported key type %T for a DNS record", key)
	}
}
