// SPDX-License-Identifier: Apache-2.0

// beaver-license creates vendor signing keys and issues plugin license files (see docs/plugins.md).
// It runs on the vendor's machine; it is not part of the server packages.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/BeaverMail/beavermaild/plugin/license"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "issue":
		err = issue(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "beaver-license:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  beaver-license keygen -out vendor.key
  beaver-license issue -key vendor.key -plugin NAME -model oneshot|perpetual -licensee NAME
                       (-domains a.example,b.example | -install-id ID) [-updates-until YYYY-MM-DD] > NAME.lic`)
	os.Exit(2)
}

// keygen writes the private key (base64 seed, 0600, never overwritten) and prints the public key.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "private key file to create")
	fs.Parse(args)
	if *out == "" {
		return errors.New("keygen: -out is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("public key (license.Product.PublicKey, base64): %s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

func issue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	keyPath := fs.String("key", "", "private key file from keygen")
	var lic license.License
	fs.StringVar(&lic.Plugin, "plugin", "", "plugin id (binary name without beaver-plugin-)")
	fs.StringVar(&lic.Model, "model", "", "oneshot or perpetual")
	fs.StringVar(&lic.Licensee, "licensee", "", "customer name")
	domains := fs.String("domains", "", "comma-separated domains (domain scope)")
	fs.StringVar(&lic.InstallID, "install-id", "", "installation id from beaver plugins list (server scope)")
	fs.StringVar(&lic.UpdatesUntil, "updates-until", "", "last release date covered, YYYY-MM-DD (perpetual only)")
	fs.Parse(args)

	if *keyPath == "" || lic.Plugin == "" || lic.Licensee == "" {
		return errors.New("issue: -key, -plugin and -licensee are required")
	}
	if lic.Model == license.ModelOneshot && lic.UpdatesUntil != "" {
		return errors.New("issue: -updates-until is for perpetual licenses only")
	}
	for _, d := range strings.Split(*domains, ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			lic.Domains = append(lic.Domains, d)
		}
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("issue: %s is not a key from keygen", *keyPath)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	data, err := license.Sign(priv, lic)
	if err != nil {
		return err
	}
	// Check the result with the same code the plugin runs, so a bad license never leaves this tool.
	released := lic.UpdatesUntil
	if released == "" {
		released = "2000-01-01"
	}
	check := license.Product{Plugin: lic.Plugin, PublicKey: priv.Public().(ed25519.PublicKey), Released: released}
	if _, err := check.Verify(data, lic.InstallID); err != nil {
		return fmt.Errorf("issue: %w", err)
	}
	_, err = fmt.Printf("%s\n", data)
	return err
}
