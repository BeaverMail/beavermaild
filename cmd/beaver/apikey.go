// beaver apikey: create, list, and revoke long-lived HTTP API keys.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/BeaverMail/beavermaild/internal/cli"
	"github.com/BeaverMail/beavermaild/internal/config"
	"github.com/BeaverMail/beavermaild/internal/directory"
)

func runAPIKey(args []string) int {
	if len(args) == 0 {
		apiKeyUsage()
		return cli.ExitUsage
	}
	switch args[0] {
	case "create":
		return runAPIKeyCreate(args[1:])
	case "list":
		return runAPIKeyList(args[1:])
	case "revoke":
		return runAPIKeyRevoke(args[1:])
	default:
		apiKeyUsage()
		return cli.ExitUsage
	}
}

// openCLIDirectory loads config and opens the directory for a CLI subcommand.
func openCLIDirectory(ctx context.Context, cmd, configPath string) (*directory.Local, func(), bool) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: load config: %v\n", cmd, err)
		return nil, nil, false
	}
	dir, closeStore, err := openDirectory(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		return nil, nil, false
	}
	return dir, closeStore, true
}

// runAPIKeyCreate prints the token once on stdout (for scripts) and metadata on stderr.
func runAPIKeyCreate(args []string) int {
	fs := flag.NewFlagSet("apikey create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	name := fs.String("name", "", "label for the key (e.g. the integration name)")
	role := fs.String("role", directory.RoleProvisioner, "key role: provisioner")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 || *name == "" {
		apiKeyUsage()
		return cli.ExitUsage
	}
	ctx := context.Background()
	dir, closeStore, ok := openCLIDirectory(ctx, "apikey create", *configPath)
	if !ok {
		return cli.ExitError
	}
	defer closeStore()
	key, token, err := dir.CreateAPIKey(ctx, *name, *role)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apikey create: %v\n", err)
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "apikey_id=%d name=%s role=%s (token shown once, store it now)\n", key.ID, key.Name, key.Role)
	fmt.Println(token)
	return cli.ExitOK
}

type apiKeyJSON struct {
	ID      uint32 `json:"id"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	Created int64  `json:"created"`
}

func runAPIKeyList(args []string) int {
	fs := flag.NewFlagSet("apikey list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	asJSON := fs.Bool("json", false, "emit JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 {
		apiKeyUsage()
		return cli.ExitUsage
	}
	ctx := context.Background()
	dir, closeStore, ok := openCLIDirectory(ctx, "apikey list", *configPath)
	if !ok {
		return cli.ExitError
	}
	defer closeStore()
	keys, err := dir.ListAPIKeys(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apikey list: %v\n", err)
		return cli.ExitError
	}
	rows := make([]apiKeyJSON, len(keys))
	for i, k := range keys {
		rows[i] = apiKeyJSON{ID: k.ID, Name: k.Name, Role: k.Role, Created: k.Created}
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(os.Stderr, "apikey list: %v\n", err)
			return cli.ExitError
		}
		return cli.ExitOK
	}
	for _, r := range rows {
		fmt.Fprintf(os.Stderr, "apikey_id=%d name=%s role=%s created=%d\n", r.ID, r.Name, r.Role, r.Created)
	}
	return cli.ExitOK
}

func runAPIKeyRevoke(args []string) int {
	fs := flag.NewFlagSet("apikey revoke", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 1 {
		apiKeyUsage()
		return cli.ExitUsage
	}
	id, err := strconv.ParseUint(fs.Arg(0), 10, 32)
	if err != nil || id == 0 {
		fmt.Fprintf(os.Stderr, "apikey revoke: invalid id %q\n", fs.Arg(0))
		return cli.ExitUsage
	}
	ctx := context.Background()
	dir, closeStore, ok := openCLIDirectory(ctx, "apikey revoke", *configPath)
	if !ok {
		return cli.ExitError
	}
	defer closeStore()
	if err := dir.RevokeAPIKey(ctx, uint32(id)); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "apikey revoke: no key with id %d\n", id)
		} else {
			fmt.Fprintf(os.Stderr, "apikey revoke: %v\n", err)
		}
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "revoked apikey_id=%d\n", id)
	return cli.ExitOK
}

func apiKeyUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	printAPIKeyUsageLines()
}

func printAPIKeyUsageLines() {
	fmt.Fprintln(os.Stderr, "  beaver apikey create [-c path] -name label [-role provisioner]")
	fmt.Fprintln(os.Stderr, "  beaver apikey list [-c path] [-json]")
	fmt.Fprintln(os.Stderr, "  beaver apikey revoke [-c path] <id>")
}
