// BeaverMail CLI entrypoint. Dispatches subcommands for the mail server binary.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/BeaverMail/beaver/internal/app"
	"github.com/BeaverMail/beaver/internal/cli"
	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/sqlite"
)

const version = "0.0.0-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return cli.ExitUsage
	}

	switch args[0] {
	case "version", "-v", "--version":
		fmt.Println(version)
		return cli.ExitOK
	case "init":
		return runInit(args[1:])
	case "serve":
		return runServe(args[1:])
	case "seed":
		return runSeed(args[1:])
	case "auth":
		return runAuth(args[1:])
	case "send":
		return runSend(args[1:])
	case "domain":
		return runDomain(args[1:])
	case "account":
		return runAccount(args[1:])
	case "help", "-h", "--help":
		usage()
		return cli.ExitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		usage()
		return cli.ExitUsage
	}
}

func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dataDir := fs.String("data-dir", config.DefaultDataDir, "data directory")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}

	cfg, err := config.InitLayout(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "initialized %s (config %s)\n", cfg.DataDir, cfg.ConfigPath())
	return cli.ExitOK
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", filepath.Join(config.DefaultDataDir, "config.json"), "config file path")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: load config: %v\n", err)
		return cli.ExitError
	}

	logger := log.New(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a, err := app.Open(ctx, logger, cfg)
	if err != nil {
		logger.Error("open failed", slog.Any("err", err))
		return cli.ExitError
	}

	if err := a.Run(ctx); err != nil {
		logger.Error("shutdown error", slog.Any("err", err))
		return cli.ExitError
	}
	return cli.ExitOK
}

func runSeed(args []string) int {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", filepath.Join(config.DefaultDataDir, "config.json"), "config file path")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	dir, closeStore, err := openDirectory(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	acc, err := directory.SeedDev(ctx, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed: %v\n", err)
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "seeded alice@localhost account_id=%d password=%s\n", acc.ID, directory.SeedPassword())
	return cli.ExitOK
}

func runAuth(args []string) int {
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", filepath.Join(config.DefaultDataDir, "config.json"), "config file path")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(os.Stderr, "usage: beaver auth [-config path] email password")
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	dir, closeStore, err := openDirectory(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	p, err := dir.Authenticate(ctx, rest[0], rest[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth: %v\n", err)
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "ok email=%s account_id=%d domain_id=%d\n", p.Email(), p.AccountID, p.DomainID)
	return cli.ExitOK
}

func runSend(args []string) int {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", filepath.Join(config.DefaultDataDir, "config.json"), "config file path")
	from := fs.String("from", "sender@example.com", "MAIL FROM address")
	to := fs.String("to", "", "recipient address")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	body := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if *to == "" || body == "" {
		fmt.Fprintln(os.Stderr, "usage: beaver send [-config path] -from addr -to addr message...")
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	queue := mail.NewQueue(store, blob.NewFS(cfg.BlobDir()))
	raw := mail.BuildSimpleMessage(*from, *to, body)
	id, err := queue.Enqueue(ctx, *from, []string{*to}, raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send: %v\n", err)
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "queued id=%d to=%s\n", id, *to)
	return cli.ExitOK
}

func runDomain(args []string) int {
	if len(args) == 0 {
		domainUsage()
		return cli.ExitUsage
	}
	switch args[0] {
	case "add":
		return runDomainAdd(args[1:])
	case "list":
		return runDomainList(args[1:])
	default:
		domainUsage()
		return cli.ExitUsage
	}
}

func runDomainAdd(args []string) int {
	fs := flag.NewFlagSet("domain add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", filepath.Join(config.DefaultDataDir, "config.json"), "config file path")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 1 {
		fmt.Fprintln(os.Stderr, "usage: beaver domain add [-config path] <name>")
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domain add: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	dir, closeStore, err := openDirectory(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domain add: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	dom, created, err := dir.EnsureDomain(ctx, directory.DefaultTenantID, fs.Args()[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "domain add: %v\n", err)
		return cli.ExitError
	}
	if created {
		fmt.Fprintf(os.Stderr, "domain_id=%d name=%s\n", dom.ID, dom.Name)
	} else {
		fmt.Fprintf(os.Stderr, "domain_id=%d name=%s unchanged\n", dom.ID, dom.Name)
	}
	return cli.ExitOK
}

func runDomainList(args []string) int {
	fs := flag.NewFlagSet("domain list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", filepath.Join(config.DefaultDataDir, "config.json"), "config file path")
	asJSON := fs.Bool("json", false, "emit JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "usage: beaver domain list [-config path] [--json]")
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domain list: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	dir, closeStore, err := openDirectory(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domain list: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	list, err := dir.ListDomains(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domain list: %v\n", err)
		return cli.ExitError
	}
	if *asJSON {
		rows := make([]domainJSON, len(list))
		for i, dom := range list {
			rows[i] = domainJSON{ID: dom.ID, Name: dom.Name, TenantID: dom.TenantID}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(os.Stderr, "domain list: %v\n", err)
			return cli.ExitError
		}
		return cli.ExitOK
	}
	for _, dom := range list {
		fmt.Fprintf(os.Stderr, "domain_id=%d name=%s tenant_id=%d\n", dom.ID, dom.Name, dom.TenantID)
	}
	return cli.ExitOK
}

func runAccount(args []string) int {
	if len(args) == 0 {
		accountUsage()
		return cli.ExitUsage
	}
	switch args[0] {
	case "create":
		return runAccountCreate(args[1:])
	default:
		accountUsage()
		return cli.ExitUsage
	}
}

func runAccountCreate(args []string) int {
	fs := flag.NewFlagSet("account create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", filepath.Join(config.DefaultDataDir, "config.json"), "config file path")
	domainName := fs.String("domain", "", "mail domain name")
	localPart := fs.String("local", "", "mailbox local part")
	password := fs.String("password", "", "account password")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 {
		accountCreateUsage()
		return cli.ExitUsage
	}
	if *domainName == "" || *localPart == "" || *password == "" {
		accountCreateUsage()
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account create: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	dir, closeStore, err := openDirectory(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account create: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	dom, err := dir.LookupDomain(ctx, *domainName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account create: %v\n", err)
		return cli.ExitError
	}
	acc, err := dir.CreateAccount(ctx, dom.ID, *localPart, *password)
	if err != nil {
		if errors.Is(err, directory.ErrExists) {
			fmt.Fprintf(os.Stderr, "account create: account already exists\n")
		} else {
			fmt.Fprintf(os.Stderr, "account create: %v\n", err)
		}
		return cli.ExitError
	}
	email := acc.LocalPart + "@" + dom.Name
	fmt.Fprintf(os.Stderr, "account_id=%d email=%s domain_id=%d\n", acc.ID, email, dom.ID)
	return cli.ExitOK
}

type domainJSON struct {
	ID       uint32 `json:"id"`
	Name     string `json:"name"`
	TenantID uint32 `json:"tenant_id"`
}

func openDirectory(ctx context.Context, cfg *config.Config) (*directory.Local, func(), error) {
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	return directory.NewLocal(store), closeStore, nil
}

func openStore(ctx context.Context, cfg *config.Config) (storage.Store, func(), error) {
	store, err := sqlite.Open(ctx, cfg.StorePath())
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
	}
	return store, func() { _ = store.Close() }, nil
}

func domainUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  beaver domain add [-config path] <name>")
	fmt.Fprintln(os.Stderr, "  beaver domain list [-config path] [--json]")
}

func accountUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	accountCreateUsage()
}

func accountCreateUsage() {
	fmt.Fprintln(os.Stderr, "  beaver account create [-config path] -domain name -local part -password pw")
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  beaver version")
	fmt.Fprintln(os.Stderr, "  beaver init [-data-dir data]")
	fmt.Fprintln(os.Stderr, "  beaver serve [-config data/config.json]")
	fmt.Fprintln(os.Stderr, "  beaver seed [-config data/config.json]")
	fmt.Fprintln(os.Stderr, "  beaver auth [-config path] email password")
	fmt.Fprintln(os.Stderr, "  beaver send [-config path] -from addr -to addr message...")
	fmt.Fprintln(os.Stderr, "  beaver domain add [-config path] <name>")
	fmt.Fprintln(os.Stderr, "  beaver domain list [-config path] [--json]")
	fmt.Fprintln(os.Stderr, "  beaver account create [-config path] -domain name -local part -password pw")
}
