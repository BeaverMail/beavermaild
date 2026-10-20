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
	"text/tabwriter"

	"github.com/BeaverMail/beaver/internal/app"
	"github.com/BeaverMail/beaver/internal/cli"
	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/log"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/pluginhost"
	plugincli "github.com/BeaverMail/beaver/internal/pluginhost/cli"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/storage/openstore"
	"github.com/BeaverMail/beaver/internal/storage/xfer"
	"github.com/BeaverMail/beaver/plugin"
)

const version = "0.0.0-dev"

// configFlag registers -c with DefaultConfigPath (BEAVER_CONFIG or /etc/beavermail/config.json).
func configFlag(fs *flag.FlagSet) *string {
	return fs.String("c", config.DefaultConfigPath(), "config file path")
}

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
	case "migrate":
		return runMigrate(args[1:])
	case "store":
		return runStore(args[1:])
	case "serve":
		return runServe(args[1:])
	case "seed":
		return runSeed(args[1:])
	case "auth":
		return runAuth(args[1:])
	case "send":
		return runSend(args[1:])
	case "queue":
		return runQueue(args[1:])
	case "domain":
		return runDomain(args[1:])
	case "account":
		return runAccount(args[1:])
	case "plugins":
		return runPlugins(args[1:])
	case "help", "-h", "--help":
		usage()
		return cli.ExitOK
	default:
		if code, ok := plugincli.TryDispatch(context.Background(), plugincli.DispatchOptions{
			Args:          args,
			BeaverVersion: version,
		}); ok {
			return code
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		usage()
		return cli.ExitUsage
	}
}

func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	defDataDir := config.DefaultDataDir
	if v := os.Getenv("BEAVER_DATA_DIR"); v != "" {
		defDataDir = v
	}
	dataDir := fs.String("data-dir", defDataDir, "data directory")
	hostname := fs.String("hostname", "", "public hostname: ACME certificate, admin UI on :443 (:80 for challenges)")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}

	cfg, err := config.InitLayout(*configPath, *dataDir, *hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "initialized %s (config %s)\n", cfg.DataDir, cfg.ConfigPath())
	// Written elsewhere via -c: other commands still read DefaultConfigPath unless told otherwise.
	if def := config.DefaultConfigPath(); filepath.Clean(def) != filepath.Clean(cfg.ConfigPath()) {
		fmt.Fprintf(os.Stderr, "note: commands read %s by default; use: export BEAVER_CONFIG=%s (or -c)\n", def, cfg.ConfigPath())
	}

	// Apply KV schema for the configured driver (sqlite file or MySQL/MariaDB tables).
	ctx := context.Background()
	if err := migrateStore(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "init: migrate store: %v\n", err)
		return cli.ExitError
	}
	return cli.ExitOK
}

// runMigrate opens the configured store so pending schema migrations run (idempotent).
func runMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	if err := migrateStore(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return cli.ExitError
	}
	return cli.ExitOK
}

// migrateStore opens the KV backend (Open runs Migrate) and reports driver + schema version.
func migrateStore(ctx context.Context, cfg *config.Config) error {
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore()

	version, err := storeSchemaVersion(ctx, store)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "store ready driver=%s schema=%d\n", cfg.StoreDriver(), version)
	return nil
}

// storeSchemaVersion reads _beaver_schema_version when the concrete store exposes it.
func storeSchemaVersion(ctx context.Context, store storage.Store) (int, error) {
	type versioned interface {
		SchemaVersion(context.Context) (int, error)
	}
	if v, ok := store.(versioned); ok {
		return v.SchemaVersion(ctx)
	}
	return storage.SchemaVersion, nil
}

// runStore dispatches beaver store export|import.
func runStore(args []string) int {
	if len(args) == 0 {
		storeUsage()
		return cli.ExitUsage
	}
	switch args[0] {
	case "export":
		return runStoreExport(args[1:])
	case "import":
		return runStoreImport(args[1:])
	case "help", "-h", "--help":
		storeUsage()
		return cli.ExitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown store command: %s\n", args[0])
		storeUsage()
		return cli.ExitUsage
	}
}

func storeUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  beaver store export [-c path] -o file|-")
	fmt.Fprintln(os.Stderr, "  beaver store import [-c path] -i file|- [--force]")
}

// runStoreExport dumps all KV rows (BEAVERKV1) to -o (file or stdout).
func runStoreExport(args []string) int {
	fs := flag.NewFlagSet("store export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	outPath := fs.String("o", "", "output path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if strings.TrimSpace(*outPath) == "" {
		fmt.Fprintln(os.Stderr, "store export: -o is required")
		storeUsage()
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store export: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store export: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	out, err := openOutput(*outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store export: %v\n", err)
		return cli.ExitError
	}
	defer func() {
		if out != os.Stdout {
			_ = out.Close()
		}
	}()

	n, err := xfer.Export(ctx, store, out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store export: %v\n", err)
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "exported %d keys driver=%s\n", n, cfg.StoreDriver())
	return cli.ExitOK
}

// runStoreImport loads a BEAVERKV1 dump into the configured store.
func runStoreImport(args []string) int {
	fs := flag.NewFlagSet("store import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	inPath := fs.String("i", "", "input path, or - for stdin")
	force := fs.Bool("force", false, "upsert into a non-empty store")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if strings.TrimSpace(*inPath) == "" {
		fmt.Fprintln(os.Stderr, "store import: -i is required")
		storeUsage()
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store import: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store import: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	in, err := openInput(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store import: %v\n", err)
		return cli.ExitError
	}
	defer func() {
		if in != os.Stdin {
			_ = in.Close()
		}
	}()

	n, err := xfer.Import(ctx, store, in, xfer.ImportOptions{Force: *force})
	if err != nil {
		fmt.Fprintf(os.Stderr, "store import: %v\n", err)
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "imported %d keys driver=%s\n", n, cfg.StoreDriver())
	return cli.ExitOK
}

// openOutput returns a writable file or os.Stdout when path is "-".
func openOutput(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdout, nil
	}
	return os.Create(path)
}

// openInput returns a readable file or os.Stdin when path is "-".
func openInput(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdin, nil
	}
	return os.Open(path)
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
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
	configPath := configFlag(fs)
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
	configPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(os.Stderr, "usage: beaver auth [-c path] email password")
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
	configPath := configFlag(fs)
	from := fs.String("from", "sender@example.com", "MAIL FROM address")
	to := fs.String("to", "", "recipient address")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	body := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if *to == "" || body == "" {
		fmt.Fprintln(os.Stderr, "usage: beaver send [-c path] -from addr -to addr message...")
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

func runQueue(args []string) int {
	if len(args) == 0 {
		queueUsage()
		return cli.ExitUsage
	}
	switch args[0] {
	case "list":
		return runQueueList(args[1:])
	default:
		queueUsage()
		return cli.ExitUsage
	}
}

func runQueueList(args []string) int {
	fs := flag.NewFlagSet("queue list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	all := fs.Bool("all", false, "include entries with no pending recipients")
	asJSON := fs.Bool("json", false, "emit JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "usage: beaver queue list [-c path] [-all] [-json]")
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "queue list: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "queue list: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	queue := mail.NewQueue(store, blob.NewFS(cfg.BlobDir()))
	var entries []mail.QueueEntry
	if *all {
		entries, err = queue.ListAll(ctx)
	} else {
		entries, err = queue.ListPending(ctx)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "queue list: %v\n", err)
		return cli.ExitError
	}

	if *asJSON {
		rows := make([]queueJSON, len(entries))
		for i, e := range entries {
			rows[i] = queueEntryJSON(e)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(os.Stderr, "queue list: %v\n", err)
			return cli.ExitError
		}
		return cli.ExitOK
	}

	for _, e := range entries {
		pending := 0
		for _, rcpt := range e.Msg.Recipients {
			if mail.RecipientStatus(rcpt) == "pending" {
				pending++
			}
		}
		fmt.Fprintf(os.Stderr, "queue_id=%d return_path=%s size=%d created=%d recipients=%d pending=%d\n",
			e.ID, e.Msg.ReturnPath, e.Msg.Size, e.Msg.Created, len(e.Msg.Recipients), pending)
		for _, rcpt := range e.Msg.Recipients {
			fmt.Fprintf(os.Stderr, "  to=%s retry=%d status=%s next_due_ms=%d last_attempt_ms=%d\n",
				rcpt.Address, rcpt.Retry, mail.RecipientStatus(rcpt), rcpt.NextDue, rcpt.LastAttempt)
		}
	}
	return cli.ExitOK
}

type queueJSON struct {
	ID         uint32          `json:"id"`
	ReturnPath string          `json:"return_path"`
	Size       uint64          `json:"size"`
	Created    uint64          `json:"created"`
	Recipients []queueRcptJSON `json:"recipients"`
}

type queueRcptJSON struct {
	Address       string `json:"address"`
	Retry         uint32 `json:"retry"`
	Status        string `json:"status"`
	NextDueMS     int64  `json:"next_due_ms"`
	LastAttemptMS int64  `json:"last_attempt_ms"`
}

func queueEntryJSON(e mail.QueueEntry) queueJSON {
	rcpts := make([]queueRcptJSON, len(e.Msg.Recipients))
	for i, rcpt := range e.Msg.Recipients {
		rcpts[i] = queueRcptJSON{
			Address:       rcpt.Address,
			Retry:         rcpt.Retry,
			Status:        mail.RecipientStatus(rcpt),
			NextDueMS:     rcpt.NextDue,
			LastAttemptMS: rcpt.LastAttempt,
		}
	}
	return queueJSON{
		ID:         e.ID,
		ReturnPath: e.Msg.ReturnPath,
		Size:       e.Msg.Size,
		Created:    e.Msg.Created,
		Recipients: rcpts,
	}
}

func queueUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  beaver queue list [-c path] [-all] [-json]")
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
	case "delete":
		return runDomainDelete(args[1:])
	default:
		domainUsage()
		return cli.ExitUsage
	}
}

func runDomainAdd(args []string) int {
	fs := flag.NewFlagSet("domain add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 1 {
		fmt.Fprintln(os.Stderr, "usage: beaver domain add [-c path] <name>")
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
	configPath := configFlag(fs)
	asJSON := fs.Bool("json", false, "emit JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "usage: beaver domain list [-c path] [-json]")
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

func runDomainDelete(args []string) int {
	fs := flag.NewFlagSet("domain delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 1 {
		fmt.Fprintln(os.Stderr, "usage: beaver domain delete [-c path] <name>")
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domain delete: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	dir, inbox, closeStore, err := openMail(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "domain delete: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	res, err := dir.DeleteDomain(ctx, fs.Args()[0], inbox.Blobs())
	if err != nil {
		fmt.Fprintf(os.Stderr, "domain delete: %v\n", err)
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "deleted domain_id=%d name=%s accounts_deleted=%d\n",
		res.Domain.ID, res.Domain.Name, res.AccountsDeleted)
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
	case "info":
		return runAccountInfo(args[1:])
	case "list":
		return runAccountList(args[1:])
	case "delete":
		return runAccountDelete(args[1:])
	case "set-role":
		return runAccountSetRole(args[1:])
	default:
		accountUsage()
		return cli.ExitUsage
	}
}

func runAccountCreate(args []string) int {
	fs := flag.NewFlagSet("account create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	domainName := fs.String("domain", "", "mail domain name")
	localPart := fs.String("local", "", "mailbox local part")
	password := fs.String("password", "", "account password")
	role := fs.String("role", directory.RoleUser, "directory role: user, admin, or tenant_admin")
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
	acc, err := dir.CreateAccountRole(ctx, dom.ID, *localPart, *password, *role)
	if err != nil {
		if errors.Is(err, directory.ErrExists) {
			fmt.Fprintf(os.Stderr, "account create: account already exists\n")
		} else {
			fmt.Fprintf(os.Stderr, "account create: %v\n", err)
		}
		return cli.ExitError
	}
	email := acc.LocalPart + "@" + dom.Name
	fmt.Fprintf(os.Stderr, "account_id=%d email=%s domain_id=%d tenant_id=%d role=%s\n",
		acc.ID, email, dom.ID, acc.TenantID, acc.Role)
	return cli.ExitOK
}

func runAccountInfo(args []string) int {
	fs := flag.NewFlagSet("account info", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	email := fs.String("email", "", "account email address")
	asJSON := fs.Bool("json", false, "emit JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 || *email == "" {
		accountInfoUsage()
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account info: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	dir, inbox, closeStore, err := openMail(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account info: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	acc, dom, err := dir.ResolveEmail(ctx, *email)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "account info: account not found\n")
		} else {
			fmt.Fprintf(os.Stderr, "account info: %v\n", err)
		}
		return cli.ExitError
	}
	fullEmail := acc.LocalPart + "@" + dom.Name

	summaries, err := inbox.ListMailboxSummaries(ctx, acc.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account info: %v\n", err)
		return cli.ExitError
	}
	tree := mail.BuildFolderTree(summaries)

	if *asJSON {
		out := accountInfoJSON{
			AccountID: acc.ID,
			Email:     fullEmail,
			DomainID:  dom.ID,
			TenantID:  acc.TenantID,
			Role:      directory.NormalizeRole(acc.Role),
			Folders:   make([]accountFolderJSON, len(tree)),
		}
		for i, line := range tree {
			out.Folders[i] = accountFolderJSON{
				Path:     line.Path,
				Depth:    line.Depth,
				Messages: line.Messages,
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "account info: %v\n", err)
			return cli.ExitError
		}
		return cli.ExitOK
	}

	fmt.Fprintf(os.Stderr, "account_id=%d email=%s domain_id=%d tenant_id=%d role=%s\n",
		acc.ID, fullEmail, dom.ID, acc.TenantID, directory.NormalizeRole(acc.Role))
	w := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	for _, line := range tree {
		indent := strings.Repeat("  ", line.Depth)
		fmt.Fprintf(w, "%s%s\t%d\n", indent, line.Segment, line.Messages)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "account info: %v\n", err)
		return cli.ExitError
	}
	return cli.ExitOK
}

func runAccountList(args []string) int {
	fs := flag.NewFlagSet("account list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	domainName := fs.String("domain", "", "mail domain name")
	asJSON := fs.Bool("json", false, "emit JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 || *domainName == "" {
		accountListUsage()
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account list: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	dir, closeStore, err := openDirectory(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account list: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	accounts, dom, err := dir.ListAccounts(ctx, *domainName)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "account list: domain not found\n")
		} else {
			fmt.Fprintf(os.Stderr, "account list: %v\n", err)
		}
		return cli.ExitError
	}
	if *asJSON {
		rows := make([]accountListJSON, len(accounts))
		for i, acc := range accounts {
			rows[i] = accountListJSON{
				AccountID: acc.ID,
				Email:     acc.LocalPart + "@" + dom.Name,
				DomainID:  dom.ID,
				Active:    acc.Active,
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(os.Stderr, "account list: %v\n", err)
			return cli.ExitError
		}
		return cli.ExitOK
	}
	for _, acc := range accounts {
		email := acc.LocalPart + "@" + dom.Name
		fmt.Fprintf(os.Stderr, "account_id=%d email=%s domain_id=%d active=%t\n",
			acc.ID, email, dom.ID, acc.Active)
	}
	return cli.ExitOK
}

func runAccountDelete(args []string) int {
	fs := flag.NewFlagSet("account delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	email := fs.String("email", "", "account email address")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 || *email == "" {
		accountDeleteUsage()
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account delete: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	dir, inbox, closeStore, err := openMail(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account delete: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	res, err := dir.DeleteAccount(ctx, *email, inbox.Blobs())
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "account delete: account not found\n")
		} else {
			fmt.Fprintf(os.Stderr, "account delete: %v\n", err)
		}
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "deleted account_id=%d email=%s messages_removed=%d blobs_removed=%d\n",
		res.Account.ID, res.Email, res.MessagesRemoved, res.BlobsRemoved)
	return cli.ExitOK
}

type accountListJSON struct {
	AccountID uint32 `json:"account_id"`
	Email     string `json:"email"`
	DomainID  uint32 `json:"domain_id"`
	Active    bool   `json:"active"`
}

type accountInfoJSON struct {
	AccountID uint32              `json:"account_id"`
	Email     string              `json:"email"`
	DomainID  uint32              `json:"domain_id"`
	TenantID  uint32              `json:"tenant_id"`
	Role      string              `json:"role"`
	Folders   []accountFolderJSON `json:"folders"`
}

type accountFolderJSON struct {
	Path     string `json:"path"`
	Depth    int    `json:"depth"`
	Messages uint32 `json:"messages"`
}

func runPlugins(args []string) int {
	if len(args) == 0 {
		pluginsUsage()
		return cli.ExitUsage
	}
	switch args[0] {
	case "list":
		return runPluginsList(args[1:])
	default:
		pluginsUsage()
		return cli.ExitUsage
	}
}

func runPluginsList(args []string) int {
	fs := flag.NewFlagSet("plugins list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}

	pluginsDir := pluginhost.PluginsDirFromConfigPath(*configPath)
	reg, err := pluginhost.LoadRegistry(pluginsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugins list: %v\n", err)
		return cli.ExitError
	}
	for _, skipErr := range reg.Skipped() {
		fmt.Fprintf(os.Stderr, "skipped %v\n", skipErr)
	}
	for _, e := range reg.List() {
		exe, err := reg.ResolveExe(e)
		status := "ok"
		if err != nil {
			status = err.Error()
		}
		fmt.Fprintf(os.Stderr, "command=%s exe=%s capabilities=%s cli_flags=%s status=%s api_version=%d\n",
			strings.Join(e.Command, " "), e.Exe, strings.Join(e.Capabilities, ","), formatCliFlags(e.CliFlags), status, plugin.APIVersion)
		_ = exe
	}
	if len(reg.List()) == 0 {
		fmt.Fprintf(os.Stderr, "no plugins in %s\n", pluginsDir)
	}
	return cli.ExitOK
}

// formatCliFlags lists descriptor flag names for plugins list output.
func formatCliFlags(flags []plugin.CliFlag) string {
	if len(flags) == 0 {
		return "-"
	}
	names := make([]string, len(flags))
	for i, f := range flags {
		names[i] = f.Flag
	}
	return strings.Join(names, ",")
}

func pluginsUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  beaver plugins list [-c path]")
}

type domainJSON struct {
	ID       uint32 `json:"id"`
	Name     string `json:"name"`
	TenantID uint32 `json:"tenant_id"`
}

func openMail(ctx context.Context, cfg *config.Config) (*directory.Local, *mail.Inbox, func(), error) {
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	dir := directory.NewLocal(store)
	inbox := mail.NewInbox(store, blob.NewFS(cfg.BlobDir()))
	return dir, inbox, closeStore, nil
}

func openDirectory(ctx context.Context, cfg *config.Config) (*directory.Local, func(), error) {
	store, closeStore, err := openStore(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	return directory.NewLocal(store), closeStore, nil
}

func openStore(ctx context.Context, cfg *config.Config) (storage.Store, func(), error) {
	store, err := openstore.OpenConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
	}
	return store, func() { _ = store.Close() }, nil
}

func domainUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  beaver domain add [-c path] <name>")
	fmt.Fprintln(os.Stderr, "  beaver domain list [-c path] [-json]")
	fmt.Fprintln(os.Stderr, "  beaver domain delete [-c path] <name>")
}

func accountUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	accountCreateUsage()
	accountListUsage()
	accountInfoUsage()
	accountDeleteUsage()
	accountSetRoleUsage()
}

func accountCreateUsage() {
	fmt.Fprintln(os.Stderr, "  beaver account create [-c path] -domain name -local part -password pw [-role user|admin|tenant_admin]")
}

func accountListUsage() {
	fmt.Fprintln(os.Stderr, "  beaver account list [-c path] -domain name [-json]")
}

func accountInfoUsage() {
	fmt.Fprintln(os.Stderr, "  beaver account info [-c path] -email addr [-json]")
}

func accountDeleteUsage() {
	fmt.Fprintln(os.Stderr, "  beaver account delete [-c path] -email addr")
}

func accountSetRoleUsage() {
	fmt.Fprintln(os.Stderr, "  beaver account set-role [-c path] -email addr -role user|admin|tenant_admin")
}

func runAccountSetRole(args []string) int {
	fs := flag.NewFlagSet("account set-role", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	email := fs.String("email", "", "account email address")
	role := fs.String("role", "", "directory role: user, admin, or tenant_admin")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 || *email == "" || *role == "" {
		accountSetRoleUsage()
		return cli.ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account set-role: load config: %v\n", err)
		return cli.ExitError
	}

	ctx := context.Background()
	dir, closeStore, err := openDirectory(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "account set-role: %v\n", err)
		return cli.ExitError
	}
	defer closeStore()

	acc, dom, err := dir.ResolveEmail(ctx, *email)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "account set-role: account not found\n")
			return cli.ExitError
		}
		fmt.Fprintf(os.Stderr, "account set-role: %v\n", err)
		return cli.ExitError
	}
	if err := dir.SetAccountRole(ctx, acc.ID, *role); err != nil {
		fmt.Fprintf(os.Stderr, "account set-role: %v\n", err)
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "account_id=%d email=%s@%s role=%s\n",
		acc.ID, acc.LocalPart, dom.Name, directory.NormalizeRole(*role))
	return cli.ExitOK
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  beaver version")
	fmt.Fprintln(os.Stderr, "  beaver init [-c path] [-data-dir dir] [-hostname name]")
	fmt.Fprintln(os.Stderr, "  beaver migrate [-c path]")
	fmt.Fprintln(os.Stderr, "  beaver store export [-c path] -o file|-")
	fmt.Fprintln(os.Stderr, "  beaver store import [-c path] -i file|- [--force]")
	fmt.Fprintln(os.Stderr, "  beaver serve [-c path]")
	fmt.Fprintln(os.Stderr, "  beaver seed [-c path]")
	fmt.Fprintln(os.Stderr, "  beaver auth [-c path] email password")
	fmt.Fprintln(os.Stderr, "  beaver send [-c path] -from addr -to addr message...")
	fmt.Fprintln(os.Stderr, "  beaver queue list [-c path] [-all] [-json]")
	fmt.Fprintln(os.Stderr, "  beaver domain add [-c path] <name>")
	fmt.Fprintln(os.Stderr, "  beaver domain list [-c path] [-json]")
	fmt.Fprintln(os.Stderr, "  beaver domain delete [-c path] <name>")
	fmt.Fprintln(os.Stderr, "  beaver account create [-c path] -domain name -local part -password pw [-role user|admin|tenant_admin]")
	fmt.Fprintln(os.Stderr, "  beaver account list [-c path] -domain name [-json]")
	fmt.Fprintln(os.Stderr, "  beaver account info [-c path] -email addr [-json]")
	fmt.Fprintln(os.Stderr, "  beaver account set-role [-c path] -email addr -role user|admin|tenant_admin")
	fmt.Fprintln(os.Stderr, "  beaver account delete [-c path] -email addr")
	fmt.Fprintln(os.Stderr, "  beaver plugins list [-c path]")
	printPluginUsageLines()
}

// printPluginUsageLines lists installed CLI plugin commands (same paths as plugins list).
func printPluginUsageLines() {
	reg, err := pluginhost.LoadRegistry(pluginhost.PluginsDirFromConfigPath(config.DefaultConfigPath()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "  beaver <plugin-command> ...  (plugins: error loading registry)")
		return
	}
	entries := reg.CLIEntries()
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "  (no plugins installed)")
		return
	}
	for _, e := range entries {
		fmt.Fprintf(os.Stderr, "  beaver %s ...\n", strings.Join(e.Command, " "))
	}
}
