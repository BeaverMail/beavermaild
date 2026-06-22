// BeaverMail CLI entrypoint. Dispatches subcommands for the mail server binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/BeaverMail/beaver/internal/app"
	"github.com/BeaverMail/beaver/internal/cli"
	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/log"
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  beaver version")
	fmt.Fprintln(os.Stderr, "  beaver init [-data-dir data]")
	fmt.Fprintln(os.Stderr, "  beaver serve [-config data/config.json]")
}
