// beaver alias: manage local aliases (delivery to mailboxes of the same tenant).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/BeaverMail/beaver/internal/cli"
	"github.com/BeaverMail/beaver/internal/directory"
)

func runAlias(args []string) int {
	if len(args) == 0 {
		aliasUsage()
		return cli.ExitUsage
	}
	switch args[0] {
	case "add":
		return runAliasAdd(args[1:])
	case "list":
		return runAliasList(args[1:])
	case "set":
		return runAliasSet(args[1:])
	case "delete":
		return runAliasDelete(args[1:])
	default:
		aliasUsage()
		return cli.ExitUsage
	}
}

// splitTargets parses a comma-separated -to list.
func splitTargets(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func printAlias(a directory.AliasView) {
	fmt.Fprintf(os.Stderr, "alias=%s targets=%s\n", a.Email, strings.Join(a.Targets, ","))
}

func runAliasAdd(args []string) int {
	fs := flag.NewFlagSet("alias add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	domainName := fs.String("domain", "", "mail domain name")
	localPart := fs.String("local", "", "alias local part")
	to := fs.String("to", "", "comma-separated target mailboxes (same tenant)")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 || *domainName == "" || *localPart == "" || *to == "" {
		aliasUsage()
		return cli.ExitUsage
	}
	ctx := context.Background()
	dir, closeStore, ok := openCLIDirectory(ctx, "alias add", *configPath)
	if !ok {
		return cli.ExitError
	}
	defer closeStore()
	a, err := dir.CreateAlias(ctx, *domainName, *localPart, splitTargets(*to))
	if err != nil {
		if errors.Is(err, directory.ErrExists) {
			fmt.Fprintf(os.Stderr, "alias add: address already used by a mailbox or alias\n")
		} else {
			fmt.Fprintf(os.Stderr, "alias add: %v\n", err)
		}
		return cli.ExitError
	}
	printAlias(a)
	return cli.ExitOK
}

type aliasJSON struct {
	Email   string   `json:"email"`
	Targets []string `json:"targets"`
}

func runAliasList(args []string) int {
	fs := flag.NewFlagSet("alias list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	domainName := fs.String("domain", "", "mail domain name")
	asJSON := fs.Bool("json", false, "emit JSON on stdout")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 || *domainName == "" {
		aliasUsage()
		return cli.ExitUsage
	}
	ctx := context.Background()
	dir, closeStore, ok := openCLIDirectory(ctx, "alias list", *configPath)
	if !ok {
		return cli.ExitError
	}
	defer closeStore()
	aliases, _, err := dir.ListAliases(ctx, *domainName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "alias list: %v\n", err)
		return cli.ExitError
	}
	if *asJSON {
		rows := make([]aliasJSON, len(aliases))
		for i, a := range aliases {
			rows[i] = aliasJSON{Email: a.Email, Targets: a.Targets}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(os.Stderr, "alias list: %v\n", err)
			return cli.ExitError
		}
		return cli.ExitOK
	}
	for _, a := range aliases {
		printAlias(a)
	}
	return cli.ExitOK
}

func runAliasSet(args []string) int {
	fs := flag.NewFlagSet("alias set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	email := fs.String("email", "", "alias address")
	to := fs.String("to", "", "comma-separated target mailboxes (replaces all)")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 || *email == "" || *to == "" {
		aliasUsage()
		return cli.ExitUsage
	}
	ctx := context.Background()
	dir, closeStore, ok := openCLIDirectory(ctx, "alias set", *configPath)
	if !ok {
		return cli.ExitError
	}
	defer closeStore()
	a, err := dir.SetAliasTargets(ctx, *email, splitTargets(*to))
	if err != nil {
		fmt.Fprintf(os.Stderr, "alias set: %v\n", err)
		return cli.ExitError
	}
	printAlias(a)
	return cli.ExitOK
}

func runAliasDelete(args []string) int {
	fs := flag.NewFlagSet("alias delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := configFlag(fs)
	email := fs.String("email", "", "alias address")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if len(fs.Args()) != 0 || *email == "" {
		aliasUsage()
		return cli.ExitUsage
	}
	ctx := context.Background()
	dir, closeStore, ok := openCLIDirectory(ctx, "alias delete", *configPath)
	if !ok {
		return cli.ExitError
	}
	defer closeStore()
	if err := dir.DeleteAlias(ctx, *email); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "alias delete: no alias %s\n", *email)
		} else {
			fmt.Fprintf(os.Stderr, "alias delete: %v\n", err)
		}
		return cli.ExitError
	}
	fmt.Fprintf(os.Stderr, "deleted alias=%s\n", *email)
	return cli.ExitOK
}

func aliasUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	printAliasUsageLines()
}

func printAliasUsageLines() {
	fmt.Fprintln(os.Stderr, "  beaver alias add [-c path] -domain name -local part -to a@x,b@y")
	fmt.Fprintln(os.Stderr, "  beaver alias list [-c path] -domain name [-json]")
	fmt.Fprintln(os.Stderr, "  beaver alias set [-c path] -email addr -to a@x,b@y")
	fmt.Fprintln(os.Stderr, "  beaver alias delete [-c path] -email addr")
}
