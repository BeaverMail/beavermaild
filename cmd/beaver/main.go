// BeaverMail CLI entrypoint. Dispatches subcommands for the mail server binary.
package main

import (
	"fmt"
	"os"
)

const version = "0.0.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

// usage prints supported CLI commands to stderr.
func usage() {
	fmt.Fprintln(os.Stderr, "usage: beaver version")
}
