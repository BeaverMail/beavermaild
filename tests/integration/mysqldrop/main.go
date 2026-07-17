// Command mysqldrop drops Beaver KV tables so an e2e smoke can start from an empty schema.
// Usage: go run ./tests/integration/mysqldrop <mysql-dsn>
package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: mysqldrop <dsn>")
		os.Exit(2)
	}
	db, err := sql.Open("mysql", os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	tables := []string{"m", "i", "n", "t", "l", "a", "u", "_beaver_schema_version"}
	for _, name := range tables {
		if _, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS `%s`", name)); err != nil {
			fmt.Fprintf(os.Stderr, "drop %s: %v\n", name, err)
			os.Exit(1)
		}
	}
}
