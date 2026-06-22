# BeaverMail

Complete mail and collaboration server in Go. One deploy for SMTP, IMAP, POP3, JMAP, CalDAV, CardDAV, WebDAV, and antispam.

## Status

**Work in progress.** BeaverMail is under active development and is **not ready for production use**. APIs, configuration, and behavior will change without notice.

## Build

```bash
go build -o beaver ./cmd/beaver
./beaver version
./beaver init
./beaver seed
./beaver auth -config .data/config.json alice@localhost beaver
./beaver serve
```

## License

MIT. See [LICENSE](LICENSE).
