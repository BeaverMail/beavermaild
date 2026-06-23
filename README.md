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

Inbound SMTP listens on `127.0.0.1:1025` by default (`smtp.listen` in config.json, or `BEAVER_SMTP_LISTEN`). After `seed`, deliver a test message:

```bash
# swaks, or any SMTP client
swaks --to alice@localhost --from sender@example.com --server 127.0.0.1 --port 1025 --body "hello"

# minimal netcat session
printf 'EHLO test\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<alice@localhost>\r\nDATA\r\nSubject: hi\r\n\r\nhello\r\n.\r\nQUIT\r\n' | nc 127.0.0.1 1025
```

Messages are stored under the data dir (`store.sqlite` metadata, `blobs/` raw RFC 5322 bytes).

## License

MIT. See [LICENSE](LICENSE).
