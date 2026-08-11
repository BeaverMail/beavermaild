# BeaverMail

Complete mail and collaboration server in Go. One deploy for SMTP, IMAP, POP3, JMAP, CalDAV, CardDAV, WebDAV, and antispam.

## Status

**Work in progress.** BeaverMail is under active development and is **not ready for production use**. APIs, configuration, and behavior will change without notice.

## Build

Default config path is `/etc/beavermail/config.json`. For local development, point at the tree created by `init`:

```bash
make beaver          # embeds admin UI (needs Node)
./beaver version
./beaver init
export BEAVER_CONFIG=data/config.json
./beaver seed
./beaver auth alice@localhost beaver
./beaver serve
```

Or pass `-c` per command: `./beaver -c data/config.json seed`

Inbound SMTP listens on `127.0.0.1:1025` by default (`smtp.listen` in config.json, or `BEAVER_SMTP_LISTEN`). After `seed`, deliver a test message:

```bash
# swaks, or any SMTP client
swaks --to alice@localhost --from sender@example.com --server 127.0.0.1 --port 1025 --body "hello"

# minimal netcat session
printf 'EHLO test\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<alice@localhost>\r\nDATA\r\nSubject: hi\r\n\r\nhello\r\n.\r\nQUIT\r\n' | nc 127.0.0.1 1025
```

Messages are stored under the data dir (`store.sqlite` metadata, `blobs/` raw RFC 5322 bytes).

IMAP listens on `127.0.0.1:1143` by default (`imap.listen` or `BEAVER_IMAP_LISTEN`). After delivering mail, read INBOX:

```bash
printf 'a1 LOGIN alice@localhost beaver\r\na2 SELECT INBOX\r\na3 FETCH 1 BODY[]\r\na4 LOGOUT\r\n' | nc 127.0.0.1 1143
```

Outbound mail uses a queue drained by `beaver serve` (local recipients go to INBOX; set `smtp.relay` or `BEAVER_SMTP_RELAY` for remote). Enqueue manually:

```bash
./beaver send -from sender@example.com -to alice@localhost hello via queue
```

Queue retry uses a fixed interval table (`queue.retry_intervals`): `2m, 5m, 10m, 15m, 30m, 1h, 2h, 24h, 3d` by default; `max_lifetime` 3d; worker poll `run_delay` 1s. Override in `config.json`:

```json
"queue": { "run_delay": "5s" }
```

Or set `BEAVER_QUEUE_RUN_DELAY=5s` for faster local testing.

## License

MIT. See [LICENSE](LICENSE).
