# BeaverMail

Complete mail and collaboration server in Go. One deploy for SMTP, IMAP, POP3, JMAP, CalDAV, CardDAV, WebDAV, and antispam.

## Status

**Work in progress.** BeaverMail is under active development and is **not ready for production use**. APIs, configuration, and behavior will change without notice.

## Build

`beaver init` writes `/etc/beavermail/config.json` with data under `/var/lib/beavermail` (override with `-c`/`BEAVER_CONFIG` and `-data-dir`/`BEAVER_DATA_DIR`). Pass `-hostname mail.example.com` on a dedicated server: ACME certificate for that name, admin UI on `:443`, `:80` for ACME challenges and redirects, and public mail ports (SMTP `:25`, submission `:587`/`:465`, IMAP `:143`/`:993`). Without it everything stays on loopback dev ports and the admin UI listens on `127.0.0.1:8080` (use an SSH tunnel, `ssh -L 8080:127.0.0.1:8080 host`, or a reverse proxy).

For local development, keep everything in the tree:

```bash
make beaver          # embeds admin UI (needs Node)
./beaver version
export BEAVER_CONFIG=data/config.json
./beaver init -data-dir data
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
