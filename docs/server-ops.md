# Running the server (operator)

## Logging

`log_level` in `config.json` (or `BEAVER_LOG_LEVEL`): `debug`, `info` (default), `warn`, `error`. Lines go to stderr and, with `log.file`, to a rotating JSON file under `data_dir`.

SMTP lines worth grepping (`grep -E 'smtp (reply|accepted|connect)'`):

| Message | Level | Fields | Meaning |
|---------|-------|--------|---------|
| `smtp accepted` | info | `ip`, `from`, `rcpts`, `size`, `submission` | Message accepted (stored locally and/or queued) |
| `smtp reply` | info | `ip`, `cmd`, `from`, `reply`, `submission` | Every `4xx`/`5xx` sent to a client: greylist, unknown user, filter verdict, relay denied, failed AUTH |
| `smtp connect` | debug | `ip`, `submission` | New connection |
| `queue rcpt failed` | warn | `queue_id`, `rcpt`, `err` | Outbound attempt failed; retried per `queue.retry_intervals` |

`cmd` keeps the argument only for `MAIL` and `RCPT`; `AUTH` arguments (credentials) are never logged.

No `smtp connect` line at all for a sender (with `log_level: debug`) means its mail never reaches Beaver: check DNS MX, firewall, and the sender's bounce.

A panic while serving one session is logged as `smtp session panic` / `imap session panic` with a stack trace; only that session ends.

## Trace headers (RFC 5321 §4.4)

Every accepted message (inbound and submission) gets this hop on top:

```text
Received: from client.example.org (client.example.org [192.0.2.10])
	by mx.example.com (BeaverMail) with ESMTPS id 18e0319b67a8bbd0.1defb.3
	(version=TLS 1.3 cipher=TLS_AES_128_GCM_SHA256)
	for <user@example.com>; Tue, 20 Oct 2026 12:00:02 +0200
```

`with` is `SMTP` (HELO), `ESMTP`, `ESMTPS` (TLS), `ESMTPA`/`ESMTPSA` (authenticated); `id` is the transaction id also used on the filter wire; `for` appears for a single recipient. Copies delivered to a local mailbox also get `Return-Path: <envelope sender>` (any `Return-Path` the message carried is replaced); relayed copies do not. A message already carrying more than 50 `Received` fields is rejected with `554 5.4.6` (mail loop).

## Queue history

`queue.keep_completed` (default `7d`, `"0"` deletes at once) keeps delivered and failed entries in the admin UI Completed tab and in `beaver queue list -all`. Each recipient shows `last_diag`: the last error, or the accepting server's reply once delivered (e.g. `mx.example.org:25: 250 2.0.0 OK ...`).

## Shutdown and restart

On `SIGTERM`/`SIGINT` Beaver stops accepting connections, then:

- IMAP sessions (including IDLE) get `* BYE [UNAVAILABLE] Server shutting down`;
- SMTP sessions waiting for a command get `421 4.3.2 <hostname> Service shutting down`;
- a command already running completes first, then the TLS connection closes with `close_notify`.

Sessions get up to 5 s; the process exits after at most ~7 s. Clients see an orderly close and can reconnect silently. A `DATA` transfer cut by shutdown gets no `250`, so the sender retries; no mail is lost.

With systemd, keep `TimeoutStopSec` at 10 s or more so the drain is not cut short. To bind ports below 1024 as a non-root user, add `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

## systemd

[`contrib/systemd/beaver.service`](../contrib/systemd/beaver.service) is a ready example: dedicated `beavermail` user, `CAP_NET_BIND_SERVICE` for low ports, `Restart=on-failure` (Beaver exits non-zero when a listener fails), `TimeoutStopSec=15s` for the drain, and a sandbox where only `/var/lib/beavermail` is writable. Install steps are in the file header. Plugins run from `<data_dir>/plugins` under the same sandbox (Unix sockets in `<data_dir>/run/plugins`). Plugin-only config changes need no restart: `beaver filter reload`.
