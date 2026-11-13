# Running the server (operator)

## Logging

`log_level` in `config.json` (or `BEAVER_LOG_LEVEL`): `debug`, `info` (default), `warn`, `error`. Lines go to stderr and, with `log.file`, to a rotating JSON file under `data_dir`.

SMTP lines worth grepping (`grep -E 'smtp (reply|accepted|connect)'`):

| Message | Level | Fields | Meaning |
|---------|-------|--------|---------|
| `smtp accepted` | info | `ip`, `from`, `rcpts`, `size`, `submission`, `tls` | Message accepted (stored locally and/or queued) |
| `smtp reply` | info | `ip`, `cmd`, `from`, `reply`, `submission`, `tls` | Every `4xx`/`5xx` sent to a client: greylist, unknown user, filter verdict, relay denied, failed AUTH |
| `smtp connect` | debug | `ip`, `submission` | New connection |
| `queue rcpt failed` | warn | `queue_id`, `rcpt`, `err` | Outbound attempt failed; retried per `queue.retry_intervals` |

`tls` is the TLS version and cipher suite (`TLS 1.3 TLS_AES_128_GCM_SHA256`) or `none` (RFC 8314 4). `cmd` keeps the argument only for `MAIL` and `RCPT`; `AUTH` arguments (credentials) are never logged.

No `smtp connect` line at all for a sender (with `log_level: debug`) means its mail never reaches Beaver: check DNS MX, firewall, and the sender's bounce.

A panic while serving one session is logged as `smtp session panic` / `imap session panic` with a stack trace; only that session ends.

## Trace headers (RFC 5321 §4.4)

Every accepted message (inbound and submission) gets this hop on top:

```text
Received: from client.example.org (client.example.org [192.0.2.10])
	by mx.example.com (BeaverMail) with ESMTPS id 18e0319b67a8bbd0.1defb.3
	for <user@example.com>
	tls TLS_AES_128_GCM_SHA256 (TLS 1.3); Tue, 20 Oct 2026 12:00:02 +0200
```

`with` is `SMTP` (HELO), `ESMTP`, `ESMTPS` (TLS), `ESMTPA`/`ESMTPSA` (authenticated); `id` is the transaction id also used on the filter wire; `for` appears for a single recipient; `tls` (RFC 8314 4.3) names the cipher suite when the message came over TLS. Copies delivered to a local mailbox also get `Return-Path: <envelope sender>` (any `Return-Path` the message carried is replaced); relayed copies do not. A message already carrying more than 50 `Received` fields is rejected with `554 5.4.6` (mail loop).

## Connection and session limits (SMTP)

| Setting / limit | Default | Effect |
|---|---|---|
| `smtp.max_connections` | 200 per listener (`-1` unlimited) | further connections get `421 4.7.0 Too many connections` |
| `smtp.max_connections_per_ip` | 20 (`-1` unlimited) | port 25 only: concurrent sessions of one IPv4 address or IPv6 /64; more get `421 4.7.0 Too many connections from your address`. Loopback is exempt. **Behind a remote TCP proxy or load balancer** every client has the proxy's address (no PROXY protocol support): set `-1` there |
| MAIL commands per inbound session | 1000 | then `421 4.7.0 Too many transactions` and the session ends |
| MAIL commands that delivered nothing | 10 | same: a MAIL/RSET loop with throwaway sender domains only makes the server query the DNS |
| unknown recipients (when they outnumber good ones) | 10 | `421 4.7.0 Too many invalid recipients` (address harvesting) |
| unrecognized commands | 10 | `421 4.7.0 Too many unrecognized commands` |

Each inbound `MAIL FROM` costs DNS work chosen by the sender (SPF, null MX check, 5 s timeout each);
the limits above bound it per connection and per address. Null MX answers are cached for an hour;
only well-formed sender domains are checked.

## Authentication-Results (RFC 8601)

Inbound mail gets an `Authentication-Results: <smtp.hostname>; ...` field above our `Received`, with
the SPF, DKIM, DMARC and ARC results. Reported domains are checked before they are written (a domain
name, or an IP literal in quotes; anything else is left out), SPF reports the envelope domain only,
ARC only `none`/`pass`/`fail`. Any `Authentication-Results` field that already claims our hostname is
removed from every accepted message, submission included, even with mail-auth off: downstream filters
and mail clients can trust the field bearing our name.

## Null MX (RFC 7505)

Mail to a domain that publishes a null MX (`MX 0 .`) fails at the first attempt, without retries; the
DSN carries `Status: 5.1.10`. On port 25 a `MAIL FROM` whose domain publishes a null MX gets
`550 5.7.27 Sender address has null MX`: no bounce could reach it. A DNS error or timeout (5 s) on that
check lets the mail through.

DSN `Status` fields carry the remote server's enhanced code (`550 5.1.1` → `5.1.1`), with the class of
the outcome (a `4xx` reply that ends in a failure at expiry is reported as `5.x.x`).

## Submission header fixes (RFC 6409 §8)

On authenticated submission (`:587`/`:465`) a missing or malformed `Message-ID` is added or
replaced (`<random@smtp.hostname>`, §8.3) and a missing or unparsable `Date` is set to the
current time (§8.2). This runs before the antispam filter, so scripts and minimal clients that
omit these fields are not scored for it. Other header fields are left as sent.

A submission that is not valid RFC 5322 mail is refused after the data with `554 5.6.0 Message
rejected: <reason>` (§8, §4.2): no `From` or more than one, a field that may appear once repeated
(`Date`, `Subject`, `To`, …), several `From` mailboxes without `Sender`, an unparsable address field,
or an address whose domain is not fully qualified (hosted domains excepted). Recipients get the same
check in the envelope: a malformed domain gets `501 5.1.3`, a single-label domain `554 5.1.2`. A
`MAIL FROM` the account may not use gets `550 5.7.1` (§6.1).

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

[`contrib/systemd/beavermail.service`](../contrib/systemd/beavermail.service) is a ready example: dedicated `beavermail` user, `CAP_NET_BIND_SERVICE` for low ports, `Restart=on-failure` (Beaver exits non-zero when a listener fails), `TimeoutStopSec=15s` for the drain, and a sandbox where only `/var/lib/beavermail` is writable. Install steps are in the file header. Plugins run from `<data_dir>/plugins` under the same sandbox (Unix sockets in `<data_dir>/run/plugins`). Plugin-only config changes need no restart: `beaver filter reload`.
