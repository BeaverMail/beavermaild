# TLS (operator)

How Beaver loads certificates and where TLS is required or optional on IMAP/SMTP. Protocol filter field `tls` is documented in [plugins-smtp-daemon.md](plugins-smtp-daemon.md).

## Quick map

| Role | Listener | TLS mode |
|------|----------|----------|
| IMAP plain | `imap.listen` (default `127.0.0.1:1143`) | Optional STARTTLS when certs loaded |
| IMAP implicit | `imap.tls_listen` (e.g. `:993`) | TLS from first byte |
| SMTP inbound | `smtp.listen` (default `127.0.0.1:2525`) | Optional STARTTLS when certs loaded |
| SMTP submission | `smtp.submission_listen` (e.g. `:587`) | STARTTLS; **AUTH and MAIL require TLS** |
| SMTP submission implicit | `smtp.submission_tls_listen` (e.g. `:465`) | TLS from first byte |
| HTTP admin/API | `http.listen` | TLS unless loopback |
| HTTP cleartext | `http.plain_listen` (e.g. `:80`) | Plain; ACME HTTP-01 + 301 to HTTPS only |
| Outbound MX | queue worker | Opportunistic STARTTLS + PKIX verify (default) |
| Outbound relay | `smtp.relay` | Optional STARTTLS (`relay_starttls`) |
| MTA-STS | outbound MX | When policy is `enforce`: mandatory STARTTLS + PKIX |

STARTTLS and implicit TLS listeners are always available: without `tls.cert_file`/`tls.key_file`, Beaver serves a self-signed certificate generated once under `<data_dir>/tls/self/`. Fine for server-to-server STARTTLS (opportunistic, unverified); mail clients will warn, so give them a real certificate.

Certificate choice per connection (by SNI): per-domain custom PEM → issued ACME cert → `tls.cert_file` → self-signed.

## Certificates

### PEM files

```json
{
  "tls": {
    "cert_file": "tls/fullchain.pem",
    "key_file": "tls/privkey.pem",
    "min_version": "1.2"
  }
}
```

Paths are relative to `data_dir` unless absolute. `min_version` accepts `1.2` or `1.3` (default `1.2`).

The files are re-read when their mtime changes (checked at most once a minute), so a certificate renewed by Caddy, certbot or similar is picked up without a restart. A broken file at startup is fatal; a broken file during a reload is logged and the previous certificate stays.

### ACME

One ACME manager covers `tls.acme_hosts` plus the mail hostname of every domain with `ssl_mode: acme` (read from the directory, so new domains need no restart).

```json
{
  "tls": { "acme_hosts": ["mail.example.com"], "acme_cache_dir": "tls/acme" },
  "http": { "enabled": true, "listen": "0.0.0.0:443", "plain_listen": "0.0.0.0:80" }
}
```

- Issuance runs in the background: at startup, after a domain is created or edited, and hourly (new hosts, retries). Renewal is automatic. A failure is logged and never stops Beaver; the host keeps the fallback certificate until issuance succeeds.
- Handshakes never trigger issuance, so clients are not blocked and Let's Encrypt is not hammered.
- Challenges: **HTTP-01** on `http.plain_listen` (or `http.listen` behind a proxy), **TLS-ALPN-01** on any TLS listener reachable on 443.
- Cache default: `<data_dir>/tls/acme`.

#### Dedicated server

Beaver owns 80/443: set `http.plain_listen: ":80"` and `http.listen: ":443"` as above.

#### Behind Caddy (or another web server on 80/443)

Either:

1. Let Beaver issue: enable `http` on loopback (`127.0.0.1:8080`, no `plain_listen`) and proxy the challenge path to it. The `http://` site address keeps Caddy from managing a certificate for that host itself.
   ```
   http://mail.example.com {
       reverse_proxy /.well-known/acme-challenge/* 127.0.0.1:8080
   }
   ```
2. Reuse the proxy's certificate: point `tls.cert_file`/`tls.key_file` at the files it renews; Beaver reloads them on change. Leave `acme_hosts` empty.

## `tls.required`

```json
"tls": { "required": true }
```

**IMAP:** when true and the connection is not yet TLS, CAPABILITY includes `LOGINDISABLED` and LOGIN/AUTHENTICATE are rejected until STARTTLS (or use `imap.tls_listen`).

**SMTP:** the flag is passed into the session today but **does not** force STARTTLS on plain inbound `:25`. Submission already requires TLS before AUTH/MAIL regardless of this flag.

## Typical production listeners

```json
{
  "tls": {
    "cert_file": "tls/fullchain.pem",
    "key_file": "tls/privkey.pem",
    "required": true
  },
  "smtp": {
    "listen": "0.0.0.0:25",
    "submission_listen": "0.0.0.0:587",
    "submission_tls_listen": "0.0.0.0:465"
  },
  "imap": {
    "listen": "0.0.0.0:143",
    "tls_listen": "0.0.0.0:993"
  }
}
```

MUA tip: prefer submission `:465` or `:587`+STARTTLS, and IMAP `:993` or `:143`+STARTTLS. Keep `:25` for server-to-server inbound.

## Outbound TLS

### Direct MX

1. Connect plain to MX.
2. If EHLO offers `STARTTLS`, upgrade.
3. Verify the server certificate (PKIX) by default.

Disable verify only for lab/self-signed:

```json
"smtp": {
  "outbound_tls_insecure_skip_verify": true
}
```

Env: `BEAVER_SMTP_OUTBOUND_TLS_INSECURE=1`.

A failed STARTTLS handshake fails the delivery attempt (no silent plaintext fallback after a failed upgrade).

### Relay

```json
"smtp": {
  "relay": "smtp.example.com:587",
  "relay_starttls": true,
  "relay_user": "user",
  "relay_password": "secret"
}
```

Env: `BEAVER_SMTP_RELAY_STARTTLS=1`.

### MTA-STS (RFC 8461)

Outbound client is **on by default**. Policy mode `enforce` filters MX and requires STARTTLS with PKIX verify (overrides insecure skip for that delivery).

```json
"smtp": {
  "mta_sts": { "disable": false }
}
```

Env: `BEAVER_SMTP_MTA_STS_DISABLE=1` to turn off.

Not implemented: publishing an inbound MTA-STS policy, TLS-RPT, or treating policy mode `testing` as enforce.

## Not implemented (intentional / P2)

| Item | Notes |
|------|--------|
| DANE (RFC 7672) | Needs DNSSEC; backlog `smtp-dane` |
| REQUIRETLS (RFC 8689) | Not advertised until enforced |
| Force TLS on SMTP `:25` via `tls.required` | Use network policy or wait for a dedicated inbound flag |

## Smoke

- IMAP/SMTP TLS: `tests/integration/submission_smoke.sh` (STARTTLS + `:465`)
- Unit coverage: `internal/smtp/server_tls_test.go`, `internal/imap/server_tls_test.go`
