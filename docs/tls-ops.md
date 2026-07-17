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
| Outbound MX | queue worker | Opportunistic STARTTLS + PKIX verify (default) |
| Outbound relay | `smtp.relay` | Optional STARTTLS (`relay_starttls`) |
| MTA-STS | outbound MX | When policy is `enforce`: mandatory STARTTLS + PKIX |

Without `tls.cert_file`/`tls.key_file` or `tls.acme_hosts`, STARTTLS is not advertised and implicit TLS listeners do not start.

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

### ACME (TLS-ALPN-01)

```json
{
  "tls": {
    "acme_hosts": ["mail.example.com"],
    "acme_cache_dir": "tls/acme",
    "min_version": "1.2"
  }
}
```

- Challenge: **TLS-ALPN-01** only (no HTTP-01 listener).
- Cache default: `<data_dir>/tls/acme`.
- The host must reach Beaver on **443** for the ACME hostname (or terminate TLS-ALPN elsewhere and present the same certs as PEM).

Do not set both PEM and ACME unless you intend ACME to win (app prefers ACME when `acme_hosts` is non-empty).

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
| ACME HTTP-01 | Use TLS-ALPN-01 or external PEM |
| Force TLS on SMTP `:25` via `tls.required` | Use network policy or wait for a dedicated inbound flag |

## Smoke

- IMAP/SMTP TLS: `tests/integration/submission_smoke.sh` (STARTTLS + `:465`)
- Unit coverage: `internal/smtp/server_tls_test.go`, `internal/imap/server_tls_test.go`
