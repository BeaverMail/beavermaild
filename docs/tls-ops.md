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
| Outbound MX | queue worker | Opportunistic STARTTLS, certificate not verified (RFC 7435) |
| Outbound relay | `smtp.relay` | Optional STARTTLS (`relay_starttls`), PKIX verify |
| MTA-STS | outbound MX | When policy is `enforce`: mandatory STARTTLS + PKIX |

STARTTLS and implicit TLS listeners are always available: without `tls.cert_file`/`tls.key_file`, Beaver serves a self-signed certificate generated once under `<data_dir>/tls/self/`. Fine for server-to-server STARTTLS (opportunistic, unverified); mail clients will warn, so give them a real certificate.

Certificate choice per connection (by SNI): per-domain custom PEM → issued ACME cert → `tls.cert_file` → self-signed.

Server certificates must use an ECDSA key or an RSA key of at least 2048 bits and must not be signed
with SHA-1 or MD5 (RFC 9325 4.5): a `tls.cert_file` that fails this stops startup, a per-domain PEM is
refused when uploaded (`400`) and skipped with a warning if already on disk.

### Protocol settings (RFC 9325)

TLS 1.2 and 1.3 only. In TLS 1.2 every listener and every verified client connection (relay, MTA-STS,
`smtp.tls_policy`, policy fetch) uses AEAD suites only: ECDHE with AES-GCM or ChaCha20-Poly1305; CBC
suites are refused because crypto/tls lacks encrypt_then_mac. Opportunistic delivery to an MX keeps
Go's defaults, CBC included, since the alternative is no delivery (RFC 9325 5.2).

ALPN is strict where a protocol name is registered: IMAP listeners (143, 993) negotiate only `imap` and
the HTTPS API only `http/1.1`, so a client offering another protocol is refused (ALPACA cross-protocol
attacks; clients that send no ALPN are unaffected). SMTP has no registered ALPN name. The HTTPS API sends
`Strict-Transport-Security: max-age=31536000`.

Not done, by limits of Go's crypto/tls: revocation checking of the certificates our clients verify
(no CRL or OCSP), and aborting a TLS 1.2 handshake with a server that lacks `renegotiation_info`. An
unknown SNI name gets the fallback certificate instead of an `unrecognized_name` alert, as RFC 8461
requires for SMTP.

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
"tls": { "required": false }
```

Default **true** (RFC 8314 4: cleartext mail access is deprecated). On IMAP without TLS, CAPABILITY
includes `LOGINDISABLED` and LOGIN/AUTHENTICATE are rejected until STARTTLS (or use `imap.tls_listen`),
before the credentials are looked at. Set it `false` only for legacy clients on a trusted network; the
server then logs a warning at startup.

**SMTP:** submission always requires TLS before AUTH/MAIL, whatever this flag says; port 25 never
requires it (see `smtp.require_starttls_from`).

At startup the server also warns when only its self-signed certificate is available: mail clients
reject it (RFC 8314 4.4), so set `tls.cert_file`, `tls.acme_hosts` or a per-domain certificate.

Logs of accepted mail, SMTP rejections and IMAP errors carry `tls` (version and cipher suite, or
`none`), and the `Received` field of mail taken over TLS ends with the RFC 8314 `tls <cipher suite>`
clause.

## Typical production listeners

```json
{
  "tls": {
    "cert_file": "tls/fullchain.pem",
    "key_file": "tls/privkey.pem",
    "required": true
  },
  "smtp": {
    "hostname": "mx.example.com",
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

`smtp.hostname` is the SMTP banner and outbound EHLO name, and the authserv-id of `Authentication-Results`. It must match the PTR record of the server IP (receivers such as Gmail compare them). Unset, it falls back to the first `tls.acme_hosts` entry, then the machine hostname; `beaver init -hostname` sets it.

MUA tip: prefer submission `:465` or `:587`+STARTTLS, and IMAP `:993` or `:143`+STARTTLS. Keep `:25` for server-to-server inbound.

### Requiring STARTTLS from selected senders (port 25)

A public MX must accept mail in clear (RFC 3207 4), so `tls.required` never applies to port 25. To
require TLS from known peers only (a partner, an internal relay), list their addresses:

```json
"smtp": {
  "require_starttls_from": ["192.0.2.0/24", "2001:db8::25"]
}
```

Those clients get `530 5.7.0 Must issue a STARTTLS command first` to every command but EHLO, NOOP,
STARTTLS and QUIT until they upgrade. Everyone else is unaffected.

## Outbound TLS

### Direct MX

1. Connect plain to MX.
2. If EHLO offers `STARTTLS`, upgrade (TLS 1.2 or later: TLS 1.0/1.1 must not be used, RFC 8996; an
   MX offering nothing newer is skipped like an unreachable one).
3. The certificate is **not** verified: any MX that can encrypt gets the mail encrypted (RFC 7435
   opportunistic security, as Postfix `may`). A certificate for another name, self-signed or expired
   does not block delivery. Mail to a domain with an MTA-STS `enforce` policy is the exception: there the
   certificate must be valid for the MX name, with TLS 1.2 or later (see below).

An MX that advertises STARTTLS but refuses the command (e.g. `454 TLS not available`) gets the message
in clear on the same session, as Postfix `may` does (RFC 7435: cleartext is the baseline); not under
MTA-STS `enforce`. A failed TLS handshake fails that MX instead: the next MX is tried and the message
stays queued (no plaintext retry after a failed handshake).

### Required TLS per destination

`smtp.tls_policy` requires TLS to the MX of chosen recipient domains (RFC 3207 6; Postfix
`smtp_tls_policy_maps`):

```json
"smtp": {
  "tls_policy": {
    "partner.example": "verify",
    "legacy.example": "encrypt"
  }
}
```

- `encrypt`: STARTTLS mandatory (TLS 1.2+), certificate not checked.
- `verify`: as `encrypt`, and the certificate must be valid for the MX host name. The MX name comes
  from DNS, so without DNSSEC this guards against a passive attacker and a misdirected connection, not
  against forged MX records (MTA-STS or DANE do that).
- `secure`: as `encrypt`, and the certificate must chain to a trusted root and be valid for the
  recipient domain or one of its subdomains (Postfix `secure`): `partner.example` accepts a certificate
  for `partner.example`, `mx1.partner.example` or `*.partner.example`. It does not trust the MX name
  from DNS (RFC 9325 7.1), so a forged MX record cannot pass; an MX hosted under another domain
  (e.g. a hosting provider) fails unless its certificate also names the recipient domain.

Without STARTTLS, after a refused STARTTLS or a failed handshake, the MX is skipped and the message
stays queued: it never goes in clear. With an MTA-STS `enforce` policy the stricter of the two applies.
The policy is for direct MX delivery; a relay has its own settings.

### Relay

The relay (`smtp.relay`) certificate is verified (PKIX, TLS 1.2+). Disable verify only for a
lab/self-signed relay:

```json
"smtp": {
  "outbound_tls_insecure_skip_verify": true
}
```

Env: `BEAVER_SMTP_OUTBOUND_TLS_INSECURE=1`. It has no effect on direct MX delivery.

Direct MX delivery never connects to loopback, private (RFC 1918, `fc00::/7`), link-local or unspecified
addresses: a remote domain whose MX points there fails permanently. For a LAN where other domains' MX
really are private hosts, allow it:

```json
"smtp": {
  "outbound_allow_private": true
}
```

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

With `relay_starttls` set, a relay that does not offer STARTTLS is an error (no silent plaintext session:
that is what a STARTTLS-stripping attacker would cause). `relay_user`/`relay_password` are sent only over
TLS, except to a relay on the loopback interface (`127.0.0.1`, `::1`, `localhost`).

### MTA-STS (RFC 8461)

Outbound client is **on by default**. Policy mode `enforce` filters MX and requires STARTTLS with PKIX verify and TLS 1.2+. A failure leaves the message queued (the policy is looked up again at each retry, and a cached policy survives a missing or broken `_mta-sts` record or policy file). Modes `testing` and `none` deliver as without a policy.

```json
"smtp": {
  "mta_sts": { "disable": false }
}
```

Env: `BEAVER_SMTP_MTA_STS_DISABLE=1` to turn off.

Policies are cached in `<data_dir>/mta-sts-cache.json`, so they survive a restart. Every cached policy
is fetched again 5 minutes after startup and then daily; a failed refresh logs `mta-sts: policy refresh
failed` (with the expiry of the cached policy), except for mode `none`. After a failed fetch the same
policy id is not fetched again for 5 minutes. The cache holds at most 10000 domains (the least recently
fetched goes first); a policy with more than 100 `mx` lines is ignored.

Through a relay (global `smtp.relay` or per-domain), the relay host name is the policy domain
(RFC 8461 3.4): under `enforce` the relay must match the policy `mx`, offer STARTTLS and present a valid
certificate, whatever `relay_starttls` and `outbound_tls_insecure_skip_verify` say. Relays given as an IP
address or on loopback have no policy.

Not implemented: publishing an inbound MTA-STS policy, TLS-RPT.

## Not implemented (intentional / P2)

| Item | Notes |
|------|--------|
| DANE (RFC 7672) | Needs DNSSEC; backlog `smtp-dane` |
| REQUIRETLS (RFC 8689) | Not advertised until enforced |
| Force TLS on SMTP `:25` for every client | Forbidden for a public MX (RFC 3207 4); use `smtp.require_starttls_from` for selected peers |

## Smoke

- IMAP/SMTP TLS: `tests/integration/submission_smoke.sh` (STARTTLS + `:465`)
- Unit coverage: `internal/smtp/server_tls_test.go`, `internal/imap/server_tls_test.go`
