# Antispam and inbound SMTP policy (operator)

This note covers **host** settings that feed the antispam plugin wire, plus where plugin policy lives. Protocol details: [plugins-smtp-daemon.md](plugins-smtp-daemon.md). Tag/score semantics: [`.specs/antispam.md`](../.specs/antispam.md) (local specs tree).

## Pieces

| Piece | Where | Default |
|-------|--------|---------|
| Plugin policy (scores, RBL, rules, traps) | `<data_dir>/antispam/config.json` | Copy from `cmd/beaver-plugin-antispam/examples/config.json.example` |
| Mail-auth verify (SPF/DKIM/DMARC/ARC) | Host `mail_auth` in `config.json` | Off until `mail_auth.enabled` |
| Greylist | Host `smtp.greylist` | **Off** |
| ASN / country at connect | Host `smtp.asn_lookup` | **Off** |

Greylist and ASN run in the SMTP core. The plugin only sees the results on the filter wire (`asn`, `country`, and auth fields). Reloading antispam rules (`beaver filter reload`) does **not** change greylist or ASN; restart `beaver serve` after editing those host keys.

## Plugin config

```text
<data_dir>/antispam/config.json
```

Example: `cmd/beaver-plugin-antispam/examples/config.json.example`. After edits, run `beaver filter reload` (or touch `<data_dir>/antispam/.reload`).

Useful knobs:

- `thresholds` / `scores` / `tag_actions` (e.g. `GTUBE_TEST` -> `reject`)
- `rbl` with optional `client_ip_zones` / `domain_zones` / `url_zones`; `rbl.spamhaus_dqs_key` (see below)
- `static` deny lists and tag names
- `spam_rules_url`, `url_redirects` (HTTPS only; private IPs blocked)

CLI: `beaver filter status`, `beaver filter reload`, `beaver filter scan -account ...`.

### Spamhaus (public mirrors vs DQS)

`zen.spamhaus.org` / `dbl.spamhaus.org` answer only queries from your own resolver. Through public resolvers (8.8.8.8, 1.1.1.1, many provider resolvers) they reply `127.255.255.254` instead of a verdict. Check on the server:

```bash
dig +short 2.0.0.127.zen.spamhaus.org   # expect 127.0.0.2
```

If that fails, either run a local resolver (e.g. `unbound`) or register for the free Spamhaus DQS key and set:

```json
"rbl": { "enabled": true, "client_ip_zones": ["zen.spamhaus.org"], "spamhaus_dqs_key": "YOUR_KEY" }
```

With a key, every `*.spamhaus.org` zone (`zen`, `dbl`, ...) is queried as `<key>.<zone>.dq.spamhaus.net`; tags keep the public name (`RBL_ZEN`, `RBL_DBL`), so scores need no change and the key never appears in `X-Spam-*` headers. Register for a key on Spamhaus's Data Query Service page (free for non-commercial, low-volume use).

DNSBL error replies count as a DNS failure, handled by `rbl.on_dns_fail` (default `accept`), never as a listing:

| Reply | Meaning |
|-------|---------|
| `127.255.255.252` | Typo in the zone name |
| `127.255.255.254` | Query through a public/open resolver (use a local resolver or DQS) |
| `127.255.255.255` | Excessive number of queries |
| `127.0.1.255` | DBL queried with an IP address instead of a domain |

Without this, a public resolver would make every client IP "listed" and, with `hard_reject.rbl_on_connect` (on by default), reject all inbound mail.

### Which replies count as a listing (`rbl.zone_codes`)

Per zone (public name), only the listed A records count; others are ignored. Entries are a single address or a last-octet range (`127.0.2.2-24`). Zones without an entry count any `127.x` reply. Built-in defaults, merged with your config:

| Zone | Codes counted | Not counted |
|------|---------------|-------------|
| `zen.spamhaus.org` | `127.0.0.2` SBL, `.3` SBL CSS, `.4-7` XBL, `.9` DROP, `.10`/`.11` PBL | anything else |
| `dbl.spamhaus.org` | `127.0.1.2` spam, `.4` phish, `.5` malware, `.6` botnet C&C | `127.0.1.102-106` abused legit domains (compromised sites, redirectors) |
| `zrd.spamhaus.org` | `127.0.2.2-24` (domain registered 2-24 h ago) | |

Example: only very young domains from ZRD:

```json
"rbl": { "domain_zones": ["dbl.spamhaus.org", "zrd.spamhaus.org"], "zone_codes": { "zrd.spamhaus.org": ["127.0.2.2-6"] } }
```

### What is checked where

| Check | Zones | Inbound (`:25`) | Submission (`:587`/`:465`) |
|-------|-------|-----------------|----------------------------|
| Client IP, at connect and EOM | `client_ip_zones` | yes (`hard_reject.rbl_on_connect` rejects) | **no**: users connect from home/mobile IPs listed in PBL, before authenticating |
| Envelope sender domain, HELO name | `domain_zones` | yes | no (our own users' domains) |
| Domains of addresses/URLs in the message | `domain_zones` / `url_zones` | yes | yes |

Domains are reduced to the registered domain (`mail.example.com` -> `example.com`) and skipped when in the trusted-domains list. All checks share `max_checks_per_message`.

## Mail-auth (`mail_auth`)

```json
{
  "mail_auth": {
    "enabled": true,
    "dns_timeout_ms": 5000,
    "spf": { "enabled": true },
    "dkim": { "enabled": true },
    "dmarc": { "enabled": true },
    "arc": { "enabled": true }
  }
}
```

When `enabled` is true and no sub-toggle is set, SPF/DKIM/DMARC/ARC all turn on. Checks run on inbound mail only: on submission they would judge the authenticated client's IP (e.g. an application server outside your SPF record) while the message leaves from this server with its DKIM signature, so the plugin gets no `auth` fields there. Results appear on the wire as `auth` (`spf_ehlo`, `spf_mail_from`, `dkim`, `dmarc`, `dmarc_policy`, `arc`). The plugin maps them to `SPF_*` / `DKIM_*` / `DMARC_*` / `ARC_*` tags.

Inbound ARC is **verify only** (no outbound seal). ARC does **not** override a DMARC fail.

### `Authentication-Results` (RFC 8601)

Every inbound (non-submission) message is verified, whether or not the antispam filter runs for its domain, and gets one header on top, with `smtp.hostname` as authserv-id:

```text
Authentication-Results: mx.example.com;
	spf=pass smtp.mailfrom=sender@example.org;
	dkim=pass header.d=example.org;
	dmarc=pass header.from=example.org;
	arc=none
```

Existing `Authentication-Results` fields that claim the same authserv-id are removed first (RFC 8601 §5), so a sender cannot forge a local verdict. Fields from other servers are kept. Nothing is added while `mail_auth.enabled` is false, or for authenticated submission.

## Headers added by the antispam plugin

Accepted messages get SpamAssassin-style headers, which mail clients (Thunderbird: "trust junk mail headers set by SpamAssassin") and Sieve rules understand:

| Header | Example | Notes |
|--------|---------|-------|
| `X-Spam-Flag` | `YES` | Only when `score >= thresholds.spam` |
| `X-Spam-Score` | `1.4` | Total score |
| `X-Spam-Level` | `*` | One `*` per whole point (omitted below 1) |
| `X-Spam-Status` | `No, score=1.4 required=5.0 tests=HELO_IPREV_MISMATCH,RCVD_COUNT_ZERO` | |
| `X-Spam-Result` | `HELO_IPREV_MISMATCH (1.00), RCVD_COUNT_ZERO (0.10)` | Per-rule weights, for debugging |

Sieve example: `if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; }`.

## Greylist (`smtp.greylist`)

Persistent triplet (client IP, MAIL FROM, RCPT TO) at **RCPT** for unauthenticated **inbound** (not submission, not SMTP AUTH). First hit: `452 4.2.2 Try again later`. After `min_delay_sec`, the same triplet is accepted.

```json
{
  "smtp": {
    "greylist": {
      "enabled": true,
      "min_delay_sec": 300,
      "max_age_sec": 129600
    }
  }
}
```

| Field | Default when enabled |
|-------|----------------------|
| `min_delay_sec` | 300 (5 minutes) |
| `max_age_sec` | 129600 (36 hours) |

State lives in the main store. Requires serve restart to enable/disable.

## ASN lookup (`smtp.asn_lookup`)

Optional Team Cymru-style DNS TXT at connect. Populates wire `asn` / `country`; the plugin may emit `SOURCE_ASN_{id}`. Fail-open on DNS errors. Loopback and private client IPs are skipped. In-memory TTL cache limits repeat queries.

```json
{
  "smtp": {
    "asn_lookup": {
      "enabled": true,
      "timeout_ms": 2000,
      "zone_ipv4": "origin.asn.cymru.com",
      "zone_ipv6": "origin6.asn.cymru.com",
      "cache_ttl_sec": 86400,
      "cache_ttl_miss_sec": 900,
      "cache_max_entries": 10000
    }
  }
}
```

There is no built-in "ham ASN" allowlist. Operators may score `SOURCE_ASN_*` in plugin `scores`, or reject via `tag_actions`. Coarse public spam ASN lists (e.g. Spamhaus ASN-DROP) are optional add-ons, not shipped defaults.

## Smoke test

`tests/integration/antispam_smoke.sh` covers ham delivery, subject-regex reject, GTUBE hard reject, and greylist 452 then retry.
