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
- `rbl` with optional `client_ip_zones` / `domain_zones` / `url_zones`
- `static` deny lists and tag names
- `spam_rules_url`, `url_redirects` (HTTPS only; private IPs blocked)

CLI: `beaver filter status`, `beaver filter reload`, `beaver filter scan -account ...`.

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

When `enabled` is true and no sub-toggle is set, SPF/DKIM/DMARC/ARC all turn on. Results appear on the wire as `auth` (`spf_ehlo`, `spf_mail_from`, `dkim`, `dmarc`, `dmarc_policy`, `arc`). The plugin maps them to `SPF_*` / `DKIM_*` / `DMARC_*` / `ARC_*` tags.

Inbound ARC is **verify only** (no outbound seal). ARC does **not** override a DMARC fail.

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
