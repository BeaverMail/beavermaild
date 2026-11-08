# Antispam operations

`beaver-plugin-antispam` is an SMTP daemon plugin ([plugins-smtp-daemon.md](plugins-smtp-daemon.md)) that scores
inbound mail the way rspamd does: each check inserts a named symbol with a score, the scores are added up, and the
total picks an action. Symbol names and default scores are rspamd's.

Only the `eom` phase is scored; earlier phases are accepted. Mail from authenticated users and the submission
listener is not scored. Client-IP checks (HELO/rDNS patterns, RBL) are skipped for loopback and private addresses.

## Files

All under `<data_dir>/antispam/` (`/var/lib/beavermail/antispam/` with the Debian package). Examples ship in
`cmd/beaver-plugin-antispam/examples/` and `/usr/share/doc/beavermail/examples/antispam/`.

| File | Content |
|------|---------|
| `config.json` | Plugin settings (below). Absent: defaults. Unknown keys are an error. |
| `spam-traps.txt` | Trap recipients: `user@domain` or `@domain`, one per line, `#` comments |
| `trusted-domains.txt` | Trusted From domains (subdomains included) |
| `url-redirectors.txt` | Redirector hosts followed when `url_redirector.enabled` (the example is rspamd's list) |

## Actions

| Key in `actions` | Default | Effect |
|------------------|---------|--------|
| `reject` | 15 | SMTP 550 |
| `rewrite_subject` | null (off) | Same as `add_header` (the host can only append headers, so the Subject is not changed) |
| `add_header` | 6 | Delivered with `X-Spam-Flag: YES` |
| `greylist` | 4 | 451 until the same message (body hash) or envelope (client /19 or /64, sender, recipients) is retried after `greylist.delay_seconds` (300) and within `greylist.expire_seconds` (86400). In memory: a plugin restart forgets it |

Set a threshold to `null` to disable that action. The highest reached threshold wins.

Every accepted message gets `X-Spam-Status` (`Yes|No, score=S required=T`), `X-Spam-Score`, `X-Spam-Action` and
`X-Spam-Symbols` (`SYMBOL(score)[options]`, truncated at 900 characters). The host appends these headers and does not
strip copies sent by the remote client, so filter on them in delivery rules only together with `X-Spam-Score`
values you trust.

## Settings

| Key | Default | Meaning |
|-----|---------|---------|
| `scores` | `{}` | Per-symbol overrides, e.g. `{"HFILTER_HOSTNAME_UNKNOWN": 1.0, "MISSING_MID": 0}` |
| `gtube` | `reject` | `reject`: the GTUBE `XJS*C4JDBQ...` string rejects. `all`: also `YJS` add header, `ZJS` rewrite subject, `AJS` no action. `disabled` |
| `hfilter.dns_checks` | false | Resolve the HELO, MAIL FROM and Message-ID hosts (`HFILTER_*_NORES_A_OR_MX`, `_NORESOLVE_MX`, `HFILTER_HELO_IP_A`) |
| `rbl.enabled` | false | Spamhaus lookups (below) |
| `rbl.dqs_key` | "" | Spamhaus DQS key; queries go to `<key>.zen.dq.spamhaus.net` / `<key>.dbl.dq.spamhaus.net` |
| `rbl.resolver` | "" | `host:port` of the recursive resolver for RBL queries; empty uses the system resolver |
| `rbl.timeout_ms` | 2000 | Per lookup |
| `rbl.max_lookups` | 24 | Uncached queries per message; further targets are skipped and logged |
| `rbl.cache_seconds` | 3600 | Answer cache, NXDOMAIN included; failures are not cached |
| `rbl.received` | true | Also check up to 4 public IPs from `Received` headers (`RECEIVED_SPAMHAUS_*`) |
| `url_redirector.enabled` | false | Follow links on listed redirector hosts with HEAD requests |
| `url_redirector.max_urls` | 5 | Redirector links followed per message |
| `url_redirector.nested_limit` | 2 | Hops followed; one more redirect scores `URL_REDIRECTOR_NESTED` |
| `url_redirector.timeout_ms` | 4000 | Per hop |
| `spamtrap.action` | "" | `reject` or `discard` mail to a single listed trap; "" only scores `SPAMTRAP` (0) |

Network checks (RBL, redirector, hfilter DNS) are off by default. The plugin answers within 80% of the host
`timeout_ms` (`plugins.smtp.filter_timeout_ms`, default 10000); slow lookups are abandoned, not scored.

### Spamhaus and resolvers

Spamhaus refuses queries arriving through large public resolvers (8.8.8.8, 1.1.1.1, most ISP resolvers) and from
high-volume users of the free mirrors; it answers `127.255.255.254` / `127.255.255.255`. The plugin treats those
codes, DNS errors and timeouts as "no answer": it logs `rbl: Spamhaus refused the query` or `lookup ... failed` on
stderr and never scores them as listings. Use either a local recursive resolver that queries the root servers
itself (`rbl.resolver`, e.g. `127.0.0.1:53` with unbound) or a free/paid DQS key (`rbl.dqs_key`). The key is never
written to message headers or logs.

Client IP and Received IPs are checked against ZEN (`RBL_SPAMHAUS_SBL` 4, `_CSS` 2, `_XBL` 4, `_PBL` 2, `_DROP` 7;
`RECEIVED_SPAMHAUS_*` lower). The envelope and From domains, Reply-To, HELO, PTR and the registrable domain of each
URL are checked against DBL (`DBL_SPAM` 6.5, `DBL_PHISH`/`_MALWARE`/`_BOTNET` 7.5, `DBL_ABUSE*` 5-6.5). Trusted
domains are not queried.

### URL redirector safety

Message links are attacker-controlled. The HTTP client connects only to public unicast addresses on ports 80 and 443
(loopback, private, link-local, CGNAT, documentation and NAT64 ranges are refused after DNS resolution), uses no proxy,
sends HEAD only, does not follow redirects by itself and has per-hop timeouts. Redirect targets are added to the
message URLs, so URL and DBL checks see the final link.

## Checks

| Group | Symbols (rspamd names) |
|-------|------------------------|
| Mail auth (host `mail_auth`) | `R_SPF_*`, `R_DKIM_*`, `DMARC_POLICY_*`, `DMARC_NA`, `ARC_*`; with `trusted-domains.txt`: `WHITELIST_DMARC` (-7), `BLACKLIST_DMARC` (+6) |
| HELO / rDNS | `HFILTER_HELO_BADIP`, `_BAREIP`, `HFILTER_HELO_1..5`, `HFILTER_HOSTNAME_1..5` (dynamic/pool PTR names), `HFILTER_HOSTNAME_UNKNOWN`, `RDNS_NONE`, `RDNS_DNSFAIL` (0) |
| Envelope / links | `HFILTER_FROM_BOUNCE`, `HFILTER_RCPT_BOUNCEMOREONE`, `HFILTER_URL_ONLY`, `HFILTER_URL_ONELINE` |
| Message-ID | `MISSING_MID`, `INVALID_MSGID`, `MID_BARE_IP`, `MID_RHS_NOT_FQDN`, `MID_MISSING_BRACKETS`, `MID_CONTAINS_FROM`, `MID_END_EQ_FROM_USER_PART`, ... |
| Date / Subject | `MISSING_DATE`, `INVALID_DATE`, `DATE_IN_FUTURE`, `DATE_IN_PAST`, `SUBJ_ALL_CAPS`, `LONG_SUBJ`, `FAKE_REPLY`, `SUBJECT_*` |
| Headers | `MISSING_FROM`, `MULTIPLE_FROM`, `FROM_INVALID`, `R_HTTP_URL_IN_FROM`, `*_NEEDS_ENCODING`, `*_EXCESS_BASE64/QP`, `MULTIPLE_UNIQUE_HEADERS`, `MISSING_ESSENTIAL_HEADERS`, `R_UNDISC_RCPT`, `REPLYTO_*`, `HEADER_*_EMPTY_DELIMITER`, `INVALID_FROM_8BIT`, ... |
| MIME / attachments | `MISSING_MIME_VERSION`, `MIME_MA_MISSING_TEXT/HTML`, `CTYPE_MISSING_DISPOSITION`, `MIME_BASE64_TEXT_BOGUS`, `MIME_BAD_EXTENSION`, `MIME_DOUBLE_BAD_EXTENSION`, `MIME_ARCHIVE_IN_ARCHIVE`, `MIME_ENCRYPTED_ARCHIVE`, `MIME_BAD_UNICODE`, `MIME_BAD_ATTACHMENT` (ZIP contents are inspected) |
| HTML / URLs | `MIME_HTML_ONLY`, `HTML_SHORT_LINK_IMG_*`, `R_EMPTY_IMAGE`, `EXT_CSS`, `HTTP_TO_HTTPS`, `HTTP_TO_IP`, `URL_*` (numeric IP, user:password, no/suspicious TLD, RTL/zero-width, many dots, long, nested URLs), `PHISHING` (link text shows another domain) |
| Other | `GTUBE`, `SPAMTRAP`, `RBL_SPAMHAUS_*`, `RECEIVED_SPAMHAUS_*`, `DBL_*`, `URL_REDIRECTOR_NESTED` |

`beaver filter scan -json` lists every symbol with its score and options.

## Commands

```bash
beaver filter status                  # config path, thresholds, network checks, list sizes (never the DQS key)
beaver filter reload                  # validate config.json and lists, then signal the running daemon
beaver filter scan -account alice@example.com [-client-ip 192.0.2.10] [-ehlo mail.example.com] \
    [-mail-auth] [-rbl] [-only spam|reject|non-ham] [-min-score 5] [-o report.tsv | -json]
```

`reload` refuses an invalid config and leaves the daemon on the previous one; it writes
`antispam/reload.stamp`, which the daemon checks before each message (at most once a second). A daemon that starts
with an invalid config logs the error and runs on defaults. After replacing the plugin binary, restart `beaver serve`.

`scan` scores stored messages as if received now from `-client-ip`: dates are judged against the message's top
`Received` header, the envelope sender comes from `Return-Path`, `-mail-auth` re-verifies DKIM and DMARC (DKIM
alignment only, no SPF), `-rbl` enables Spamhaus lookups. The redirector and hfilter DNS checks never run in scans.
Output is TSV (`mailbox uid score action symbols`) on stdout, in `-o` file, or JSON lines on stderr with `-json`.

## Host settings that feed the plugin

These live in the main `config.json`, not in the plugin file.

| Host key | Effect |
|----------|--------|
| `mail_auth.enabled`, `.spf/.dkim/.dmarc/.arc.enabled`, `.dns_timeout_ms` | SPF/DKIM/DMARC/ARC results sent as `auth` (scored as above) |
| `smtp.greylist.enabled`, `.min_delay_sec`, `.max_age_sec` | Host greylisting at RCPT, before the plugin (independent of the score-based `greylist` action) |
| `smtp.asn_lookup.enabled` (+ zones, timeouts, cache) | Adds `asn` / `country` to requests; the plugin does not score them |
| `plugins.smtp.filter_timeout_ms`, `.timeout_policy` | Time the host waits for a verdict; on timeout `accept` (default) or `tempfail` |

Per-domain antispam (`antispam` flag on a domain in the API / admin UI): the host skips the plugin at RCPT for that
domain, and at end of data when every recipient is local with antispam off.
