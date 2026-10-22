# HTTP API (`/api/v1`)

The admin REST API served by `beaver serve` when `http.enabled` is true. The web UI uses the same API, so anything
the UI does a script or an LLM agent can do too.

Source of truth: [`internal/httpapi/handlers.go`](../internal/httpapi/handlers.go) (route table). If this page and
the code disagree, the code wins; please fix the page.

## Basics

| Item | Value |
|------|-------|
| Base URL | `https://<http.listen>/api/v1` (plain `http://` only on a loopback listen) |
| Format | JSON in, JSON out (`Content-Type: application/json`) |
| Request body limit | 1 MiB |
| Unknown JSON fields | **rejected** with `400 invalid json` |
| Errors | `{"error": "<message>"}` with a 4xx/5xx status |

Config (`beaver.json`):

```json
"http": { "enabled": true, "listen": "127.0.0.1:8080" }
```

A non-loopback `listen` requires TLS (`tls.cert_file`/`key_file` or `tls.acme_hosts`); see [tls-ops.md](tls-ops.md).

| Question | Answer today |
|----------|--------------|
| Where does it listen? | TCP only: loopback (plain HTTP allowed) or network (HTTPS required). No Unix socket. |
| How do clients authenticate? | API key (integrations) or session token from `POST /auth/login` (browser, scripts). No mTLS. |
| Can credentials be restricted? | By role and tenant (see [Roles](#roles)). API keys use the `provisioner` role. No per-operation scopes or read-only tokens. |

## Authentication

### API keys (integrations)

Create a key on the mail server with the CLI; the token is printed once on stdout:

```sh
beaver apikey create -name panel          # prints bk_<id>_<secret>
beaver apikey list [-json]                # id, name, role, created (never the secret)
beaver apikey revoke <id>                 # takes effect on the next request
```

Send it as `Authorization: Bearer bk_<id>_<secret>`. API keys:

- do not expire; revoke them with the CLI;
- use the `provisioner` role (see [Roles](#roles));
- **skip the login rate limit**, so failed logins from other local clients cannot lock the integration out;
- can only be created, listed and revoked from the CLI, not through the API;
- are stored as SHA-256 of the secret; a lost token cannot be recovered, create a new one.

A wrong or revoked key returns `401`.

### Session login

1. `POST /auth/login` with directory credentials; the response carries a `token`.
2. Send `Authorization: Bearer <token>` on every other call.

```sh
TOKEN=$(curl -s https://mail.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"secret"}' | jq -r .token)

curl -s https://mail.example.com/api/v1/me -H "Authorization: Bearer $TOKEN"
```

- Session tokens are HMAC-signed and valid for **12 hours**; clients log in again when they get `401`.
- Logout is client-side for Bearer clients (drop the token); `POST /auth/logout` only clears the browser cookie.
- The browser UI uses the `beaver_session` cookie instead. Cookie-authenticated writes must pass a same-origin check;
  Bearer requests skip it.
- Login and setup are rate limited per client IP: after 10 failures in 15 minutes (defaults, `auth.rate_limit`)
  further attempts get `429 too many auth attempts`. Authenticated calls have no rate limit.
- The failure counter is **shared with IMAP and SMTP AUTH** and keyed by IP only. Every local client (webmail,
  scripts, other users on the host) counts as `127.0.0.1`, so 10 failed IMAP logins from a local webmail also block
  session logins from the same host for up to 15 minutes. Integrations should use an API key, which is not affected.

### Roles

| Role | Scope |
|------|-------|
| `admin` | Whole instance |
| `provisioner` | API keys only. All tenants, domains and accounts (create, change, delete). Cannot create or promote `admin` accounts, and has no access to queue, logs, status or delivery |
| `tenant_admin` | Its own tenant: domains and accounts |
| `user` | Read-only view of its own domain and its own account |

Calls outside the caller's scope return `403 forbidden`.

## Endpoints

Paths are relative to `/api/v1`. "Who" is the minimum role.

### Setup and session

| Method | Path | Who | Body | Response |
|--------|------|-----|------|----------|
| GET | `/health` | public | | `{"status":"ok"}` |
| GET | `/setup` | public | | `{"needed": bool}` |
| POST | `/setup` | public, only while `needed` | `{email, password}` | same as login; `409` once setup is done |
| POST | `/auth/login` | public | `{email, password}` | `{token, account:{email, role, tenant_id}}` |
| POST | `/auth/logout` | public | | `{"status":"ok"}` |
| GET | `/me` | any | | `{email, role, tenant_id}` (API key: `apikey-<id>@api-key.invalid`, `tenant_id` 0) |

### Tenants

| Method | Path | Who | Body | Response |
|--------|------|-----|------|----------|
| GET | `/tenants` | tenant_admin (own) / provisioner, admin (all) | | `{"tenants":[{id, name, external_id?}]}` |
| POST | `/tenants` | provisioner / admin | `{name, external_id?}` | `201` `{id, name, external_id?}` |
| PATCH | `/tenants/{id}` | tenant_admin (own) / provisioner, admin | `{name}` | `{id, name, external_id?}` |
| DELETE | `/tenants/{id}` | provisioner / admin | `{"confirm": "<tenant name>"}` | `{id, name, domains_deleted, accounts_deleted}` |

Deleting a tenant deletes all its domains, accounts and mail. The default tenant (`id=1`) cannot be deleted.

`external_id` is an optional key chosen by the caller (e.g. the panel's customer id): up to 128 bytes, no spaces or
control characters, unique across tenants, immutable after create. Creating a tenant with an `external_id` that
already exists returns `409` with the existing tenant, so a retrying client gets its `id` without a second call:

```json
409 Conflict
{"error":"tenant already exists","tenant":{"id":5,"name":"Customer","external_id":"cust-42"}}
```

Tenant names are not unique; without `external_id`, a repeated create makes another tenant. After a tenant is
deleted its `external_id` can be used again.

### Domains

| Method | Path | Who | Body | Response |
|--------|------|-----|------|----------|
| GET | `/domains` | any (scoped) | | `{"domains":[Domain]}` |
| POST | `/domains` | tenant_admin / admin | DomainInput | `201` Domain |
| GET | `/domains/{domain}` | any (scoped) | | Domain |
| PATCH | `/domains/{domain}` | tenant_admin / admin | DomainInput (no `name`, `tenant_id`) | Domain |
| DELETE | `/domains/{domain}` | tenant_admin / admin | `{"confirm": "<domain name>"}` | `{name, accounts_deleted}` |
| GET | `/domains/{domain}/dns-recommended` | any (scoped) | | `{domain, records:[{type, host, value, placeholder?, note?}]}` |
| GET | `/domains/{domain}/reports` | any (scoped) | | `{domain, reports:[...], dmarc?, tls?}` |

**DomainInput**

| Field | Type | Notes |
|-------|------|-------|
| `name` | string | POST only, required |
| `tenant_id` | number | POST only; admin and provisioner may choose (default `1`), tenant_admin is forced to its own |
| `mail_hostname` | string | **required** (e.g. `mail.example.com`) |
| `ssl_mode` | string | `none` (default), `acme`, `custom` |
| `cert_pem`, `key_pem` | string | required with `custom` on create; on PATCH omit them to keep the stored cert |
| `catch_all` | string | local part that receives mail for unknown addresses |
| `dkim_enabled` | bool | generates a key (selector `beaver`) on first enable |
| `antispam` | bool | |
| `send_max_messages`, `send_window` | number, duration | per-domain submission rate, e.g. `100` per `"1h"`; `0`/empty = global |
| `storage_bytes`, `messages_quota` | number | default per-account quotas; `0` = global default |
| `relay_host`, `relay_user`, `relay_password`, `relay_starttls` | | per-domain outbound relay; on PATCH an empty `relay_password` keeps the stored one |

> **PATCH is a full replace**, not a merge. Every field you leave out is reset (catch-all cleared, DKIM and antispam
> off, quotas and rate limits back to global). Read the domain with GET, change what you need, send the whole object.

**Domain** (response) has the input fields (except secrets and PEMs) plus `id`, `dkim_selector`, `dkim_dns_name`,
`dkim_dns_value`, `account_count`, `storage_used`, `ssl_active`, `dkim_active`, `antispam_active`. Empty or false
optional fields are omitted.

**Reports**: each item has `kind` (`dmarc`|`tls`), `from`, `to`, `received_at`, `content_type`, `format`, `file`,
`parsed`, `problems?`. The `dmarc` aggregate (`reports`, `messages`, `dkim_pass`, `spf_pass`, `dmarc_pass`,
`dmarc_fail`, `spoofing:{messages, source_ips}`) and the `tls` aggregate (`reports`, `successful_sessions`,
`failed_sessions`, `mx_failures:[{mx, failed_sessions, result_types}]`) are present only when at least one report of
that kind parsed.

### Accounts

| Method | Path | Who | Body | Response |
|--------|------|-----|------|----------|
| GET | `/domains/{domain}/accounts` | any (user: only itself) | | `{"accounts":[Account]}` |
| POST | `/domains/{domain}/accounts` | tenant_admin / admin | `{local_part, password, role?}` | `201` Account |
| PATCH | `/accounts/{email}` | tenant_admin / admin | any of `{role, password, active, storage_limit, messages_limit}` | Account |
| DELETE | `/accounts/{email}` | tenant_admin / admin | | `{email, messages_removed, blobs_removed}` |

**Account**: `id`, `local_part`, `email`, `role`, `tenant_id`, `active`, `storage_used`, `storage_limit`,
`messages_used`, `messages_limit` (limit `0` = unlimited; usage is filled on list and PATCH, not on create).

- `role` defaults to `user`. A tenant_admin or provisioner can assign only `user` or `tenant_admin`.
- Account PATCH is a real partial update: send only the fields to change.
- `active: false` blocks IMAP/SMTP/API login **and rejects incoming mail** with `550 5.1.1 User inactive`, so senders
  get a bounce. Stored mail is kept.
- You cannot delete yourself, deactivate yourself, or reset your own password through this API.
- DELETE removes the account **and all its mail**; it has no `confirm` body.

**Passwords** are sent in clear text inside the JSON body (protected by TLS) and stored as bcrypt hashes. Importing an
existing hash is not supported. Empty passwords are rejected; bcrypt rejects passwords longer than 72 bytes.

### Quotas and usage

| Need | How |
|------|-----|
| Read usage of one mailbox | `GET /domains/{domain}/accounts`: `storage_used` / `messages_used` per account |
| Read usage of a domain | `GET /domains/{domain}`: `storage_used` (sum of its accounts) |
| Set a default mailbox quota for a domain | `storage_bytes` / `messages_quota` on the domain (POST or full PATCH) |
| Set the quota of one mailbox | `PATCH /accounts/{email}` with `storage_limit` (bytes) and/or `messages_limit`; `0` = unlimited, an omitted field keeps its value |
| Cap the total size of a domain | **not available**: limits are per mailbox |

The domain default is copied into a mailbox's quota record the first time that mailbox is used (delivery, IMAP,
usage read). Changing the domain default later does **not** update mailboxes that already have a record: set each
mailbox explicitly with PATCH. A new limit below current usage blocks further delivery but deletes nothing. Usage is
in bytes and counts stored messages only.

Who can set mailbox limits: `admin`, `provisioner`, and `tenant_admin` for accounts in its own tenant (same rule as the domain
defaults). A customer who holds a `tenant_admin` login can therefore raise its own limits; there is no server-side
tenant-wide cap yet.

### Aliases and forwarding

Not supported. The only routing option is the per-domain `catch_all` (one local part that receives mail for unknown
addresses on that domain).

### DKIM

Set `dkim_enabled: true` on the domain (POST or PATCH). The server generates the key pair on first enable (selector
`beaver`) and keeps the private key. The public record to publish is returned:

- in every Domain object as `dkim_dns_name` / `dkim_dns_value`;
- in `GET /domains/{domain}/dns-recommended` as the `TXT` row, together with MX, SPF and autoconfig records.

Key rotation and importing your own key are not available through the API.

### Outbound queue (admin)

| Method | Path | Query | Response |
|--------|------|-------|----------|
| GET | `/queue` | `all=1` to include finished entries | `{"entries":[QueueEntry]}` |
| POST | `/queue/{id}/retry` | `address=` to retry one recipient (default: all) | `{"status":"ok"}` |
| POST | `/queue/{id}/hold` | | `{"status":"ok"}` |
| POST | `/queue/{id}/unhold` | | `{"status":"ok"}` |
| DELETE | `/queue/{id}` | | `{"status":"ok"}` (cancels delivery) |

**QueueEntry**: `id`, `return_path`, `size`, `created` (Unix seconds), `pending`, `held`, `completed_ms?`,
`recipients:[{address, retry, status, next_due_ms, last_attempt_ms, last_diag?}]`. `*_ms` fields are Unix
milliseconds.

### Operations (admin)

| Method | Path | Body / query | Response |
|--------|------|--------------|----------|
| GET | `/status` | | `{"services":[{id, name, listen?, state, error?}]}` |
| GET | `/logs` | `limit` (default 200), `level` (`debug`/`info`/`warn`/`error`, minimum), `q` (text), `before` (RFC 3339, for paging) | `{"entries":[{time, level, msg, attrs?}]}` |
| GET | `/delivery` | | `{relay_configured, relay}` |
| POST | `/delivery/test` | `{to, mode?}`; `to` is an address or domain, `mode` is `mx`, `relay` or empty (auto) | `{ok, mode, domain?, host?, steps:[{name, ok, detail?, error?}]}` |

`/delivery/test` checks connectivity (dial, EHLO, STARTTLS, AUTH) and never sends a message. It can take up to 20 s.
`/logs` needs `log.file` configured, otherwise it returns `503`.

## Status codes

| Code | Meaning |
|------|---------|
| 400 | Invalid JSON, unknown field, or validation error (message in `error`) |
| 401 | Missing, invalid, expired or revoked token / API key |
| 403 | Outside the caller's role or tenant, or a forbidden self-action |
| 404 | Domain, account, tenant or queue entry not found |
| 409 | Already exists (tenant `409` includes the existing tenant), or setup already complete |
| 429 | Too many login attempts from this IP |
| 503 | Feature not wired on this instance (queue, logs, delivery probe, blob store, quota store) |

### Idempotency

| Operation | Repeated call |
|-----------|---------------|
| Create domain / account | `409` (already exists): nothing changed. Treat `409` as "exists" if you only need it to exist. |
| Create tenant | with `external_id`: `409` plus the existing tenant. Without it: creates a duplicate (names are not unique) |
| PATCH domain / account / tenant | idempotent (same body, same result) |
| DELETE domain / account / tenant | second call returns `404` |
| Queue retry / hold / unhold | idempotent (`200`) |

## Examples

The bodies below show the wire format as built by the handlers. Values are fictional.

**Create a domain with DKIM**

```http
POST /api/v1/domains
Authorization: Bearer <token>
Content-Type: application/json

{"name":"example.org","mail_hostname":"mail.example.org","ssl_mode":"acme","dkim_enabled":true,"storage_bytes":1073741824}
```

```json
201 Created
{"id":2,"name":"example.org","tenant_id":1,"mail_hostname":"mail.example.org","ssl_mode":"acme",
 "dkim_enabled":true,"dkim_selector":"beaver","dkim_dns_name":"beaver._domainkey.example.org",
 "dkim_dns_value":"v=DKIM1; k=rsa; p=MIIBIjANBg...","storage_bytes":1073741824,
 "account_count":0,"storage_used":0,"ssl_active":false,"dkim_active":true,"antispam_active":false}
```

**Create a mailbox**

```http
POST /api/v1/domains/example.org/accounts

{"local_part":"alice","password":"correct horse battery staple"}
```

```json
201 Created
{"id":7,"local_part":"alice","email":"alice@example.org","role":"user","tenant_id":1,"active":true,
 "storage_used":0,"storage_limit":0,"messages_used":0,"messages_limit":0}
```

**Set a mailbox quota (1 GiB, no message cap)**

```http
PATCH /api/v1/accounts/alice@example.org

{"storage_limit":1073741824,"messages_limit":0}
```

```json
200 OK
{"id":7,"local_part":"alice","email":"alice@example.org","role":"user","tenant_id":1,"active":true,
 "storage_used":52428800,"storage_limit":1073741824,"messages_used":1200,"messages_limit":0}
```

**Change password, then disable**

```http
PATCH /api/v1/accounts/alice@example.org

{"password":"new secret"}
```

```http
PATCH /api/v1/accounts/alice@example.org

{"active":false}
```

**List mailboxes with usage**

```json
GET /api/v1/domains/example.org/accounts
200 OK
{"accounts":[{"id":7,"local_part":"alice","email":"alice@example.org","role":"user","tenant_id":1,"active":true,
 "storage_used":52428800,"storage_limit":1073741824,"messages_used":1200,"messages_limit":0}]}
```

**DNS records to show the customer**

```json
GET /api/v1/domains/example.org/dns-recommended
200 OK
{"domain":"example.org","records":[
 {"type":"MX","host":"example.org","value":"10 mail.example.org"},
 {"type":"TXT","host":"example.org","value":"v=spf1 mx a:mail.example.org ~all"},
 {"type":"TXT","host":"beaver._domainkey.example.org","value":"v=DKIM1; k=rsa; p=MIIBIjANBg..."},
 {"type":"CNAME","host":"autoconfig.example.org","value":"mail.example.org"},
 {"type":"CNAME","host":"autodiscover.example.org","value":"mail.example.org"}]}
```

**Delete a domain**

```http
DELETE /api/v1/domains/example.org

{"confirm":"example.org"}
```

```json
200 OK
{"name":"example.org","accounts_deleted":1}
```

**Error**

```json
409 Conflict
{"error":"account already exists"}
```

## Notes for LLM agents and tool builders

- Map one endpoint to one tool. Read-only tools (all `GET`, plus `/delivery/test`) are safe to call freely.
- **Destructive calls**: `DELETE /tenants/{id}`, `DELETE /domains/{domain}`, `DELETE /accounts/{email}`,
  `DELETE /queue/{id}`. They permanently delete mail or cancel delivery. Ask the human before calling them. Tenant and
  domain deletes also require a `confirm` field equal to the name.
- `PATCH /domains/{domain}` resets every field you omit: always GET first and send the full object back.
- Do not invent fields; unknown keys fail the whole request.
- Always send `external_id` when creating a tenant, so a retried call cannot create a duplicate.
- Prefer an API key (`provisioner`) over a password login; on `401` with an API key, stop and ask: the key was
  revoked. With a session token, log in again (tokens expire after 12 h).
- Never put passwords or API keys in logs or prompts. For an agent that serves one customer, a `tenant_admin`
  account scoped to that tenant is narrower than a `provisioner` key.
