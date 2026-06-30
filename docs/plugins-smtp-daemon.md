# SMTP daemon plugin protocol (draft v2.1)

Persistent plugins with `smtp` capability are started by `beaver serve`. The **same executable** may also expose `cli` and be spawned on demand for operator commands; see [plugins.md](plugins.md) (Capabilities).

**Discovery:** host probes each `beaver-plugin-*` binary (`BEAVER_PLUGIN_MODE=metadata`) and reads `Descriptor.capabilities`. Plugins with `smtp` are spawned as daemons under `beaver serve`. No separate manifest file.

Transport: **JSON line-delimited** on a Unix domain socket (`BEAVER_SMTP_SOCKET`). One JSON object per line, same style as CLI JSONL.

Implementation: `internal/pluginhost/daemon/`.

## Lifecycle

| Host action | `BEAVER_PLUGIN_MODE` | stdin | Process |
|-------------|----------------------|-------|---------|
| `beaver serve` | `daemon` | unused | stays up until serve stops |
| `beaver filter reload` (CLI) | unset | `CliRequest` JSON | exits after job |

## Environment (host sets on spawn)

| Variable | Purpose |
|----------|---------|
| `BEAVER_PLUGIN_MODE` | `daemon` |
| `BEAVER_SMTP_SOCKET` | Unix socket path, e.g. `<data_dir>/run/antispam.sock` |

## Connection and ready handshake

Beaver creates the socket path, spawns the plugin, and accepts the plugin connection. **Beaver must not forward SMTP filter requests until the plugin is ready.**

1. Plugin connects to `BEAVER_SMTP_SOCKET`.
2. Plugin loads config (regex DB, remote lists, etc.).
3. Plugin sends **one** ready line (no `id`):

```json
{"status":"ready","capabilities":["smtp"],"max_connections":10}
```

| Field | Meaning |
|-------|---------|
| `status` | Must be `ready` |
| `capabilities` | Optional echo, e.g. `smtp`, `web` |
| `max_connections` | Optional hint for host concurrency |

4. Only after `ready`, Beaver forwards per-message filter requests.

If the plugin exits or the socket closes, `DaemonManager` marks the plugin not ready (fail-open skips it), waits `plugins.smtp.restart_backoff_ms`, respawns the child, and waits for a new `ready` line before forwarding filter traffic again. Intentional shutdown via `beaver serve` stop does not respawn plugins.

## Per-message flow (host -> plugin)

Each SMTP transaction uses a monotonic string `id` (correlates request and response).

### Phases

| Phase | When | `body_path` |
|-------|------|-------------|
| `connect` | TCP accepted | omit |
| `helo` | EHLO/HELO | omit |
| `mail` | MAIL FROM | omit |
| `rcpt` | RCPT TO (one line per recipient) | omit |
| `data` | DATA started; headers may be complete | optional |
| `eom` | End of DATA (`.` on SMTP wire) | **required** |

Early phases (`connect` through `rcpt`) support policy on IP, envelope, and recipients only (greylist, RBL, etc.). **Content filtering requires `eom` with `body_path`.**

### Request shape

Common fields:

```json
{
  "id": "1",
  "phase": "eom",
  "from": "sender@example.com",
  "to": ["rcpt@example.com"],
  "client_ip": "203.0.113.1",
  "body_path": "/tmp/beaver-smtp-msg-123456.eml",
  "timeout_ms": 5000
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | Correlates with response |
| `phase` | yes | See table above |
| `from` | phases after `mail` | Envelope sender |
| `to` | `rcpt`, `eom` | Recipient list |
| `client_ip` | `connect`+ | Client address |
| `body_path` | `eom` | Absolute path to full RFC 5322 message on disk |
| `timeout_ms` | no | Per-request override; host default if omitted |

### `body_path` (same pattern as CLI `raw_path`)

**Host behavior:**

1. While receiving DATA from the remote SMTP client, Beaver buffers/writes the message to a temp file under the data dir, e.g. `<data_dir>/tmp/smtp-filter-<id>.eml`.
2. At `eom`, Beaver sends the filter request with `body_path` set to that file.
3. Plugin reads the file (streaming for large messages), runs antispam/AV logic, replies `accept` / `reject` / etc.
4. After the plugin responds and Beaver has accepted or rejected delivery, **Beaver deletes the temp file**. Cleanup is **host-only**.

**Plugin behavior:** Open `body_path` read-only; do not delete it. Do not assume the file outlives the response.

**Why not inline body in JSON:** avoids RAM blow-up and base64 overhead on large mail. Same rationale as CLI `raw_path`.

**Not in v2.1:** `data_stream` (chunked body over the socket). Possible later; `body_path` is the default and recommended path.

Example `rcpt` (no body):

```json
{"id":"1","phase":"rcpt","from":"sender@example.com","to":["rcpt@example.com"],"client_ip":"203.0.113.1"}
```

Example `eom` (content filter):

```json
{
  "id": "1",
  "phase": "eom",
  "from": "sender@example.com",
  "to": ["rcpt@example.com"],
  "client_ip": "203.0.113.1",
  "body_path": "/tmp/beaver-smtp-msg-1.eml",
  "timeout_ms": 5000
}
```

## Response (plugin -> host)

One line per request `id`:

```json
{"id":"1","action":"accept"}
```

| `action` | SMTP effect (draft) |
|----------|---------------------|
| `accept` | Continue / 250 |
| `reject` | 550 |
| `tempfail` | 451 |
| `discard` | Accept then drop silently |

Optional v2.2: `rewrite` with header map.

## Timeout and backpressure

Remote SMTP clients block on 250/550. Slow plugins must not stall the server indefinitely.

- Each request may include `timeout_ms`.
- Host default: `plugins.smtp.filter_timeout_ms` in config.json (default **10000** ms).
- On timeout, host applies `plugins.smtp.timeout_policy`:
  - `accept` (default): fail-open, deliver mail, log `plugin_timeout`
  - `tempfail`: return 451 to SMTP client
- Beaver logs `plugin_timeout` with plugin name, `id`, phase, and configured timeout for operator tuning.

Example config:

```json
{
  "plugins": {
    "smtp": {
      "filter_timeout_ms": 10000,
      "timeout_policy": "accept",
      "socket_dir": "run/plugins",
      "restart_backoff_ms": 1000
    }
  }
}
```

Plugins that need more time should document recommended `timeout_ms` / host config values.

## Host responsibilities (summary)

| Concern | Owner |
|---------|--------|
| Write message to `body_path` before `eom` | Host |
| Delete `body_path` after decision | Host |
| Wait for `ready` before filtering | Host |
| Restart plugin on crash; wait for new `ready` | `DaemonManager` (`restart_backoff_ms`) |
| Enforce `timeout_ms`; apply timeout policy on expiry | Host |
| Read/analyze `body_path` | Plugin |
| Never open the host mail store / deliver mail | Plugin |

## Checklist (v2.1)

| Item | Spec | Implemented |
|------|------|-------------|
| `body_path` on `eom` | yes | yes |
| Ready handshake `{"status":"ready"}` | yes | yes |
| `timeout_ms` per request + host default + timeout policy + `plugin_timeout` log | yes | yes |
| Multi-phase hooks (connect/helo/mail/rcpt/data/eom) | yes | yes |
| Wire into `beaver serve` and SMTP DATA path | yes | yes |
| In-process plugin restart on crash | yes | yes |
| `web` capability reverse proxy | draft | no |
