# BeaverMail plugin SDK (API v2)

CLI extensions are separate executables (`beaver-plugin-*`) spawned by `beaver` with plain `exec` (no go-plugin). The **host** opens the mail store and blob backend (`internal/storage`); plugins never touch them. Communication is one JSON line on **stdin** and JSONL on **stdout**.

Go package: `github.com/BeaverMail/beaver/plugin`

## Quick start

1. Build the host:

```bash
make beaver
```

2. Install a plugin executable under `<data_dir>/plugins/` (`/var/lib/beavermail/plugins/` with `beaver init` defaults; `make plugins` builds into `.data/plugins`):

```bash
install -m 755 beaver-plugin-antispam /var/lib/beavermail/plugins/
```

The host discovers command and `cli_flags` via metadata probe (`BEAVER_PLUGIN_MODE=metadata`). CLI plugins are available immediately; daemon plugins (`smtp`) load when `beaver serve` starts, so restart it after installing or upgrading one. A binary whose probe fails is skipped with a warning (`beaver plugins list` shows it) instead of blocking the others.

3. Run a plugin command (account must exist for mail-ingest plugins):

```bash
beaver widget frob -account alice@example.com -srcdir /var/data/src
beaver plugins list
# config outside the default path: -c (or BEAVER_CONFIG) selects which data_dir/plugins is scanned
beaver widget frob -c /srv/beaver/config.json -account alice@example.com -srcdir /var/data/src
```

Plugin commands come from each plugin `Descriptor` (metadata probe), not from hardcoded subcommands in `beaver`.

## System (v2)

| Topic | Behavior |
|-------|----------|
| Runtime | Subprocess `exec`, stdin JSON + stdout JSONL |
| Store access | Host only (`storage.Store` + blobs); plugin sends batches, host ingests |
| Commands | CLI: `beaver <command>` only. Daemon: `beaver serve` (scaffold, not wired in v2.0) |
| Discovery | `beaver-plugin-*` in `<data_dir>/plugins/`; host probes each binary (`BEAVER_PLUGIN_MODE=metadata`) |
| Versioning | `APIVersion` constant (currently **2**) |
| Deploy | Ship `beaver` + all `beaver-plugin-*` from the same build |

### Capabilities (strategic model)

`capabilities` in the plugin `Descriptor` tells the host **how** to run the same executable, not **whether** it exists. One `beaver-plugin-*` binary can declare multiple capabilities and behave differently depending on how the host spawns it.

| Capability | Host entrypoint | Host behavior | Process lifecycle |
|------------|-----------------|---------------|-------------------|
| `cli` | `beaver <plugin-command>`, e.g. `beaver filter reload` | `exec` subprocess, one JSON line on **stdin**, JSONL on **stdout**, wait, exit | Ephemeral (use and discard) |
| `smtp` | `beaver serve` | `exec` subprocess with daemon env (Unix socket path). No stdin protocol. | Persistent until serve stops |
| `web` | `beaver serve` | Same daemon process; host reverse-proxies HTTP admin UI to `BEAVER_WEB_PORT` | Persistent (shared with `smtp` on same exe) |

**v2.0 today:** `cli` is wired. `smtp` is wired on `beaver serve` when plugins declare it in `Descriptor`. `web` is parsed from the descriptor but **not** started yet.

**Why `cli` plugins do not load in `beaver serve`:** operator tools (import, reload lists, backup) are on-demand jobs, not long-lived services. Daemon capabilities are the opposite: loaded once with the MTA and kept running.

#### Same executable, three modes

A plugin such as `beaver-plugin-antispam` should branch at startup:

```go
func main() {
    if plugin.IsDaemonProcess() {
        runDaemon() // SMTP socket + optional web UI
        return
    }
    if plugin.IsMetadataProcess() {
        plugin.EmitDescriptor(plugin.Descriptor{
            Command:  []string{"filter", "reload"},
            CliFlags: []plugin.CliFlag{...},
        })
        return
    }
    plugin.RunCLI(runCLI) // e.g. op filter/reload via stdin JSONL
}
```

| Mode | How the host starts it | Plugin does |
|------|------------------------|-------------|
| **Metadata** | `BEAVER_PLUGIN_MODE=metadata`. No stdin. | Print one `Descriptor` JSON line on stdout, exit 0 |
| **CLI** | `BEAVER_PLUGIN_MODE` unset. Host writes `CliRequest` on stdin. | Run one job, emit JSONL, exit |
| **Daemon** | `BEAVER_PLUGIN_MODE=daemon` plus socket/port env (see below). No stdin job. | Listen on Unix socket (and HTTP if `web`), run until SIGTERM |

Mail-ingest plugin example (descriptor in code, single binary artifact):

```go
func main() {
    desc := plugin.Descriptor{
        Command: []string{"widget", "frob"},
        CliFlags: []plugin.CliFlag{
            {Key: "srcdir", Flag: "srcdir", Required: true, Description: "Source directory"},
        },
    }
    if plugin.IsMetadataProcess() {
        plugin.EmitDescriptor(desc)
        return
    }
    plugin.RunCLI(runWidgetFrob)
}
```

`cli_flags` maps dedicated `-flag` options into `params` for the plugin. `-param key=value` remains available for ad-hoc args.

Antispam example (descriptor declares cli + smtp + web):

```go
desc := plugin.Descriptor{
    Command:      []string{"filter", "reload"},
    Capabilities: []string{plugin.CapCLI, plugin.CapSMTP, plugin.CapWeb},
}
```

- `beaver filter reload` uses `Registry.Find` (requires `cli`) and the **CLI** path above.
- `beaver serve` uses `Registry.DaemonEntries` (requires `smtp` or `web`) and the **daemon** path above.

Daemon environment (draft, set by host on spawn):

| Variable | Purpose |
|----------|---------|
| `BEAVER_PLUGIN_MODE` | `daemon` or `metadata` (CLI job when unset) |
| `BEAVER_SMTP_SOCKET` | Unix socket path, e.g. `/run/beaver/antispam.sock` |
| `BEAVER_WEB_PORT` | Local HTTP port for admin UI (`web` capability) |

SMTP wire format (ready handshake, `body_path`, timeouts): [plugins-smtp-daemon.md](plugins-smtp-daemon.md).

Plugins without a metadata probe default to `capabilities: ["cli"]` and command equal to the binary stem (`beaver-plugin-widget-frob` -> `widget-frob`). The operator must run exactly the command shown by `beaver plugins list`.

## CLI JSONL protocol (v2)

**stdin (host -> plugin):** one JSON line `CliRequest`. The `op` field is derived from the plugin `Descriptor` `command` array joined by `/`.

```json
{
  "api_version": 2,
  "beaver_version": "0.0.0-dev",
  "op": "myplugin/run",
  "account_email": "alice@example.com",
  "dry_run": false,
  "params": {"key": "value"}
}
```

Op-specific arguments live in `params` (each plugin defines its own shape). Host options such as `--clear-recent` are handled by the host after ingest, not sent to the plugin.

**stdout (plugin -> host):** JSONL, one event per line:

| `op` | Payload | Host action |
|------|---------|-------------|
| `batch` | `{messages:[{imap_name, raw_path or raw_b64, flags, received_at, blob_hash_hex}]}` | read file or decode, dedup, append |
| `done` | `{}` | job complete |
| `error` | `{message}` | fail job |

**stderr:** human-readable logs only (never protocol).

Default batch size: **1000** messages (`DefaultBatchSize`). Override with env `BEAVER_CLI_BATCH_SIZE`.

**Message payload:** prefer `raw_path` (absolute path to an `.eml` file). The host reads the file and unlinks it only when the path matches a plugin temp file (see `plugin.WriteTempMessage`). Source paths owned by the plugin are never deleted. Use `raw_b64` only for small messages.

### DTOs

- `Descriptor` / `CliFlag` - plugin self-description for host discovery
- `CliRequest` - common job fields + opaque `params`
- `BatchMessage` - one message in a `batch` event
- `JobResult` - host-side `{Imported, Skipped, Errors, ByMailbox}`

## Host ingest

Host implementation: `internal/pluginhost/cli/` and `internal/pluginhost/mail_adapter.go`.

- Host resolves `account_email` and ensures mailboxes **before** spawn.
- Host preloads Blake3 hash index; plugin sends `blob_hash_hex` for dedup.
- After a successful job, host may clear `\\Recent` on mailboxes that received new messages (`--clear-recent`).

## Writing a plugin

### CLI-only

```go
func main() {
    if plugin.IsMetadataProcess() {
        plugin.EmitDescriptor(desc)
        return
    }
    plugin.RunCLI(runJob)
}
```

### Dual-mode (CLI + daemon, e.g. antispam)

```go
func main() {
    if plugin.IsDaemonProcess() {
        runDaemon()
        return
    }
    if plugin.IsMetadataProcess() {
        plugin.EmitDescriptor(desc)
        return
    }
    plugin.RunCLI(runCLI)
}
```

### CLI job handler

```go
func runJob(req plugin.CliRequest, emit *plugin.BatchEmitter) error {
    var params myParams
    if err := json.Unmarshal(req.Params, &params); err != nil {
        return err
    }
    // emit.Add(...) then emit.EmitDone()
    return emit.EmitDone()
}
```

Rules: import only `github.com/BeaverMail/beaver/plugin` and stdlib; never `internal/*`; never open the host database, blob dir, or write under `data/` directly.

## Daemon plugins

SMTP persistent plugins use `internal/pluginhost/daemon/` and are started by `beaver serve` when a plugin `Descriptor` declares the `smtp` capability. Web capability remains scaffold only.

See **Capabilities (strategic model)** above for how the same exe runs as CLI vs daemon. Wire protocol: [plugins-smtp-daemon.md](plugins-smtp-daemon.md).

**v2.0 shipped:** CLI plugins only. SMTP daemon wiring lands in the same release series as [plugins-smtp-daemon.md](plugins-smtp-daemon.md) implementation.

## API changelog

| Version | Changes |
|---------|---------|
| 2 | CLI JSONL on stdio; `params` for op-specific args; host-side clear-recent; `raw_path` batch payload; metadata probe (`BEAVER_PLUGIN_MODE=metadata`); `Descriptor` / `CliFlag`; registry scan-only (no aggregate manifest); exact command as `plugins list` (no hyphen alias); `beaver plugins list` and plugin lines in `beaver help`; `JobResult.ByMailbox`; plugin stderr forwarded to operator |
| 2.1 (draft) | SMTP daemon filter on `beaver serve`; multi-phase socket protocol; configurable filter timeout (default fail-open) |
