# Storage backends (KV store)

BeaverMail stores mail metadata and directory objects behind `storage.Store` (content-addressed blobs stay on the filesystem under `data_dir/blobs`).

## Drivers

| `store.driver` | Use | Notes |
|----------------|-----|-------|
| `sqlite` (default) | Single-node / lab | File at `data_dir/store.sqlite` |
| `mysql` | MariaDB or MySQL | MySQL wire protocol via `go-sql-driver/mysql` |

PostgreSQL is planned next (same `Store` interface).

## Config

```json
{
  "data_dir": "/var/lib/beavermail",
  "store": {
    "driver": "mysql",
    "dsn": "beaver:secret@tcp(127.0.0.1:3306)/beavermail?parseTime=true&charset=utf8mb4"
  }
}
```

Environment overrides: `BEAVER_STORE_DRIVER`, `BEAVER_STORE_DSN`.

### MariaDB / MySQL setup

1. Create database and user (InnoDB default is fine).
2. Point `store.dsn` at that database. Migrations create subspace tables (`m`, `i`, `n`, …) on first open.
3. Blobs remain on local disk (`data_dir/blobs`); back up DB **and** `blobs` together for DR.

Apply schema (idempotent; also runs on every store open / `serve`):

```bash
# After setting store.driver=mysql and store.dsn in config.json:
beaver migrate -c /var/lib/beavermail/config.json
```

`beaver init` also opens the store and migrates for whatever driver is already in the config (default sqlite).

Example database bootstrap:

```sql
CREATE DATABASE beavermail CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'beaver'@'%' IDENTIFIED BY 'secret';
GRANT ALL ON beavermail.* TO 'beaver'@'%';
FLUSH PRIVILEGES;
```

## MariaDB / MySQL dump and restore (DR)

KV keys and values are **binary BLOBs** (same idea as Stalwart). A plain SQL dump without hex encoding can corrupt binary rows on restore. Always use `--hex-blob`.

### Dump

Prefer stopping or idling `beaver serve` if you need app-level consistency with the filesystem blob tree. InnoDB `--single-transaction` gives a consistent DB snapshot without long table locks.

```bash
# Replace user/db; add -p or a defaults file for the password.
mariadb-dump \
  --single-transaction \
  --hex-blob \
  --skip-comments \
  -u beaver \
  beavermail \
  | zstd > beavermail-$(date +%F).sql.zst
```

`mysqldump` with the same flags works on MySQL.

If restore fails with packet-too-large errors, raise `max_allowed_packet` on both dump and restore sides (for example `1G` in the server config, or `--max-allowed-packet=1G` on the client).

### Restore

```bash
zstd -d -c beavermail-YYYY-MM-DD.sql.zst | mariadb -u beaver beavermail
```

Create an empty database first (or drop/recreate), then load. After restore, run `beaver migrate -c …` so schema version matches this binary if needed.

### Blobs (required for full DR)

`mariadb-dump` does **not** include message bodies. Also copy the blob directory:

```bash
rsync -a /var/lib/beavermail/blobs/ /backup/beavermail/blobs/
```

Restore blobs to the same path configured under `data_dir` before starting `serve`.

### When to use what

| Goal | Tool |
|------|------|
| Full instance DR (MySQL backend) | `mariadb-dump --hex-blob` + `rsync` of `blobs/` |
| Portable KV across sqlite/mysql (lab / backend switch) | `beaver store export` / `import` (still copy `blobs/` separately) |
| Daily KV-only snapshot while serve runs | `beaver store export -o -` (best-effort; not a substitute for DB+blobs DR) |

## KV export / import (BEAVERKV1)

Dumps **metadata KV only** (not `blobs/`). Use the same `data_dir/blobs` (or rsync it) after a backend switch.

| Command | Notes |
|---------|--------|
| `beaver store export -c … -o file` | Online OK (best-effort snapshot; fine for daily backups) |
| `beaver store export -c … -o -` | Write dump to stdout (pipe to `zstd` / `gpg`) |
| `beaver store import -c … -i file` | Stop `serve` first. Fails if target already has any KV row |
| `beaver store import … --force` | Upsert into a non-empty store |

Format: magic `BEAVERKV1\n`, then `schema_version` (u32 BE), then length-prefixed key/value records. Import rejects dumps with schema newer than this binary.

```bash
# Daily backup (serve may stay up)
beaver store export -c /etc/beavermail/config.json -o - | zstd > kv-$(date +%F).beaverkv.zst

# Migrate sqlite → mysql (stop serve; keep blobs)
beaver store export -c .data/config.json -o /tmp/kv.beaverkv
# set store.driver=mysql + store.dsn, then:
beaver migrate -c .data/config.json
beaver store import -c .data/config.json -i /tmp/kv.beaverkv
```

## Tests

MySQL/MariaDB store tests skip unless a DSN is set:

```bash
export BEAVER_TEST_MYSQL_DSN='beaver:secret@tcp(127.0.0.1:3306)/beavermail_test?parseTime=true'
go test ./internal/storage/mysql/ ./internal/storage/xfer/ -count=1
```
