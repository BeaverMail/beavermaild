#!/usr/bin/env bash
# Integration smoke: submission + IMAP against store.driver=mysql (MariaDB/MySQL).
# Requires BEAVER_TEST_MYSQL_DSN. Skips (exit 0) when unset.
# Optional: BEAVER_SUBMISSION_SMOKE_EMAIL, BEAVER_SUBMISSION_SMOKE_PASSWORD (default seed alice).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

DSN="${BEAVER_TEST_MYSQL_DSN:-}"
if [[ -z "$DSN" ]]; then
	echo "skip: set BEAVER_TEST_MYSQL_DSN to run MySQL/MariaDB e2e smoke"
	exit 0
fi

EMAIL="${BEAVER_SUBMISSION_SMOKE_EMAIL:-alice@localhost}"
PASSWORD="${BEAVER_SUBMISSION_SMOKE_PASSWORD:-beaver}"

# Avoid host env overriding ports written into the smoke config.
unset BEAVER_IMAP_LISTEN BEAVER_SMTP_LISTEN BEAVER_STORE_DRIVER BEAVER_STORE_DSN || true

TMP="$(mktemp -d)"
SERVE_PID=""
trap 'kill "$SERVE_PID" 2>/dev/null || true; rm -rf "$TMP"' EXIT

echo "== build =="
go build -o "$TMP/beaver" ./cmd/beaver

echo "== wipe mysql schema =="
go run ./tests/integration/mysqldrop "$DSN"

echo "== init (blobs + config) =="
export BEAVER_CONFIG="$TMP/data/config.json"
"$TMP/beaver" init -data-dir "$TMP/data"

INBOUND_PORT=$((17000 + RANDOM % 1000))
SUB_STARTTLS_PORT=$((18000 + RANDOM % 1000))
SUB_TLS_PORT=$((19000 + RANDOM % 1000))
IMAP_PORT=$((20000 + RANDOM % 1000))

python3 - <<PY "$BEAVER_CONFIG" "$DSN" "$INBOUND_PORT" "$SUB_STARTTLS_PORT" "$SUB_TLS_PORT" "$IMAP_PORT"
import json, sys
path, dsn, inbound, sub_plain, sub_tls, imap = sys.argv[1:7]
with open(path) as f:
    cfg = json.load(f)
cfg["store"] = {"driver": "mysql", "dsn": dsn}
cfg.setdefault("tls", {})
cfg["tls"].update({
    "cert_file": "tls/smoke.crt",
    "key_file": "tls/smoke.key",
    "required": False,
})
cfg.setdefault("smtp", {})
cfg["smtp"]["listen"] = f"127.0.0.1:{inbound}"
cfg["smtp"]["submission_listen"] = f"127.0.0.1:{sub_plain}"
cfg["smtp"]["submission_tls_listen"] = f"127.0.0.1:{sub_tls}"
cfg.setdefault("imap", {})
cfg["imap"]["listen"] = f"127.0.0.1:{imap}"
cfg["imap"]["tls_listen"] = ""
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PY

echo "== migrate + seed =="
"$TMP/beaver" migrate -c "$BEAVER_CONFIG"
"$TMP/beaver" seed -c "$BEAVER_CONFIG"
"$TMP/beaver" auth -c "$BEAVER_CONFIG" "$EMAIL" "$PASSWORD"

mkdir -p "$TMP/data/tls"
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/data/tls/smoke.key" -out "$TMP/data/tls/smoke.crt" \
	-days 1 -nodes -subj "/CN=localhost" 2>/dev/null
# No antispam plugin: this smoke is store persistence, not filter policy.

wait_port() {
	local hostport="$1"
	local host="${hostport%:*}"
	local port="${hostport##*:}"
	for _ in $(seq 1 80); do
		if nc -z "$host" "$port" 2>/dev/null; then
			return 0
		fi
		sleep 0.1
	done
	echo "timeout waiting for $hostport" >&2
	return 1
}

start_serve() {
	export BEAVER_SMTP_LISTEN="127.0.0.1:$INBOUND_PORT"
	export BEAVER_IMAP_LISTEN="127.0.0.1:$IMAP_PORT"
	"$TMP/beaver" serve -c "$BEAVER_CONFIG" &
	SERVE_PID=$!
	wait_port "127.0.0.1:$SUB_STARTTLS_PORT"
	wait_port "127.0.0.1:$SUB_TLS_PORT"
	wait_port "127.0.0.1:$IMAP_PORT"
	sleep 0.3
}

stop_serve() {
	if [[ -n "$SERVE_PID" ]]; then
		kill "$SERVE_PID" 2>/dev/null || true
		wait "$SERVE_PID" 2>/dev/null || true
		SERVE_PID=""
	fi
}

echo "== serve (mysql store) =="
start_serve

echo "== submission STARTTLS + IMAP =="
SUBJECT="mysql-e2e-$$"
python3 - <<PY "$SUB_STARTTLS_PORT" "$IMAP_PORT" "$EMAIL" "$PASSWORD" "$SUBJECT"
import imaplib, smtplib, ssl, sys, time

def imap_login(imap, email, password):
    typ, dat = imap._simple_command("LOGIN", imap._quote(email), imap._quote(password))
    if typ != "OK":
        raise imap.error(dat[-1] if dat else "LOGIN failed")
    imap.state = "AUTH"

def imap_verify_subject(host, port, email, password, subject):
    with imaplib.IMAP4(host, port, timeout=30) as imap:
        imap.sock.settimeout(30)
        imap_login(imap, email, password)
        imap.select("INBOX")
        typ, data = imap.search(None, "SUBJECT", subject)
        if typ != "OK" or not data or not data[0]:
            raise SystemExit(f"IMAP SEARCH missing subject {subject!r}")

sub_plain, imap_port, email, password, subject = sys.argv[1:6]
msg = (
    f"From: {email}\r\n"
    f"To: {email}\r\n"
    f"Subject: {subject}\r\n"
    "\r\n"
    f"mysql e2e {subject}\r\n"
)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with smtplib.SMTP("127.0.0.1", int(sub_plain), timeout=30) as smtp:
    smtp.ehlo()
    smtp.starttls(context=ctx)
    smtp.ehlo()
    smtp.login(email, password)
    smtp.sendmail(email, [email], msg)
time.sleep(0.5)
imap_verify_subject("127.0.0.1", int(imap_port), email, password, subject)
print("ok delivery")
PY

echo "== restart serve (persistence) =="
stop_serve
start_serve
python3 - <<PY "$IMAP_PORT" "$EMAIL" "$PASSWORD" "$SUBJECT"
import imaplib, sys

def imap_login(imap, email, password):
    typ, dat = imap._simple_command("LOGIN", imap._quote(email), imap._quote(password))
    if typ != "OK":
        raise imap.error(dat[-1] if dat else "LOGIN failed")
    imap.state = "AUTH"

imap_port, email, password, subject = sys.argv[1:5]
with imaplib.IMAP4("127.0.0.1", int(imap_port), timeout=30) as imap:
    imap.sock.settimeout(30)
    imap_login(imap, email, password)
    imap.select("INBOX")
    typ, data = imap.search(None, "SUBJECT", subject)
    if typ != "OK" or not data or not data[0]:
        raise SystemExit(f"after restart: missing subject {subject!r}")
print("ok persistence after restart")
PY

stop_serve
echo "== OK mysql e2e =="
