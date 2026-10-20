#!/usr/bin/env bash
# Integration smoke: submission SMTP (:587 STARTTLS, :465 implicit TLS), local delivery, IMAP verify.
# Optional env: BEAVER_SUBMISSION_SMOKE_EMAIL, BEAVER_SUBMISSION_SMOKE_PASSWORD (default seed alice).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

EMAIL="${BEAVER_SUBMISSION_SMOKE_EMAIL:-alice@localhost}"
PASSWORD="${BEAVER_SUBMISSION_SMOKE_PASSWORD:-beaver}"

TMP="$(mktemp -d)"
trap 'kill "$SERVE_PID" 2>/dev/null || true; rm -rf "$TMP"' EXIT

echo "== build =="
go build -o "$TMP/beaver" ./cmd/beaver
go build -o "$TMP/beaver-plugin-antispam" ./cmd/beaver-plugin-antispam

echo "== init =="
export BEAVER_CONFIG="$TMP/data/config.json"
"$TMP/beaver" init -data-dir "$TMP/data"

"$TMP/beaver" seed -c "$BEAVER_CONFIG"
"$TMP/beaver" auth -c "$BEAVER_CONFIG" "$EMAIL" "$PASSWORD"

mkdir -p "$TMP/data/tls" "$TMP/data/plugins" "$TMP/data/antispam"
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/data/tls/smoke.key" -out "$TMP/data/tls/smoke.crt" \
	-days 1 -nodes -subj "/CN=localhost" 2>/dev/null
cp "$TMP/beaver-plugin-antispam" "$TMP/data/plugins/"
cp cmd/beaver-plugin-antispam/examples/config.json.example "$TMP/data/antispam/config.json"

INBOUND_PORT=$((17000 + RANDOM % 1000))
SUB_STARTTLS_PORT=$((18000 + RANDOM % 1000))
SUB_TLS_PORT=$((19000 + RANDOM % 1000))
IMAP_PORT=$((20000 + RANDOM % 1000))

python3 - <<PY "$BEAVER_CONFIG" "$INBOUND_PORT" "$SUB_STARTTLS_PORT" "$SUB_TLS_PORT" "$IMAP_PORT"
import json, sys
path, inbound, sub_plain, sub_tls, imap = sys.argv[1:6]
with open(path) as f:
    cfg = json.load(f)
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

echo "== serve (submission + imap) =="
export BEAVER_SMTP_LISTEN="127.0.0.1:$INBOUND_PORT"
"$TMP/beaver" serve -c "$BEAVER_CONFIG" &
SERVE_PID=$!

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

wait_port "127.0.0.1:$SUB_STARTTLS_PORT"
wait_port "127.0.0.1:$SUB_TLS_PORT"
wait_port "127.0.0.1:$IMAP_PORT"
sleep 0.3

echo "== submission STARTTLS :$SUB_STARTTLS_PORT =="
SUBJECT_STARTTLS="bench-submission-starttls-$$"
python3 - <<PY "$SUB_STARTTLS_PORT" "$SUB_TLS_PORT" "$IMAP_PORT" "$EMAIL" "$PASSWORD" "$SUBJECT_STARTTLS"
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

sub_plain, sub_tls, imap_port, email, password, subject = sys.argv[1:7]
body = f"submission smoke starttls {subject}\r\n"
msg = (
    f"From: {email}\r\n"
    f"To: {email}\r\n"
    f"Subject: {subject}\r\n"
    "\r\n"
    f"{body}"
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
print("ok starttls delivery")
PY

echo "== submission implicit TLS :$SUB_TLS_PORT =="
SUBJECT_TLS="bench-submission-tls-$$"
python3 - <<PY "$SUB_TLS_PORT" "$IMAP_PORT" "$EMAIL" "$PASSWORD" "$SUBJECT_TLS"
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

sub_tls, imap_port, email, password, subject = sys.argv[1:6]
body = f"submission smoke tls {subject}\r\n"
msg = (
    f"From: {email}\r\n"
    f"To: {email}\r\n"
    f"Subject: {subject}\r\n"
    "\r\n"
    f"{body}"
)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

with smtplib.SMTP_SSL("127.0.0.1", int(sub_tls), context=ctx, timeout=30) as smtp:
    smtp.ehlo()
    smtp.login(email, password)
    smtp.sendmail(email, [email], msg)

time.sleep(0.5)
imap_verify_subject("127.0.0.1", int(imap_port), email, password, subject)
print("ok tls delivery")
PY

kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
SERVE_PID=""

echo "== OK =="
