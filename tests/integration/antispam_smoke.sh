#!/usr/bin/env bash
# Integration smoke: antispam plugin on inbound SMTP (GTUBE reject, clean delivery with X-Spam-* headers)
# and the admin commands (filter status / reload / scan).
# Optional env: BEAVER_SUBMISSION_SMOKE_EMAIL, BEAVER_SUBMISSION_SMOKE_PASSWORD (default seed alice).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

EMAIL="${BEAVER_SUBMISSION_SMOKE_EMAIL:-alice@localhost}"
PASSWORD="${BEAVER_SUBMISSION_SMOKE_PASSWORD:-beaver}"
unset BEAVER_IMAP_LISTEN BEAVER_SMTP_LISTEN || true

TMP="$(mktemp -d)"
SERVE_PID=""
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
IMAP_PORT=$((20000 + RANDOM % 1000))

python3 - <<PY "$BEAVER_CONFIG" "$INBOUND_PORT" "$IMAP_PORT"
import json, sys
path, inbound, imap = sys.argv[1:4]
with open(path) as f:
    cfg = json.load(f)
cfg.setdefault("tls", {})
cfg["tls"].update({"cert_file": "tls/smoke.crt", "key_file": "tls/smoke.key", "required": False})
cfg.setdefault("smtp", {})
cfg["smtp"]["listen"] = f"127.0.0.1:{inbound}"
cfg["smtp"]["submission_listen"] = ""
cfg["smtp"]["submission_tls_listen"] = ""
cfg.setdefault("imap", {})
cfg["imap"]["listen"] = f"127.0.0.1:{imap}"
cfg["imap"]["tls_listen"] = ""
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PY

echo "== filter status / reload =="
"$TMP/beaver" filter status -c "$BEAVER_CONFIG" | tee "$TMP/status.txt"
grep -q "rbl: off" "$TMP/status.txt"
"$TMP/beaver" filter reload -c "$BEAVER_CONFIG"
test -f "$TMP/data/antispam/reload.stamp"

echo "== serve =="
"$TMP/beaver" serve -c "$BEAVER_CONFIG" &
SERVE_PID=$!
for _ in $(seq 1 80); do
	nc -z 127.0.0.1 "$INBOUND_PORT" 2>/dev/null && nc -z 127.0.0.1 "$IMAP_PORT" 2>/dev/null && break
	sleep 0.1
done
sleep 0.5

echo "== inbound: GTUBE rejected, clean delivered with X-Spam headers =="
python3 - <<PY "$INBOUND_PORT" "$IMAP_PORT" "$EMAIL" "$PASSWORD"
import imaplib, smtplib, sys, time
inbound, imap_port, email, password = sys.argv[1:5]
gtube = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"

def msg(subject, body):
    return (f"From: Carol <carol@example.com>\r\nTo: {email}\r\nSubject: {subject}\r\n"
            "Date: " + time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime()) + "\r\n"
            f"Message-ID: <{subject}@example.com>\r\nMIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n" + body + "\r\n")

with smtplib.SMTP("127.0.0.1", int(inbound), timeout=30) as s:
    s.ehlo("mail.example.com")
    try:
        s.sendmail("carol@example.com", [email], msg("gtube-smoke", gtube))
        raise SystemExit("GTUBE message was accepted")
    except smtplib.SMTPDataError as e:
        if e.smtp_code != 550:
            raise SystemExit(f"GTUBE: want 550, got {e.smtp_code} {e.smtp_error!r}")
    print("ok gtube rejected")
    s.rset()
    s.sendmail("carol@example.com", [email], msg("clean-smoke", "see you at noon"))
print("ok clean accepted")

time.sleep(0.5)
with imaplib.IMAP4("127.0.0.1", int(imap_port), timeout=30) as imap:
    typ, dat = imap._simple_command("LOGIN", imap._quote(email), imap._quote(password))
    if typ != "OK":
        raise SystemExit("IMAP LOGIN failed")
    imap.state = "AUTH"
    imap.select("INBOX")
    typ, data = imap.search(None, "SUBJECT", "clean-smoke")
    if typ != "OK" or not data or not data[0]:
        raise SystemExit("clean message not delivered")
    num = data[0].split()[-1]
    typ, data = imap.fetch(num, "(BODY.PEEK[HEADER])")
    hdr = data[0][1].decode()
    if "X-Spam-Status: No, score=" not in hdr or "X-Spam-Symbols:" not in hdr:
        raise SystemExit("missing X-Spam headers:\n" + hdr)
    typ, data = imap.search(None, "SUBJECT", "gtube-smoke")
    if data and data[0]:
        raise SystemExit("GTUBE message was delivered")
print("ok headers")
PY

kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
SERVE_PID=""

echo "== filter scan =="
"$TMP/beaver" filter scan -c "$BEAVER_CONFIG" -account "$EMAIL" -o "$TMP/scan.tsv"
head -1 "$TMP/scan.tsv" | grep -q "^mailbox	uid	score	action	symbols$"
grep -q "INBOX" "$TMP/scan.tsv"
"$TMP/beaver" filter scan -c "$BEAVER_CONFIG" -account "$EMAIL" -only reject | tee "$TMP/scan-reject.txt"
test "$(wc -l < "$TMP/scan-reject.txt")" -eq 1 # header line only

echo "== OK =="
