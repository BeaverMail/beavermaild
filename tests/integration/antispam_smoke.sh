#!/usr/bin/env bash
# Integration smoke test: antispam plugin + SMTP filter (local dry-run and live).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'kill "$SERVE_PID" 2>/dev/null || true; rm -rf "$TMP"' EXIT
SERVE_PID=""

GTUBE_SUBJECT='XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'

echo "== build =="
go build -o "$TMP/beaver" ./cmd/beaver
go build -o "$TMP/beaver-plugin-antispam" ./cmd/beaver-plugin-antispam

echo "== init =="
"$TMP/beaver" init -data-dir "$TMP/data"
export BEAVER_CONFIG="$TMP/data/config.json"

"$TMP/beaver" seed -c "$BEAVER_CONFIG"
"$TMP/beaver" auth -c "$BEAVER_CONFIG" alice@localhost beaver

mkdir -p "$TMP/data/plugins"
cp "$TMP/beaver-plugin-antispam" "$TMP/data/plugins/"
mkdir -p "$TMP/data/antispam"
cp cmd/beaver-plugin-antispam/examples/config.json.example "$TMP/data/antispam/config.json"

echo "== plugin CLI =="
"$TMP/beaver" filter status -c "$BEAVER_CONFIG" 2>&1 | grep -q enabled=
"$TMP/beaver" filter reload -c "$BEAVER_CONFIG" 2>&1 | grep -q reloaded

echo "== serve + deliver test messages =="
PORT=$((18000 + RANDOM % 1000))
export BEAVER_SMTP_LISTEN="127.0.0.1:$PORT"
export BEAVER_IMAP_LISTEN="127.0.0.1:0"

start_serve() {
  "$TMP/beaver" serve -c "$BEAVER_CONFIG" &
  SERVE_PID=$!
  for _ in $(seq 1 50); do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  sleep 0.2
}

stop_serve() {
  if [[ -n "${SERVE_PID}" ]]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
    SERVE_PID=""
  fi
}

start_serve

# Well-formed message: include Message-ID / MIME-Version so Stalwart-aligned
# MISSING_ESSENTIAL_HEADERS (7.0) does not reject ordinary ham at default threshold 10.
send_smtp() {
  local subject="$1"
  local mid="smoke-$(date +%s%N)@localhost"
  printf 'EHLO mail.example.com\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<alice@localhost>\r\nDATA\r\nFrom: sender@example.com\r\nTo: alice@localhost\r\nSubject: %s\r\nDate: Thu, 14 Jul 2026 12:00:00 +0000\r\nMessage-ID: <%s>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody\r\n.\r\nQUIT\r\n' "$subject" "$mid" \
    | nc -q 3 127.0.0.1 "$PORT" 2>/dev/null || true
}

# MAIL+RCPT only (for greylist RCPT replies).
send_rcpt() {
  printf 'EHLO mail.example.com\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<alice@localhost>\r\nQUIT\r\n' \
    | nc -q 3 127.0.0.1 "$PORT" 2>/dev/null || true
}

# Checks the SMTP reply after DATA (EHLO also emits many 250 lines).
assert_data_reply() {
  local out="$1"
  local expect="$2"
  local data_reply
  data_reply=$(echo "$out" | awk '/^354 /{p=1;next} p && /^[0-9]{3} /{print; exit}')
  if ! echo "$data_reply" | grep -q "^${expect} "; then
    echo "assert_data_reply: want ${expect}, got: ${data_reply}" >&2
    echo "$out" >&2
    return 1
  fi
}

# First numeric reply after MAIL FROM Ok (RCPT stage). With PIPELINING, EHLO ends
# with a final "250 " line, then MAIL "250 ", then RCPT.
assert_rcpt_reply() {
  local out="$1"
  local expect="$2"
  local rcpt_reply
  rcpt_reply=$(echo "$out" | awk '
    /^250-/ { next }
    /^250 / {
      if (!ehlo_done) { ehlo_done=1; next }
      if (!mail_done) { mail_done=1; next }
    }
    mail_done && /^[0-9]{3} / { print; exit }
  ')
  if ! echo "$rcpt_reply" | grep -q "^${expect} "; then
    echo "assert_rcpt_reply: want ${expect}, got: ${rcpt_reply}" >&2
    echo "$out" >&2
    return 1
  fi
}

R1="$(send_smtp 'hello inbox')"
assert_data_reply "$R1" 250

R2="$(send_smtp 'second inbox')"
assert_data_reply "$R2" 250

echo "== filter scan account (dry-run) =="
OUT="$("$TMP/beaver" filter scan -c "$BEAVER_CONFIG" -account alice@localhost 2>&1)"
echo "$OUT"
echo "$OUT" | grep -q $'^INBOX\t'
echo "$OUT" | grep -q 'scanned=2'

echo "== SMTP reject on subject regex spam =="
python3 - <<'PY' "$TMP/data/antispam/config.json"
import json, sys
path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)
# Well-formed ham stays low; SUBJECT_BAD (5) + small session tags trip reject at 6.
cfg["thresholds"]["reject"] = 6.0
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PY
"$TMP/beaver" filter reload -c "$BEAVER_CONFIG" >/dev/null

HAM_REPLY="$(send_smtp 'another ham')"
assert_data_reply "$HAM_REPLY" 250
echo "$HAM_REPLY"

SPAM_REPLY="$(send_smtp 'buy viagra')"
assert_data_reply "$SPAM_REPLY" 550
echo "$SPAM_REPLY"

echo "== SMTP reject on GTUBE =="
# GTUBE_TEST is a hard reject via tag_actions (independent of score thresholds).
GTUBE_REPLY="$(send_smtp "$GTUBE_SUBJECT")"
assert_data_reply "$GTUBE_REPLY" 550
echo "$GTUBE_REPLY"

echo "== greylist RCPT tempfail then accept =="
stop_serve
python3 - <<'PY' "$BEAVER_CONFIG"
import json, sys
path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)
cfg.setdefault("smtp", {})
cfg["smtp"]["greylist"] = {
    "enabled": True,
    "min_delay_sec": 1,
    "max_age_sec": 3600,
}
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PY
start_serve

GREY1="$(send_rcpt)"
assert_rcpt_reply "$GREY1" 452
echo "$GREY1" | grep -q "452 4.2.2"
echo "$GREY1"

sleep 2

GREY2="$(send_smtp 'greylist retry ok')"
assert_data_reply "$GREY2" 250
echo "$GREY2"

stop_serve

echo "== OK =="
