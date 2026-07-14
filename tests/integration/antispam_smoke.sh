#!/usr/bin/env bash
# Integration smoke test: antispam plugin + SMTP filter (local dry-run and live).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'kill "$SERVE_PID" 2>/dev/null || true; rm -rf "$TMP"' EXIT

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
cp data/antispam/config.json.example "$TMP/data/antispam/config.json"

echo "== plugin CLI =="
"$TMP/beaver" filter status -c "$BEAVER_CONFIG" 2>&1 | grep -q enabled=
"$TMP/beaver" filter reload -c "$BEAVER_CONFIG" 2>&1 | grep -q reloaded

echo "== serve + deliver test messages =="
PORT=$((18000 + RANDOM % 1000))
export BEAVER_SMTP_LISTEN="127.0.0.1:$PORT"
export BEAVER_IMAP_LISTEN="127.0.0.1:0"

"$TMP/beaver" serve -c "$BEAVER_CONFIG" &
SERVE_PID=$!

for _ in $(seq 1 50); do
  if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
sleep 0.2

send_smtp() {
  local subject="$1"
  printf 'EHLO mail.example.com\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<alice@localhost>\r\nDATA\r\nFrom: sender@example.com\r\nTo: alice@localhost\r\nSubject: %s\r\nDate: Thu, 14 Jul 2026 12:00:00 +0000\r\n\r\nbody\r\n.\r\nQUIT\r\n' "$subject" \
    | nc -q 3 127.0.0.1 "$PORT" 2>/dev/null || true
}

# Checks the SMTP reply after DATA (EHLO also emits many 250 lines).
assert_data_reply() {
  local out="$1"
  local expect="$2"
  local data_reply
  data_reply=$(echo "$out" | awk '/^354 /{p=1;next} p && /^[0-9]{3} /{print; exit}')
  echo "$data_reply" | grep -q "^${expect} "
}

# Default reject threshold is 10; "viagra" in subject scores high enough to 550 at SMTP.
# Deliver two ham messages first; live reject is tested after lowering the threshold.
R1="$(send_smtp 'hello inbox')"
assert_data_reply "$R1" 250

R2="$(send_smtp 'second inbox')"
assert_data_reply "$R2" 250

echo "== filter scan account (dry-run) =="
OUT="$("$TMP/beaver" filter scan -c "$BEAVER_CONFIG" -account alice@localhost 2>&1)"
echo "$OUT"
echo "$OUT" | grep -q $'^INBOX\t'
echo "$OUT" | grep -q 'scanned=2'

echo "== SMTP reject on new spam =="
python3 - <<'PY' "$TMP/data/antispam/config.json"
import json, sys
path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)
# Ham fixtures score ~5.5 at SMTP eom; viagra subject ~8+. Threshold 6 rejects spam only.
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

kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
SERVE_PID=""

echo "== OK =="
