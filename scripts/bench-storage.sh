#!/usr/bin/env bash
# IMAP wire benchmark on a live beaver serve instance (local operator tool).
# Prerequisite: beaver serve already running; stop other IMAP clients first.
#
# Required env:
#   BEAVER_BENCH_IMAP_HOST   host:port (e.g. 127.0.0.1:1993 implicit TLS)
#   BEAVER_BENCH_EMAIL       account email
#   BEAVER_BENCH_PASSWORD    account password
#
# Optional env:
#   BEAVER_BENCH_MAILBOX_MEDIUM   subfolder for second SELECT/FETCH suite
#   BEAVER_BENCH_IMAP_STARTTLS=1  use plain IMAP + STARTTLS instead of implicit TLS
#   BEAVER_BENCH_IDLE_SEC=3       IDLE probe duration budget (default 3)
#   BEAVER_BENCH_IDLE_POLL_INTERVAL=0.55  seconds per micro-IDLE cycle (>500ms server poll)
#   BEAVER_BENCH_IDLE_POLL_CYCLES=0  micro-IDLE cycles (0 = derive from IDLE_SEC / interval)
#   BEAVER_BENCH_FETCH_N=10       FETCH count (default 10)
#   BEAVER_BENCH_RUNS=1           repetitions per timed operation (median reported)
#   BEAVER_BENCH_OUTPUT_DIR=.data/bench
set -euo pipefail

: "${BEAVER_BENCH_IMAP_HOST:?set BEAVER_BENCH_IMAP_HOST (e.g. 127.0.0.1:1993)}"
: "${BEAVER_BENCH_EMAIL:?set BEAVER_BENCH_EMAIL}"
: "${BEAVER_BENCH_PASSWORD:?set BEAVER_BENCH_PASSWORD}"

export BEAVER_BENCH_MAILBOX_MEDIUM="${BEAVER_BENCH_MAILBOX_MEDIUM:-}"
export BEAVER_BENCH_IMAP_STARTTLS="${BEAVER_BENCH_IMAP_STARTTLS:-0}"
export BEAVER_BENCH_IDLE_SEC="${BEAVER_BENCH_IDLE_SEC:-3}"
export BEAVER_BENCH_IDLE_POLL_INTERVAL="${BEAVER_BENCH_IDLE_POLL_INTERVAL:-0.55}"
export BEAVER_BENCH_IDLE_POLL_CYCLES="${BEAVER_BENCH_IDLE_POLL_CYCLES:-0}"
export BEAVER_BENCH_FETCH_N="${BEAVER_BENCH_FETCH_N:-10}"
export BEAVER_BENCH_RUNS="${BEAVER_BENCH_RUNS:-1}"
export BEAVER_BENCH_OUTPUT_DIR="${BEAVER_BENCH_OUTPUT_DIR:-.data/bench}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p "$BEAVER_BENCH_OUTPUT_DIR"
STAMP="$(date -u +%Y-%m-%d-%H%M%S)"
REPORT="$BEAVER_BENCH_OUTPUT_DIR/$STAMP.txt"
GIT_HEAD="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
export GIT_HEAD

python3 - <<'PY' | tee "$REPORT"
import imaplib
import os
import re
import ssl
import statistics
import time
from datetime import datetime, timezone

hostport = os.environ["BEAVER_BENCH_IMAP_HOST"]
email = os.environ["BEAVER_BENCH_EMAIL"]
password = os.environ["BEAVER_BENCH_PASSWORD"]
medium_override = os.environ.get("BEAVER_BENCH_MAILBOX_MEDIUM", "").strip()
use_starttls = os.environ.get("BEAVER_BENCH_IMAP_STARTTLS", "0") in ("1", "true", "TRUE", "yes", "YES")
idle_sec = float(os.environ.get("BEAVER_BENCH_IDLE_SEC", "3"))
idle_poll_interval = float(os.environ.get("BEAVER_BENCH_IDLE_POLL_INTERVAL", "0.55"))
idle_poll_cycles_env = int(os.environ.get("BEAVER_BENCH_IDLE_POLL_CYCLES", "0"))
fetch_n = max(1, int(os.environ.get("BEAVER_BENCH_FETCH_N", "10")))
runs = max(1, int(os.environ.get("BEAVER_BENCH_RUNS", "1")))

if idle_poll_cycles_env > 0:
    idle_poll_cycles = idle_poll_cycles_env
else:
    idle_poll_cycles = max(1, int(round(idle_sec / idle_poll_interval)))

if ":" in hostport:
    host, port_s = hostport.rsplit(":", 1)
    port = int(port_s)
else:
    host, port = hostport, 993

git_head = os.environ.get("GIT_HEAD", "unknown")


def imap_login(imap):
    typ, dat = imap._simple_command("LOGIN", imap._quote(email), imap._quote(password))
    if typ != "OK":
        raise RuntimeError(dat[-1] if dat else "LOGIN failed")
    imap.state = "AUTH"


def connect():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if use_starttls:
        imap = imaplib.IMAP4(host, port, timeout=60)
        imap.sock.settimeout(60)
        imap.starttls(ssl_context=ctx)
        return imap
    imap = imaplib.IMAP4_SSL(host, port, ssl_context=ctx, timeout=60)
    imap.sock.settimeout(60)
    return imap


def timed(label, fn):
    samples = []
    last = None
    for _ in range(runs):
        t0 = time.perf_counter()
        last = fn()
        samples.append(time.perf_counter() - t0)
    med = statistics.median(samples)
    return med, last


def parse_status_messages(status_line):
    m = re.search(r"MESSAGES\s+(\d+)", status_line)
    return int(m.group(1)) if m else 0


def mailbox_messages(imap, name):
    mbox = "INBOX" if name.upper() == "INBOX" else imap._quote(name)
    typ, data = imap.status(mbox, "(MESSAGES UIDNEXT UIDVALIDITY)")
    if typ != "OK" or not data:
        return 0
    line = data[0].decode() if isinstance(data[0], bytes) else str(data[0])
    return parse_status_messages(line)


def imap_idle(imap, seconds):
    tag = imap._new_tag().decode()
    imap.send(f"{tag} IDLE\r\n".encode())
    while True:
        line = imap.readline()
        if not line:
            raise RuntimeError("IDLE: connection closed")
        if line.startswith(b"+ "):
            break
    time.sleep(seconds)
    imap.send(b"DONE\r\n")
    while True:
        line = imap.readline()
        if line.startswith(tag.encode()):
            break


def imap_idle_once(imap, hold_sec):
    """Run one IDLE cycle; return protocol overhead beyond hold_sec (≈ one server poll)."""
    t0 = time.perf_counter()
    tag = imap._new_tag().decode()
    imap.send(f"{tag} IDLE\r\n".encode())
    while True:
        line = imap.readline()
        if not line:
            raise RuntimeError("IDLE: connection closed")
        if line.startswith(b"+ "):
            break
    time.sleep(hold_sec)
    imap.send(b"DONE\r\n")
    while True:
        line = imap.readline()
        if not line:
            raise RuntimeError("IDLE: connection closed waiting for DONE")
        if line.startswith(tag.encode()):
            break
    return time.perf_counter() - t0 - hold_sec


def idle_poll_probe(imap, cycles, hold_sec):
    overheads = []
    for _ in range(cycles):
        overheads.append(imap_idle_once(imap, hold_sec))
    return overheads


def bench_mailbox(imap, name, do_idle):
    rows = []

    def select():
        typ, data = imap.select(imap._quote(name))
        if typ != "OK":
            raise RuntimeError(f"SELECT {name!r} failed")
        return int(data[0]) if data and data[0] else 0

    med, exists = timed(f"SELECT {name}", select)
    rows.append((f"SELECT {name}", med, f"exists={exists}"))

    def status():
        return mailbox_messages(imap, name)

    med, msgs = timed(f"STATUS {name}", status)
    status_med = med
    rows.append((f"STATUS {name}", med, f"messages={msgs}"))

    n = min(fetch_n, max(exists, 1))

    def fetch_headers():
        typ, _ = imap.fetch(f"1:{n}", "(UID FLAGS ENVELOPE)")
        if typ != "OK":
            raise RuntimeError(f"FETCH {name} failed")

    med, _ = timed(f"FETCH {name} 1:{n}", fetch_headers)
    rows.append((f"FETCH {name} 1:{n}", med, ""))

    if do_idle and idle_sec > 0:
        rows.append(("IDLE analysis", None, ""))
        rows.append((
            f"  legacy 1x poll (STATUS=List)",
            status_med,
            f"messages={msgs}",
        ))

        def probe():
            return idle_poll_probe(imap, idle_poll_cycles, idle_poll_interval)

        med, overheads = timed(
            f"  quiet poll probe {idle_poll_cycles}x{idle_poll_interval:g}s",
            probe,
        )
        oh_med = statistics.median(overheads) * 1000
        oh_max = max(overheads) * 1000
        rows.append((
            f"  quiet poll probe {idle_poll_cycles}x{idle_poll_interval:g}s",
            med,
            f"overhead med={oh_med:.1f}ms max={oh_max:.1f}ms",
        ))

        def idle_wall():
            imap_idle(imap, idle_sec)

        med, _ = timed(f"  IDLE wall {idle_sec:g}s", idle_wall)
        rows.append((f"  IDLE wall {idle_sec:g}s", med, "client sleep (not poll cost)"))

    return rows


lines = []
lines.append(f"beaver bench-storage {datetime.now(timezone.utc).isoformat()}")
lines.append(f"git={git_head}")
lines.append(f"imap_host={hostport} starttls={use_starttls}")
lines.append(f"email={email}")
lines.append(f"runs={runs} fetch_n={fetch_n} idle_sec={idle_sec}")
lines.append(
    f"idle_poll={idle_poll_cycles}x{idle_poll_interval:g}s "
    f"(overhead ≈ server poll + IMAP framing)"
)
lines.append("")

imap = connect()
try:
    med, _ = timed("LOGIN", lambda: imap_login(imap))
    lines.append(f"LOGIN\t{med:.3f}s")

    def list_all():
        typ, data = imap.list('""', "*")
        if typ != "OK":
            raise RuntimeError("LIST failed")
        boxes = []
        for item in data:
            if not item:
                continue
            parts = item.decode().split(' "/" ')
            if len(parts) == 2:
                boxes.append(parts[1].strip('"'))
        return boxes

    med, boxes = timed('LIST "" *', list_all)
    lines.append(f'LIST "" *\t{med:.3f}s\tmailboxes={len(boxes)}')

    def status_all():
        counts = {}
        for box in boxes:
            counts[box] = mailbox_messages(imap, box)
        return counts

    med, counts = timed("STATUS all mailboxes", status_all)
    lines.append(f"STATUS all\t{med:.3f}s\tmailboxes={len(boxes)}")
    for box in sorted(boxes, key=lambda b: counts.get(b, 0), reverse=True)[:10]:
        lines.append(f"  {box}\tmessages={counts.get(box, 0)}")

    inbox = next((b for b in boxes if b.upper() == "INBOX"), "INBOX")
    if medium_override and medium_override in boxes:
        medium = medium_override
    else:
        ranked = sorted(
            [b for b in boxes if b.upper() != "INBOX"],
            key=lambda b: counts.get(b, 0),
            reverse=True,
        )
        medium = ranked[0] if ranked else None

    lines.append("")
    lines.append(f"INBOX suite: {inbox}")
    for label, med, extra in bench_mailbox(imap, inbox, do_idle=True):
        if med is None:
            lines.append(label)
            continue
        suffix = f"\t{extra}" if extra else ""
        lines.append(f"{label}\t{med:.3f}s{suffix}")

    if medium:
        lines.append("")
        lines.append(f"medium suite: {medium} (messages={counts.get(medium, 0)})")
        for label, med, extra in bench_mailbox(imap, medium, do_idle=False):
            suffix = f"\t{extra}" if extra else ""
            lines.append(f"{label}\t{med:.3f}s{suffix}")
    else:
        lines.append("")
        lines.append("medium suite: skipped (no subfolder)")
finally:
    try:
        imap.logout()
    except Exception:
        pass

text = "\n".join(lines)
print(text)
PY

echo "report: $REPORT"
