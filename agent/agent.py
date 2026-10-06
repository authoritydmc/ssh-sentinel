#!/usr/bin/env python3
"""ssh-sentinel agent — tails AUTH_LOG and pushes new lines to central.

Stdlib only. State (inode+offset) in STATE_FILE survives restarts.
Configure via env: CENTRAL_URL, AGENT_TOKEN, AGENT_ID (default: hostname),
AUTH_LOG (default /var/log/auth.log), PUSH_EVERY (default 10s).

Runs as systemd unit (see install.sh) or plain `python3 agent.py`.
"""
import json
import os
import socket
import time
import urllib.request

CENTRAL = os.environ.get("CENTRAL_URL", "http://central:8079").rstrip("/")
TOKEN = os.environ.get("AGENT_TOKEN", "")
AGENT_ID = os.environ.get("AGENT_ID", socket.gethostname().split(".")[0])
LOG = os.environ.get("AUTH_LOG", "/var/log/auth.log")
EVERY = int(os.environ.get("PUSH_EVERY", "10"))
STATE_FILE = os.environ.get("AGENT_STATE", "/var/lib/ssh-sentinel-agent/state.json")
# SHIP_FILTER=sshd-only (default): only ship sshd + pam_unix(sshd:session) lines.
# Drops sudo COMMAND/PWD, CRON, systemd noise that leaks internal paths/args.
# Set to "full" only for debugging. Accepted logins are ALWAYS shipped fully
# (IP + user) so a brute-forcer that guesses correctly stays visible.
SHIP_FILTER = os.environ.get("SHIP_FILTER", "sshd-only").strip().lower()


def keep_line(ln):
    if SHIP_FILTER == "full":
        return True
    l = ln.lower()
    if "sshd" in l:
        return True
    if "pam_unix(sshd" in l:
        return True
    return False


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(st):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(st, f)
    except OSError as e:
        print("state save failed: %s" % e, flush=True)


def read_new(st):
    """Return lines appended since last call (handles rotation via inode)."""
    try:
        ino = os.stat(LOG).st_ino
    except OSError as e:
        print("log unreadable %s: %s" % (LOG, e), flush=True)
        return [], st
    off = st.get("offset", 0) if st.get("ino") == ino else 0
    try:
        with open(LOG, errors="replace") as f:
            f.seek(off)
            lines = f.readlines()
            st = {"ino": ino, "offset": f.tell()}
    except OSError as e:
        print("log read failed: %s" % e, flush=True)
        return [], st
    return lines, st


def push(lines):
    # Filter client-side to save bandwidth + avoid leaking sudo/CRON details.
    # Accepted lines are kept verbatim (compromise detection needs full IP/user).
    filtered = [ln for ln in lines if keep_line(ln)]
    data = json.dumps({"host": AGENT_ID, "lines": filtered[-2000:]}).encode()
    req = urllib.request.Request(
        CENTRAL + "/api/agent/push", data=data,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + TOKEN,
                 "User-Agent": "ssh-sentinel-agent/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, r.read()[:200], len(filtered), len(lines) - len(filtered)


def main():
    if not TOKEN:
        raise SystemExit("AGENT_TOKEN is empty — join via central: server.py gentoken %s" % AGENT_ID)
    st = load_state()
    print("agent %s -> %s every %ss filter=%s" % (AGENT_ID, CENTRAL, EVERY, SHIP_FILTER), flush=True)
    backoff = 5
    while True:
        lines, st = read_new(st)
        if lines:
            try:
                status, body, kept, dropped = push(lines)
                extra = " (%d non-sshd dropped)" % dropped if dropped else ""
                print("pushed %d lines%s -> %s %s" % (kept, extra, status, body.decode()[:80]), flush=True)
                save_state(st)
                backoff = 5
            except Exception as e:
                print("push failed (%d lines kept): %s: %s" % (len(lines), type(e).__name__, str(e)[:120]), flush=True)
                time.sleep(backoff)
                backoff = min(backoff * 2, 300)
                continue
        time.sleep(EVERY)


if __name__ == "__main__":
    main()
