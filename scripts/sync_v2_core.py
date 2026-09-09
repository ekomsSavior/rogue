#!/usr/bin/env python3
"""
ROGUE v2 core synchronizer
==========================
Keeps the canonical comms core (rogue_v2_core.py) embedded identically inside
rogue_c2.py and rogue_implant.py. Both files are single-file deployables, so
the core block is duplicated by design - this script is the single-source
maintenance path.

    python3 scripts/sync_v2_core.py [--check]

--check  verifies embedded blocks match the canonical file (exit 1 if not).
"""
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE = os.path.join(ROOT, "rogue_v2_core.py")
TARGETS = ["rogue_c2.py", "rogue_implant.py"]
BEGIN = "# ===== ROGUE-V2 COMMS CORE (auto-embedded - edit rogue_v2_core.py) ====="
END = "# ===== END ROGUE-V2 COMMS CORE ====="


def core_block():
    src = open(CORE).read()
    return "%s\n%s\n%s\n" % (BEGIN, src.rstrip(), END)


def replace_block(path, block):
    src = open(path).read()
    i = src.find(BEGIN)
    j = src.find(END)
    if i == -1 or j == -1:
        raise SystemExit("markers not found in %s - add them first" % path)
    j = src.find("\n", j) + 1
    src = src[:i] + block + src[j:]
    open(path, "w").write(src)


def embedded_hash(path):
    src = open(path).read()
    i = src.find(BEGIN)
    j = src.find(END)
    if i == -1 or j == -1:
        return None
    j = src.find("\n", j) + 1  # include the newline that ends the END line
    return hashlib.sha256(src[i:j].encode()).hexdigest()


def main():
    check_only = "--check" in sys.argv
    block = core_block()
    canon_hash = hashlib.sha256(block.encode()).hexdigest()
    ok = True
    for t in TARGETS:
        p = os.path.join(ROOT, t)
        if not os.path.exists(p):
            print("!! %s missing" % p)
            ok = False
            continue
        if check_only:
            h = embedded_hash(p)
            status = "OK" if h == canon_hash else "STALE"
            if h != canon_hash:
                ok = False
            print("[%s] %s" % (status, t))
        else:
            replace_block(p, block)
            print("[synced] %s" % t)
    if check_only and not ok:
        print("embedded core differs from rogue_v2_core.py - run without --check")
        sys.exit(1)


if __name__ == "__main__":
    main()
